;;;
;;; AWS API signing utility
;;;

(define-module app.amazon.auth
  (use gauche.record)
  (use gauche.sequence)
  (use rfc.822)
  (use rfc.base64)
  (use rfc.sha)
  (use rfc.uri)
  (use rfc.hmac)
  (use srfi.13)
  (use srfi.197)                        ;chain
  (use util.digest)
  (export aws4-signing-key aws4-auth-string))
(select-module app.amazon.auth)

;; API
(define (aws4-signing-key access-id secret-key region service yyyymmdd)
  (define (sha-hash key msg)
    (hmac-message-to <u8vector> <sha256> key msg))
  (define signing-key
    (chain (string-append "AWS4" secret-key)
           (sha-hash _ yyyymmdd)
           (sha-hash _ region)
           (sha-hash _ service)
           (sha-hash _ "aws4_request")))
  (define scope
    (format "~a/~a/~a/aws4_request" yyyymmdd region service))
  (^[msg]
    (case msg
      ((id) access-id)
      ((key) signing-key)
      ((scope) scope)
      ((date) yyyymmdd)
      (else (error "aws4-signing-key: Unknown attribute:" msg)))))

;; API
(define (aws4-auth-string signing-key method url headers body)
  (let* ([canon-headers (canonical-headers url headers)]
         [content-hash (compute-content-hash body)]
         [request-to-sign (canonical-request method url canon-headers
                                             content-hash)]
         [string-to-sign (string-join
                          (list "AWS4-HMAC-SHA256"
                                (signing-key 'date)
                                (signing-key 'scope)
                                (digest-message-to 'hex <sha256>
                                                   request-to-sign))
                          "\n")]
         [sig (hmac-message-to 'hex <sha256> (signing-key 'key) string-to-sign)])
    (format "AWS4-HMAC-SHA256 Credential=~a/~a, SignedHeaders=~a, Signature=~a"
            (signing-key 'id) (signing-key 'scope)
            (signed-headers-string canon-headers)
            sig)))

(define (compute-content-hash body)
  (if (or (string? body) (u8vector? body))
    (digest-message-to 'hex <sha256> body))
    (digest-message-to 'hex <sha256> ""))

(define (header-matcher include-patterns)
  (define (matcher-1 pattern)
    (if (string-suffix? "*" pattern)
      (let1 prefix (string-trim-right pattern #\*)
        (^[header-entry] (string-prefix? prefix (car header-entry))))
      (^[header-entry] (string=? pattern (car header-entry)))))
  (apply any-pred (map matcher-1 include-patterns)))

(define (header-entry-normalize entry)
  (list (string-downcase (car entry))   ; lowercase header name
        (chain (string-trim-both (cadr entry))
               (delete-neighbor-dups _))))

(define (canonical-headers url headers
                           :optional (included '("host" "content-type" "date"
                                                 "x-amz-*")))
  (define (thru x) (pprint x) x)
  (let1 headers-to-include (filter (header-matcher included) headers)
    (chain (if (rfc822-header-ref headers-to-include "host")
             headers-to-include
             `(("host" ,(uri-ref url 'host)) ,@headers-to-include))
           (map header-entry-normalize _)
           (group-collection _ :key car :test string=?)
           (map (^e (list (caar e) (string-join (map cadr e) ","))) _)
           (sort-by _ car string<?))))

(define (signed-headers-string canon-headers)
  (string-join (map car canon-headers) ";"))

(define (canonical-path path)
  (if path
    (chain (sys-normalize-pathname path :canonicalize #t)
           (uri-encode-string _ :noescape #[[:alnum:]/~]))
    "/"))

(define (canonical-query query-string)
  ;; WRITEME
  (or query-string ""))

(define (concat-headers canon-headers)
  (string-concatenate
   (map (^h (format "~a:~a\n" (car h) (cadr h))) canon-headers)))

(define (canonical-request method url canon-headers content-hash)
  (string-join (list (string-upcase (x->string method))
                     (canonical-path (uri-ref url 'path))
                     (canonical-query (uri-ref url 'query))
                     (concat-headers canon-headers)
                     (signed-headers-string canon-headers)
                     content-hash)
               "\n"))
