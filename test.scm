;;;
;;; Test app.amazon.auth
;;;

(use gauche.test)
(use rfc.json)
(use srfi.19)

(test-start "app.amazon.auth")
(use app.amazon.auth)
(test-module 'app.amazon.auth)

(define *dummy-access-id* "ABCDEFGHIJKLMNOP")
(define *dummy-secret-key* "abcdefghijklm//opqrstuvwxyz")


(test* "basic"
       '(("authorization" "AWS4-HMAC-SHA256 Credential=ABCDEFGHIJKLMNOP/20240102/us-west-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, Signature=a5c66063f7e9f1586e1012c7a21e0312e33a1ad71968ed2225f11f3c45295397")
         ("x-amz-content-sha256"
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
         ("x-amz-date" "20240102T123456Z")
         ("date" "Tue Jan 02 2024 12:34:56 GMT"))
       (aws4-add-auth-headers
        (aws4-signing-key :access-id *dummy-access-id*
                          :secret-key *dummy-secret-key*
                          :region "us-west-1"
                          :service "s3"
                          :date (make-date 0 56 34 12 2 1 2024 0))
        'GET
        "https://my-bucket.s3.us-west-1.amazon.com/my-object"
        '(("date" "Tue Jan 02 2024 12:34:56 GMT"))
        #f))

(test* "query"
       '(("authorization" "AWS4-HMAC-SHA256 Credential=ABCDEFGHIJKLMNOP/20240102/us-west-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, Signature=fa77440f6a352b6d36453067ab5aec5b3d8484bf562f4822d696386a60b3a344")
         ("x-amz-content-sha256"
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
         ("x-amz-date" "20240102T123456Z")
         ("date" "Tue Jan 02 2024 12:34:56 GMT"))
       (aws4-add-auth-headers
        (aws4-signing-key :access-id *dummy-access-id*
                          :secret-key *dummy-secret-key*
                          :region "us-west-1"
                          :service "s3"
                          :date (make-date 0 56 34 12 2 1 2024 0))
        'GET
        "https://my-bucket.s3.us-west-1.amazon.com/my-object?abc=def&ghi=jkl&mn&opq=;e%24%29%25%2A%21%40%5E%28%5B%5D%7B%7D%3C%3E%2C.%27%60&rs=tu=v"
        '(("date" "Tue Jan 02 2024 12:34:56 GMT"))
        #f))


(test-end :exit-on-failure #t)
