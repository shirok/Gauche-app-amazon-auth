;;;
;;; Test app.amazon.auth
;;;

(use gauche.test)

(test-start "app.amazon.auth")
(use app.amazon.auth)
(test-module 'app.amazon.auth)


;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
