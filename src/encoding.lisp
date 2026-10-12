;;;; encoding.lisp -- base64, PEM, hex. Pure CL.

(in-package :cl-sev-snp)

(define-condition attestation-error (error)
  ((reason :initarg :reason :reader attestation-error-reason))
  (:report (lambda (c s) (format s "attestation check failed: ~a" (attestation-error-reason c))))
  (:documentation "Signalled for malformed input. Verification failures return NIL, not this."))

(defun %fail (fmt &rest args)
  (error 'attestation-error :reason (apply #'format nil fmt args)))

(defparameter +b64-alphabet+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-decode (string)
  "Decode standard base64 (whitespace ignored, '=' padding optional) into an octet vector."
  (let ((out (make-array (floor (* 3 (length string)) 4) :element-type '(unsigned-byte 8)))
        (k 0) (acc 0) (bits 0))
    (loop for ch across string
          for v = (position ch +b64-alphabet+)
          do (cond (v (setf acc (logior (ash acc 6) v)) (incf bits 6)
                      (when (>= bits 8)
                        (decf bits 8)
                        (setf (aref out k) (ldb (byte 8 bits) acc))
                        (incf k)
                        (setf acc (ldb (byte bits 0) acc))))
                   ((or (char= ch #\=) (member ch '(#\Space #\Tab #\Newline #\Return))) nil)
                   (t (%fail "invalid base64 character ~s" ch))))
    (subseq out 0 k)))

(defun hex-string (octets)
  (format nil "~(~{~2,'0x~}~)" (coerce octets 'list)))

(defun %string-octets (s)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))

(defun pem-to-der-list (pem-text)
  "All CERTIFICATE blocks in PEM-TEXT, each decoded to DER (list of octet vectors, in order)."
  (let ((out '()) (pos 0)
        (begin "-----BEGIN CERTIFICATE-----") (end "-----END CERTIFICATE-----"))
    (loop
      (let ((b (search begin pem-text :start2 pos)))
        (unless b (return (nreverse out)))
        (let* ((body-start (+ b (length begin)))
               (e (or (search end pem-text :start2 body-start)
                      (%fail "unterminated PEM block"))))
          (push (base64-decode (subseq pem-text body-start e)) out)
          (setf pos (+ e (length end))))))))

(defun base64-encode (octets)
  "Standard base64 (RFC 4648) with padding, returned as a string."
  (let* ((alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
         (n (length octets))
         (out (make-string-output-stream)))
    (loop for i from 0 below n by 3
          do (let* ((b0 (aref octets i))
                    (b1 (if (< (+ i 1) n) (aref octets (+ i 1)) 0))
                    (b2 (if (< (+ i 2) n) (aref octets (+ i 2)) 0))
                    (w (+ (ash b0 16) (ash b1 8) b2)))
               (write-char (char alphabet (ldb (byte 6 18) w)) out)
               (write-char (char alphabet (ldb (byte 6 12) w)) out)
               (write-char (if (< (+ i 1) n) (char alphabet (ldb (byte 6 6) w)) #\=) out)
               (write-char (if (< (+ i 2) n) (char alphabet (ldb (byte 6 0) w)) #\=) out)))
    (get-output-stream-string out)))
