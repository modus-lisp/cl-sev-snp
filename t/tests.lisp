(require :cram) (require :json-simple)
;; Load the library source first (it defines package CL-SEV-SNP), then the test package.
(let ((root (merge-pathnames "../" (make-pathname :name nil :type nil :version nil
                                                 :defaults (or *load-truename* *default-pathname-defaults*)))))
  (dolist (f '("package" "hash" "encoding" "der" "rsa" "ec" "snp" "tinfoil" "rekor"))
    (load (merge-pathnames (format nil "src/~a.lisp" f) root))))

(defpackage :cl-sev-snp-tests (:use :cl :cl-sev-snp))
(in-package :cl-sev-snp-tests)
(defparameter *root*
  (merge-pathnames "../" (make-pathname :name nil :type nil :version nil
                                        :defaults (or *load-truename* *default-pathname-defaults*))))
(defparameter *fx* (merge-pathnames "t/fixtures/" *root*))
(defun fx (name) (with-open-file (s (merge-pathnames name *fx*) :element-type '(unsigned-byte 8))
                   (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8)))) (read-sequence v s) v)))
(defun fx-json () (with-open-file (s (merge-pathnames "atc.json" *fx*)) (json-simple:parse s)))
(defun copy-obj (o) (cond ((hash-table-p o) (let ((h (make-hash-table :test 'equal)))
                                             (maphash (lambda (k v) (setf (gethash k h) (copy-obj v))) o) h))
                          ((vectorp o) (map 'vector #'copy-obj o)) (t o)))
(defun flip (v i) (let ((c (copy-seq v))) (setf (aref c i) (logxor 1 (aref c i))) c))

(defun fx-pem-certs ()
  "Each PEM certificate block in t/fixtures/chain-Genoa.pem, as a string (ASK then ARK)."
  (let* ((text (map 'string #'code-char (fx "chain-Genoa.pem")))
         (end "-----END CERTIFICATE-----")
         (out '()) (start 0))
    (loop for p = (search "-----BEGIN CERTIFICATE-----" text :start2 start)
          while p
          do (let ((e (+ (search end text :start2 p) (length end))))
               (push (subseq text p e) out)
               (setf start e)))
    (nreverse out)))

(defvar *results* '())
(defmacro check (name form)
  `(let ((ok (handler-case (and ,form t) (error () nil))))
     (push (cons ,name ok) *results*)
     (format t "~:[FAIL~;PASS~] ~a~%" ok ,name)))

(defun report-bytes () (fx "report.bin"))
(defun verify-report (rep &key (vcek (fx "vcek.der")))
  (values (verify-snp-report (parse-snp-report rep) (fx "ark.der") (fx "ask.der") vcek :now (- (get-universal-time) 2208988800))))
(defun bundle-ok (b) (verify-tinfoil-bundle b (fx "ark.der") (fx "ask.der")))

;; --- SNP report ---
(check "genuine SNP report verifies" (verify-report (report-bytes)))
(check "report measurement tamper fails" (not (verify-report (flip (report-bytes) #x90))))
(check "report_data tamper fails" (not (verify-report (flip (report-bytes) #x50))))
(check "chip_id tamper fails" (not (verify-report (flip (report-bytes) #x1a0))))
(check "signature tamper fails" (not (verify-report (flip (report-bytes) #x2a0))))
(check "wrong VCEK fails" (not (verify-report (report-bytes) :vcek (fx "ask.der"))))
(check "debug policy flagged" (let ((r (parse-snp-report (report-bytes)))) (setf (cl-sev-snp::snp-report-policy r) (logior (cl-sev-snp::snp-report-policy r) (ash 1 19)))
                                 (member "policy: debugging is enabled" (cl-sev-snp::%check-binding r (parse-certificate (fx "vcek.der"))) :test #'string=)))

;; --- Tinfoil bundle ---
(check "genuine bundle verifies" (bundle-ok (fx-json)))
(check "enclaveCert swap fails"
       (let ((b (copy-obj (fx-json)))
             (ark-pem (second (fx-pem-certs))))
         (setf (gethash "enclaveCert" b) ark-pem)
         (not (bundle-ok b))))
(check "digest tamper fails" (let ((b (copy-obj (fx-json)))) (setf (gethash "digest" b) (format nil "00~a" (subseq (gethash "digest" b) 2))) (not (bundle-ok b))))
(check "DSSE payload tamper fails" (let* ((b (copy-obj (fx-json))) (env (gethash "dsseEnvelope" (gethash "sigstoreBundle" b)))
                                          (p (cl-sev-snp::base64-decode (gethash "payload" env))))
                                     (setf (aref p 30) (logxor 1 (aref p 30)))
                                     (setf (gethash "payload" env) (cl-sev-snp::base64-encode p))
                                     (not (bundle-ok b))))

;; --- Rekor tlogEntries ---
(defun tlog-entry (b) (first (coerce (%json-get-t b "sigstoreBundle" "verificationMaterial" "tlogEntries") 'list)))
(defun %json-get-t (obj &rest keys)
  (let ((cur obj))
    (dolist (k keys cur)
      (setf cur (if (hash-table-p cur) (gethash k cur) (aref cur k))))))
(defun payload-of (b) (cl-sev-snp::base64-decode (gethash "payload" (gethash "dsseEnvelope" (gethash "sigstoreBundle" b)))))
(defun rekor-ok (b &optional (entry (tlog-entry b)))
  (values (cl-sev-snp:verify-rekor-entry entry (payload-of b))))
(check "genuine Rekor entry verifies" (rekor-ok (fx-json)))
(check "Rekor body tamper fails (SET/body)"
       (let* ((b (copy-obj (fx-json))) (e (tlog-entry b)) (body (cl-sev-snp::base64-decode (gethash "canonicalizedBody" e))))
         (setf (aref body 40) (logxor 1 (aref body 40)))
         (setf (gethash "canonicalizedBody" e) (cl-sev-snp::base64-encode body))
         (not (rekor-ok b e))))
(check "inclusion proof hash tamper fails"
       (let* ((b (copy-obj (fx-json))) (ip (gethash "inclusionProof" (tlog-entry b)))
              (h (cl-sev-snp::base64-decode (aref (gethash "hashes" ip) 0))))
         (setf (aref h 0) (logxor 1 (aref h 0)))
         (setf (aref (gethash "hashes" ip) 0) (cl-sev-snp::base64-encode h))
         (not (rekor-ok b))))
(check "SET tamper fails"
       (let* ((b (copy-obj (fx-json))) (e (tlog-entry b))
              (s (cl-sev-snp::base64-decode (gethash "signedEntryTimestamp" (gethash "inclusionPromise" e)))))
         (setf (aref s 10) (logxor 1 (aref s 10)))
         (setf (gethash "signedEntryTimestamp" (gethash "inclusionPromise" e)) (cl-sev-snp::base64-encode s))
         (not (rekor-ok b e))))
(check "DSSE payload tamper fails Rekor body binding"
       (let* ((b (copy-obj (fx-json))) (p (payload-of b)))
         (setf (aref p 30) (logxor 1 (aref p 30)))
         (not (values (cl-sev-snp:verify-rekor-entry (tlog-entry b) p)))))

(let* ((fails (remove-if #'cdr *results*)))
  (format t "~%~d/~d passed~%" (- (length *results*) (length fails)) (length *results*))
  (sb-ext:exit :code (if fails 1 0)))
