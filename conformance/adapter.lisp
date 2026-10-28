;;;; adapter.lisp -- cl-sev-snp as a tinfoil-conformance adapter.
;;;;
;;;; The tinfoil-conformance suite (github.com/tinfoilsh/tinfoil-conformance) grades an
;;;; SDK by spawning `tinfoil-conformance <stage>` with a JSON input on stdin and reading
;;;; a JSON verdict on stdout.  Exit codes: 0 accept, 10 reject, 20 stage unsupported,
;;;; 30 malformed input, 1 internal error.  This file is that program for cl-sev-snp, so
;;;; the suite's vectors -- not tests we wrote ourselves -- decide whether the verifier
;;;; implements the specification.
;;;;
;;;; Build with conformance/build.sh; run the suite with
;;;;   tools/run_adapter.py --adapter /path/to/tinfoil-conformance --dirs vectors/v3/envelope

(defpackage :cl-sev-snp.conformance
  (:use :common-lisp)
  (:local-nicknames (:snp :cl-sev-snp) (:json :json-simple))
  (:export #:main))

(in-package :cl-sev-snp.conformance)

(defparameter *stages* '("v3-check-envelope" "v3-authenticate-quote" "v3-authenticate-provenance")
  "The stages this adapter implements.  Every other stage answers exit 20 (unsupported)
so the harness records a SKIP rather than a failure we have not earned.")

(defun ht (&rest pairs)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on pairs by #'cddr do (setf (gethash k h) v))
    h))

(defun emit (object code)
  (json:stringify object :stream *standard-output*)
  (terpri *standard-output*)
  (finish-output *standard-output*)
  (sb-ext:exit :code code :abort t))

(defun accept (stage outputs) (emit (ht "stage" stage "accepted" t "outputs" outputs) 0))

(defun reject (stage code reason)
  (format *error-output* "~a: ~a~%" code reason)
  (emit (ht "stage" stage "accepted" nil "rejection" (ht "code" code "spec_ref" "")) 10))

(defun malformed (stage reason)
  (format *error-output* "malformed input: ~a~%" reason)
  (emit (ht "stage" stage "accepted" nil "rejection" (ht "code" "MALFORMED_INPUT" "spec_ref" "")) 30))

(defun field (input name)
  (and (hash-table-p input) (gethash name input)))

(defun decode-hex (s)
  (unless (and (stringp s) (evenp (length s)) (every (lambda (c) (digit-char-p c 16)) s))
    (return-from decode-hex nil))
  (let ((v (make-array (floor (length s) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length v) v)
      (setf (aref v i) (parse-integer s :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun stage-check-envelope (stage input)
  (let* ((doc-b64 (field input "document_b64"))
         (nonce (decode-hex (or (field input "expected_nonce_hex") (field input "nonce_hex")))))
    (unless (stringp doc-b64) (malformed stage "document_b64 missing"))
    (unless (and nonce (= (length nonce) 32)) (malformed stage "nonce must be 32 bytes of hex"))
    (let ((doc (handler-case (snp:v3-check-envelope (snp:base64-decode doc-b64) nonce)
                 (snp:v3-reject (e) (reject stage (snp:v3-reject-code e) (snp:v3-reject-reason e))))))
      (accept stage
              (ht "report_data_hex" (snp:v3-doc-report-data-hex doc)
                  "crypto_material_hash_hex" (snp:hex-string (snp:v3-doc-crypto-material-hash doc))
                  "device_evidence_hash_hex" (snp:hex-string (snp:v3-doc-device-evidence-hash doc))
                  "cpu_evidence_format" (snp:v3-doc-cpu-format doc))))))

(defun stage-authenticate-quote (stage input)
  (let* ((doc-b64 (field input "document_b64"))
         (nonce (decode-hex (or (field input "expected_nonce_hex") (field input "nonce_hex"))))
         (time (field input "verification_time_unix")))
    (declare (ignore nonce))
    (unless (stringp doc-b64) (malformed stage "document_b64 missing"))
    ;; B3 authenticates the quote from the decoded document; the challenge is the
    ;; envelope stage's business, so no nonce is bound here.
    (let* ((doc (handler-case (snp:v3-decode-document (snp:base64-decode doc-b64))
                  (snp:v3-reject (e) (reject stage (snp:v3-reject-code e) (snp:v3-reject-reason e)))))
           (q (handler-case
                  (apply #'snp:v3-authenticate-sev-quote doc
                         :ark-pem (field input "amd_root_ca_pem") :ask-pem (field input "ask_pem")
                         (and (integerp time) (list :now time)))
                (snp:v3-reject (e) (reject stage (snp:v3-reject-code e) (snp:v3-reject-reason e))))))
      (accept stage
              (ht "platform" (getf q :platform)
                  "identity_hex" (getf q :identity-hex)
                  "launch_measurement" (ht "type" (getf (getf q :launch-measurement) :type)
                                           "registers" (coerce (getf (getf q :launch-measurement) :registers) 'vector))
                  "report_data_hex" (getf q :report-data-hex))))))

(defun measurement-json (m)
  (ht "type" (getf m :type) "registers" (coerce (getf m :registers) 'vector)))

(defun stage-authenticate-provenance (stage input)
  (let ((doc-b64 (field input "document_b64"))
        (root-b64 (field input "sigstore_trusted_root_json_b64"))
        (pin (field input "repo")))
    (unless (stringp doc-b64) (malformed stage "document_b64 missing"))
    (unless (stringp root-b64) (malformed stage "this adapter has no embedded Sigstore root; supply one"))
    (unless (stringp pin) (malformed stage "repo pin missing"))
    (let* ((doc (handler-case (snp:v3-decode-document (snp:base64-decode doc-b64))
                  (snp:v3-reject (e) (malformed stage (snp:v3-reject-reason e)))))
           (root (handler-case (snp:parse-sigstore-trusted-root (snp:base64-decode root-b64))
                   (error (e) (malformed stage (format nil "trusted root: ~a" e)))))
           (code (handler-case (snp:v3-authenticate-code doc pin root)
                   (snp:v3-reject (e) (reject stage (snp:v3-reject-code e) (snp:v3-reject-reason e))))))
      (accept stage (ht "code_digest" (getf code :digest)
                        "code_measurement" (measurement-json (getf code :measurement)))))))

(defun capabilities ()
  (emit (ht "sdk" "cl-sev-snp"
            "v3" (ht "supported" t
                     "stages_supported" (coerce *stages* 'vector)
                     "synthetic_sigstore_root" nil
                     "synthetic_vendor_roots" nil
                     "intermediate_facts" nil
                     "freshness_enforced" nil
                     "device_appraisal" nil))
        0))

(defun main ()
  (let* ((args (rest sb-ext:*posix-argv*))
         (stage (first args)))
    (handler-case
        (cond ((null stage) (format *error-output* "usage: tinfoil-conformance <stage>~%") (sb-ext:exit :code 30))
              ((string= stage "capabilities") (capabilities))
              ((not (member stage *stages* :test #'string=)) (sb-ext:exit :code 20 :abort t))
              (t
               (let ((input (handler-case (json:parse (with-output-to-string (s)
                                                        (loop for line = (read-line *standard-input* nil)
                                                              while line do (write-line line s))))
                              (error (e) (malformed stage (format nil "input is not JSON: ~a" e))))))
                 (cond ((string= stage "v3-check-envelope") (stage-check-envelope stage input))
                       ((string= stage "v3-authenticate-quote") (stage-authenticate-quote stage input))
                       ((string= stage "v3-authenticate-provenance") (stage-authenticate-provenance stage input))))))
      (sb-sys:interactive-interrupt () (sb-ext:exit :code 1 :abort t))
      (error (e)
        (format *error-output* "internal error: ~a~%" e)
        (emit (ht "stage" (or stage "") "accepted" nil "error" (princ-to-string e)) 1)))))
