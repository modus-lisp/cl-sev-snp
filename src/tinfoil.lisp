;;;; tinfoil.lisp -- verify a Tinfoil attestation bundle (the document served at
;;;; https://atc.tinfoil.sh/attestation). Pure CL. Given the bundle's parts as data, this
;;;; checks:
;;;;   1. enclaveAttestationReport: base64 -> gzip -> SEV-SNP report, verified against the
;;;;      bundle's VCEK and the ARK/ASK chain (see snp.lisp).
;;;;   2. report_data[0:32] == SHA-256(SubjectPublicKeyInfo of enclaveCert). This binds the
;;;;      attested report to the TLS key the enclave presents.
;;;;   3. sigstoreBundle DSSE envelope: the ECDSA P-256 signature verifies under the Fulcio
;;;;      leaf certificate, over the PAE of (payloadType, payload).
;;;;   4. The in-toto statement's snp_measurement equals the report measurement, and its
;;;;      subject sha256 equals the bundle's `digest` field.
;;;;
;;;; Trust roots are NOT fixed here: the ARK is the caller's responsibility to pin (see
;;;; the kds subsystem for fetching it). This verifier proves the bundle is internally
;;;; consistent and was signed by the holder of the VCEK/Fulcio keys.

(in-package :cl-sev-snp)

(defun %ascii (s) (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))

(defun %read-file-octets (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
      (read-sequence v s)
      v)))

(defun %json-get (obj &rest keys)
  "Walk string KEYS through hash-table OBJ (json-simple objects)."
  (let ((cur obj))
    (dolist (k keys cur)
      (setf cur (cond ((hash-table-p cur) (gethash k cur))
                      ((and (integerp k) (listp cur)) (nth k cur))
                      ((and (integerp k) (vectorp cur)) (aref cur k))
                      (t nil))))))

(defun %pae (payload-type payload)
  "DSSE pre-authentication encoding."
  (%octets (%ascii (format nil "DSSEv1 ~d " (length payload-type)))
           (%ascii payload-type)
           (%ascii (format nil " ~d " (length payload)))
           payload))

(defun %gunzip (octets) (coerce (cram:gzip-decompress octets) '(simple-array (unsigned-byte 8) (*))))

(defun %hex-to-octets (hex)
  (let* ((n (floor (length hex) 2)) (v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun tinfoil-bundle-report-data (bundle)
  "The 64-byte report_data of BUNDLE's SNP report (json-simple hash table)."
  (snp-report-report-data
   (parse-snp-report (%gunzip (base64-decode (%json-get bundle "enclaveAttestationReport" "body"))))))

(defun verify-tinfoil-bundle (bundle ark-der ask-der &key (now (- (get-universal-time) 2208988800)))
  "Verify BUNDLE, a parsed Tinfoil attestation document (json-simple hash tables).
ARK-DER and ASK-DER are the AMD root and intermediate certificates (DER octets), supplied by
the caller (fetch from AMD KDS; pin the ARK out of band).

Returns (values OK-P CHECKS). CHECKS is an alist of (NAME . PASSED-P), plus (:failures . REASONS)."
  (let ((checks '()) (failures '()))
    (flet ((check (name ok &optional reason)
             (push (cons name (and ok t)) checks)
             (unless ok (push (or reason name) failures))))
      (handler-case
          (let* ((report (parse-snp-report
                          (%gunzip (base64-decode (%json-get bundle "enclaveAttestationReport" "body")))))
                 (vcek-der (base64-decode (%json-get bundle "vcek")))
                 (enclave (parse-certificate (first (pem-to-der-list (%json-get bundle "enclaveCert")))))
                 (sigstore (%json-get bundle "sigstoreBundle"))
                 (leaf (parse-certificate
                        (base64-decode (%json-get sigstore "verificationMaterial" "certificate" "rawBytes"))))
                 (env (%json-get sigstore "dsseEnvelope"))
                 (ptype (%json-get env "payloadType"))
                 (payload (base64-decode (%json-get env "payload")))
                 (sig (base64-decode (%json-get (%json-get env "signatures" 0) "sig")))
                 (statement (json-simple:parse (map 'string #'code-char payload))))
            ;; 1. SNP report: chain (ARK/ASK/VCEK), report signature, binding to VCEK.
            (multiple-value-bind (ok reasons)
                (verify-snp-report report ark-der ask-der vcek-der :now now)
              (check "snp report chain/signature/binding" ok
                     (format nil "snp: ~{~a~^; ~}" reasons)))
            ;; 2. report_data binds the enclave TLS key.
            (check "report_data binds enclaveCert SPKI"
                   (equalp (subseq (snp-report-report-data report) 0 32)
                           (sha256 (cert-spki-der enclave)))
                   "report_data does not match SHA-256 of enclaveCert SPKI")
            ;; 3. DSSE signature by the Fulcio leaf (ECDSA P-256 / SHA-256 over PAE).
            (let ((pt (ec-point-from-spki-key +p256+ (cert-spki-key leaf))))
              (multiple-value-bind (r s) (ecdsa-der-signature-rs sig)
                (check "DSSE signature by Fulcio leaf"
                       (verify-ecdsa +p256+ pt (sha256 (%pae ptype payload)) r s)
                       "DSSE signature does not verify under the Fulcio leaf")))
            ;; 4. Statement measurement and subject digest.
            (check "statement snp_measurement == report measurement"
                   (equalp (%hex-to-octets (%json-get statement "predicate" "snp_measurement"))
                           (snp-report-measurement report))
                   "snp_measurement does not match the report")
            (check "statement subject == bundle digest"
                   (equalp (%json-get statement "subject" 0 "digest" "sha256")
                           (%json-get bundle "digest"))
                   "statement subject digest does not match bundle digest"))
        (error (c)
          (push (format nil "malformed bundle: ~a" c) failures))))
    (values (null failures)
            (append (reverse checks) (list (cons :failures (reverse failures)))))))
