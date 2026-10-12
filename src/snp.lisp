;;;; snp.lisp -- AMD SEV-SNP attestation report: parse, and verify the chain
;;;; ARK -> ASK -> VCEK (RSASSA-PSS SHA-384), the report signature (ECDSA P-384 SHA-384),
;;;; and the chip-ID / TCB / policy binding against the VCEK extensions.
;;;;
;;;; Report layout (AMD SEV-SNP ABI, version 2/3), little-endian integers:
;;;;   0x000 version  0x008 policy  0x030 vmpl  0x050 report_data (64)  0x090 measurement (48)
;;;;   0x1a0 chip_id (64)  0x2a0 signature r (72, LE)  0x2e8 signature s (72, LE)
;;;; The signature covers bytes [0, 0x2a0).

(in-package :cl-sev-snp)

(defconstant +snp-report-size+ #x4a0)  ; 1184 bytes, the size of the report we handle

(defstruct snp-report
  octets version policy vmpl report-data measurement chip-id r s)

(defun %le (v s e)
  (let ((n 0)) (loop for i from (1- e) downto s do (setf n (+ (* n 256) (aref v i)))) n))

(defun parse-snp-report (octets)
  "Parse a raw SEV-SNP attestation report (already gunzipped). Signals ATTESTATION-ERROR if too short."
  (let ((v (coerce octets '(simple-array (unsigned-byte 8) (*)))))
    (when (< (length v) #x2e8) (%fail "SNP report too short (~d bytes)" (length v)))
    (make-snp-report
     :octets v
     :version (%le v 0 4)
     :policy (%le v 8 16)
     :vmpl (%le v #x30 #x34)
     :report-data (subseq v #x50 #x90)
     :measurement (subseq v #x90 #xc0)
     :chip-id (subseq v #x1a0 #x1e0)
     :r (%le v #x2a0 (+ #x2a0 72))
     :s (%le v #x2e8 (+ #x2e8 72)))))

(defun snp-report-debug-p (report)
  "Bit 19 of the guest policy: debugging allowed."
  (logbitp 19 (snp-report-policy report)))

(defun %chain-link (label signer subject)
  "One RSASSA-PSS link: SUBJECT's signature checks under SIGNER's key."
  (multiple-value-bind (n e) (rsa-public-key-from-spki-key (cert-spki-key signer))
    (let ((ok (verify-rsa-pss n e (cert-tbs subject) (cert-signature subject)
                              :hash #'sha384 :hash-len 48 :salt-len 48)))
      (values ok label))))

(defparameter +snp-pss-oid+ "1.2.840.113549.1.1.10")
(defparameter +snp-oid-chip-id+ "1.3.6.1.4.1.3704.1.4")
(defparameter +snp-tcb-oids+
  '(("1.3.6.1.4.1.3704.1.3.1" . 0)   ; bootloader SPL  -> report byte 0x180
    ("1.3.6.1.4.1.3704.1.3.2" . 1)   ; TEE SPL         -> 0x181
    ("1.3.6.1.4.1.3704.1.3.3" . 6)   ; SNP SPL         -> 0x186
    ("1.3.6.1.4.1.3704.1.3.8" . 7))) ; microcode SPL   -> 0x187

(defun %vcek-int-ext (cert oid)
  "The INTEGER value of a VCEK extension, or NIL when absent."
  (let ((v (cert-extension cert oid)))
    (when v
      (let* ((vv (coerce v '(simple-array (unsigned-byte 8) (*))))
             (tlv (der-element vv 0)))
        (%le vv (tlv-start tlv) (tlv-end tlv))))))

(defun %check-binding (report vcek)
  "List of failed binding checks (strings). Empty when the report agrees with the VCEK."
  (let ((failures '()))
    ;; chip ID: VLEK-signed reports carry an all-zero chip id and no hwid extension.
    (let ((chip (snp-report-chip-id report)))
      (unless (or (every #'zerop chip)
                  (let ((h (cert-extension vcek +snp-oid-chip-id+)))
                    (and h (equalp h chip))))
        (push "chip_id does not match VCEK hwid extension" failures)))
    ;; TCB SPL values must match the certificate extensions.
    (loop for (oid . idx) in +snp-tcb-oids+
          do (let ((ext (%vcek-int-ext vcek oid)))
               (unless (and ext (= ext (aref (snp-report-octets report) (+ #x180 idx))))
                 (push (format nil "TCB component ~a does not match VCEK" oid) failures))))
    (when (snp-report-debug-p report) (push "policy: debugging is enabled" failures))
    (unless (zerop (snp-report-vmpl report)) (push "report not produced at VMPL0" failures))
    failures))

(defun %check-time (cert label now)
  (if (and (<= (cert-not-before cert) now) (<= now (cert-not-after cert)))
      nil
      (format nil "~a is outside its validity period" label)))

(defun verify-snp-report (report ark-der ask-der vcek-der
                          &key (now (- (get-universal-time) 2208988800)))
  "Verify REPORT (SNP-REPORT struct) against the ARK, ASK and VCEK certificates (DER octets).
Returns (values OK-P FAILURES) where FAILURES is a list of human-readable reasons, empty on success."
  (let* ((ark (parse-certificate ark-der))
         (ask (parse-certificate ask-der))
         (vcek (parse-certificate vcek-der))
         (failures '()))
    (flet ((fail (fmt &rest args) (push (apply #'format nil fmt args) failures)))
      ;; Profile: every chain link must be RSASSA-PSS.
      (loop for (label c) in (list (list "ARK" ark) (list "ASK" ask) (list "VCEK" vcek))
            unless (string= (cert-sig-alg-oid c) +snp-pss-oid+)
              do (fail "~a is not RSASSA-PSS" label))
      ;; ARK self-signed, ASK by ARK, VCEK by ASK.
      (unless (%chain-link "ARK self" ark ark) (fail "ARK self-signature invalid"))
      (unless (%chain-link "ASK by ARK" ark ask) (fail "ASK not signed by ARK"))
      (unless (%chain-link "VCEK by ASK" ask vcek) (fail "VCEK not signed by ASK"))
      ;; Report signature: ECDSA P-384 over SHA-384 of bytes [0, 0x2a0).
      (let ((pt (handler-case (ec-point-from-spki-key +p384-curve+ (cert-spki-key vcek))
                  (attestation-error () nil))))
        (cond ((null pt) (fail "VCEK public key is not a valid P-384 point"))
              ((not (verify-ecdsa +p384-curve+ pt
                                  (sha384 (subseq (snp-report-octets report) 0 #x2a0))
                                  (snp-report-r report) (snp-report-s report)))
               (fail "report signature invalid (not signed by this VCEK)"))))
      ;; Validity periods.
      (dolist (pair (list (cons ark "ARK") (cons ask "ASK") (cons vcek "VCEK")))
        (let ((msg (%check-time (car pair) (cdr pair) now))) (when msg (push msg failures))))
      ;; Binding to the report's own fields.
      (dolist (f (%check-binding report vcek)) (push f failures)))
    (values (null failures) (nreverse failures))))
