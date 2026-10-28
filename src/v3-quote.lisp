;;;; v3-quote.lisp -- Tinfoil attestation document v3: the quote layer (SEV-SNP).
;;;;
;;;; Conformance stage B3, v3-authenticate-quote.  Given a v3 document the envelope
;;;; layer accepted, prove that its SEV-SNP report was signed by a genuine AMD chip:
;;;;
;;;;   - the report is a 1184-byte SNP report whose CPUID names a product line we
;;;;     have a root for (Genoa or Turin; a report without CPUID, version < 3, rejects);
;;;;   - it was signed with a VCEK (SIGNER_INFO.SIGNING_KEY = 0) and does not mask its
;;;;     CHIP_ID (the machines map is keyed by it);
;;;;   - the VCEK and the ASK/ARK chain come from the document's own collateral (no
;;;;     network), the chain's ARK and ASK are exactly the trusted anchors, and every
;;;;     link verifies (RSASSA-PSS SHA-384), every certificate is inside its validity;
;;;;   - the VCEK names this chip (hwid = CHIP_ID), this TCB (SPL extensions =
;;;;     REPORTED_TCB) and this product line;
;;;;   - the AMD CRL from the collateral is present, signed by the ARK, inside its
;;;;     validity window, and does not list the ASK or the VCEK;
;;;;   - the report signature verifies under the VCEK (ECDSA P-384 SHA-384).
;;;;
;;;; This is AUTHENTICATION only: it says the report is genuine, not that its contents
;;;; are what we expect.  Comparing them (TCB floors, guest policy, measurement,
;;;; REPORT_DATA) is the policy layer.  Port of tinfoil-go verify/internal/quote/sev
;;;; (Authenticate) and the go-sev-guest checks it delegates to.

(in-package :cl-sev-snp)

(defun %quote-reject (fmt &rest args)
  (apply #'%v3-reject "QUOTE_REJECTED" fmt args))

(defparameter +snp-oid-product-name+ "1.3.6.1.4.1.3704.1.2")
(defparameter +snp-sev-guest-v2+ "https://tinfoil.sh/predicate/sev-snp-guest/v2")

;;; ---- report fields ---------------------------------------------------------

(defun %snp-product (octets)
  "The SEV product line from the report's CPUID family/model (bytes 0x188, 0x189),
present since report version 3.  NIL when the report carries none or names a product
this verifier has no root for."
  (let ((family (aref octets #x188)) (model (aref octets #x189)))
    (cond ((and (zerop family) (zerop model)) nil)
          ((and (= family #x19) (or (<= #x10 model #x1f) (<= #xa0 model #xaf))) "Genoa")
          ((and (= family #x1a) (<= model #x1f)) "Turin")
          (t nil))))

(defun %snp-tcb-bytes (octets offset) (subseq octets offset (+ offset 8)))

(defparameter +snp-tcb-oids-by-product+
  '(("Genoa" . (("1.3.6.1.4.1.3704.1.3.1" . 0)    ; bootloader SPL
                ("1.3.6.1.4.1.3704.1.3.2" . 1)    ; TEE SPL
                ("1.3.6.1.4.1.3704.1.3.3" . 6)    ; SNP SPL
                ("1.3.6.1.4.1.3704.1.3.8" . 7)))  ; microcode SPL
    ("Turin" . (("1.3.6.1.4.1.3704.1.3.9" . 0)    ; FMC SPL (Turin only)
                ("1.3.6.1.4.1.3704.1.3.1" . 1)    ; bootloader SPL
                ("1.3.6.1.4.1.3704.1.3.2" . 2)    ; TEE SPL
                ("1.3.6.1.4.1.3704.1.3.3" . 3)    ; SNP SPL
                ("1.3.6.1.4.1.3704.1.3.8" . 7)))) ; microcode SPL
  "Where each VCEK TCB extension sits in the 8-byte REPORTED_TCB, per product line.
Turin moved the layout: FMC at byte 0, then bootloader, TEE and SNP at bytes 1..3.
Measured against a live Turin VCEK (i01.tfinf.maple.ai), whose report bytes
01 03 02 05 00 00 00 61 match its extensions FMC=1 BL=3 TEE=2 SNP=5 UCODE=0x61.")

(defparameter +snp-hwid-length-by-product+ '(("Genoa" . 64) ("Turin" . 8))
  "The hwid a VCEK carries: Genoa the full 64-byte CHIP_ID, Turin only its first
8 bytes, with the rest of the report's CHIP_ID zero.")

;;; ---- PEM, serials, names ---------------------------------------------------

(defun %pem-certificates-strict (pem label)
  "The DER of every PEM block in PEM, which must all be CERTIFICATE blocks with a body,
with nothing but whitespace after the last one."
  (let ((out '()) (pos 0))
    (loop
      (let ((b (search "-----BEGIN " pem :start2 pos)))
        (unless b
          (unless (every (lambda (c) (member c '(#\Space #\Tab #\Newline #\Return))) (subseq pem pos))
            (%quote-reject "~a carries trailing data after the certificates" label))
          (return (nreverse out)))
        (let* ((type-end (or (search "-----" pem :start2 (+ b 11)) (%quote-reject "~a: unterminated PEM header" label)))
               (type (subseq pem (+ b 11) type-end))
               (end-marker (format nil "-----END ~a-----" type))
               (body-start (+ type-end 5))
               (e (or (search end-marker pem :start2 body-start) (%quote-reject "~a: unterminated PEM block" label))))
          (unless (string= type "CERTIFICATE")
            (%quote-reject "~a carries a ~s block, want CERTIFICATE" label type))
          (let ((der (base64-decode (subseq pem body-start e))))
            (when (zerop (length der)) (%quote-reject "~a carries an empty CERTIFICATE block" label))
            (push der out))
          (setf pos (+ e (length end-marker))))))))

(defun %unwrap-octet-string (value)
  "VALUE, or its content when VALUE is itself a DER OCTET STRING spanning the whole
of it.  AMD's VCEKs carry the 64-byte hwid raw; some encoders wrap it in an inner
OCTET STRING, and go-sev-guest accepts both."
  (if (and value (> (length value) 2) (= (aref value 0) #x04))
      (let* ((v (coerce value '(simple-array (unsigned-byte 8) (*))))
             (tlv (ignore-errors (der-element v 0))))
        (if (and tlv (= (tlv-end tlv) (length v))) (der-content v tlv) value))
      value))

(defun %cert-serial (cert)
  "The serialNumber INTEGER of CERT."
  (let* ((v (cert-der cert))
         (tbs (der-children v (first (der-children v (der-element v 0)))))
         (serial (if (= (tlv-tag (first tbs)) #xa0) (second tbs) (first tbs))))
    (%int-be v (tlv-start serial) (tlv-end serial))))

(defun %cert-subject-der (cert)
  "The DER encoding of CERT's subject Name."
  (let* ((v (cert-der cert))
         (tbs (der-children v (first (der-children v (der-element v 0)))))
         (base (if (= (tlv-tag (first tbs)) #xa0) 1 0)))
    (der-whole v (nth (+ base 4) tbs))))

;;; ---- the AMD CRL -----------------------------------------------------------

(defstruct (amd-crl (:conc-name amd-crl-))
  tbs sig-alg-oid signature issuer-der this-update next-update revoked)

(defun parse-amd-crl (der)
  "Parse an X.509 v2 CRL (RFC 5280 TBSCertList) into its signed bytes, issuer, validity
window and the list of revoked serial numbers.  NEXT-UPDATE is NIL when absent."
  (let* ((v (coerce der '(simple-array (unsigned-byte 8) (*))))
         (top (der-element v 0))
         (kids (der-children v top)))
    (unless (= (length kids) 3) (%quote-reject "CRL has ~d top-level fields" (length kids)))
    (destructuring-bind (tbs-t alg-t sig-t) kids
      (let* ((tbs (der-children v tbs-t))
             (tbs (if (= (tlv-tag (first tbs)) #x02) (rest tbs) tbs)) ; optional version
             (issuer (second tbs))
             (this-t (third tbs))
             (rest (nthcdr 3 tbs))
             (next-t (and rest (member (tlv-tag (first rest)) '(#x17 #x18)) (pop rest)))
             (revoked-t (and rest (= (tlv-tag (first rest)) #x30) (pop rest))))
        (make-amd-crl
         :tbs (der-whole v tbs-t)
         :sig-alg-oid (der-oid-string v (first (der-children v alg-t)))
         :signature (subseq (der-content v sig-t) 1)
         :issuer-der (der-whole v issuer)
         :this-update (der-time-unix v this-t)
         :next-update (and next-t (der-time-unix v next-t))
         :revoked (and revoked-t
                       (loop for entry in (der-children v revoked-t)
                             for serial = (first (der-children v entry))
                             collect (%int-be v (tlv-start serial) (tlv-end serial)))))))))

;;; ---- anchors ---------------------------------------------------------------

(defun %anchor-certs (ark-pem ask-pem)
  "The trusted ARK, and ASK when given, as parsed certificates."
  (flet ((one (pem label)
           (let ((ders (%pem-certificates-strict pem label)))
             (unless (= (length ders) 1) (%quote-reject "~a must carry exactly one certificate" label))
             (parse-certificate (first ders)))))
    (values (one ark-pem "AMD root anchor")
            (and ask-pem (plusp (length ask-pem)) (one ask-pem "AMD ASK anchor")))))

;;; ---- authenticate ----------------------------------------------------------

(defun %pss-link (signer subject-tbs subject-signature)
  (multiple-value-bind (n e) (rsa-public-key-from-spki-key (cert-spki-key signer))
    (verify-rsa-pss n e subject-tbs subject-signature :hash #'sha384 :hash-len 48 :salt-len 48)))

(defun v3-authenticate-sev-quote (doc &key ark-pem ask-pem (now (- (get-universal-time) 2208988800)))
  "Authenticate DOC's SEV-SNP report (DOC is a V3-DOCUMENT from V3-CHECK-ENVELOPE)
against the trusted AMD root ARK-PEM (and ASK-PEM when given), using only the
document's collateral.  NOW is Unix seconds.  Returns a plist describing the
authenticated quote; signals V3-REJECT (QUOTE_REJECTED) on any failure."
  (unless (string= (v3-doc-cpu-format doc) +v3-sev-snp-report-format+)
    (%quote-reject "cpu evidence format ~s is not SEV-SNP" (v3-doc-cpu-format doc)))
  (unless ark-pem (%quote-reject "no trusted AMD root supplied"))
  (let* ((octets (coerce (v3-doc-report doc) '(simple-array (unsigned-byte 8) (*))))
         (collateral (v3-doc-collateral doc))
         (vcek-entry (getf collateral :vcek))
         (crl-der (getf collateral :crl)))
    ;; collateral presence (an empty VCEK would make a library fetch one)
    (unless vcek-entry (%quote-reject "document carries no amd-vcek collateral for the CPU"))
    (when (zerop (length (getf vcek-entry :der))) (%quote-reject "amd-vcek collateral carries an empty VCEK"))
    (let ((chain (%pem-certificates-strict (getf vcek-entry :chain-pem) "cert_chain_pem")))
      (unless (= (length chain) 2)
        (%quote-reject "cert_chain_pem must carry exactly the ASK and ARK certificates, got ~d" (length chain)))
      (unless crl-der (%quote-reject "document carries no amd-crl collateral for the CPU"))
      (when (zerop (length crl-der)) (%quote-reject "amd-crl collateral carries an empty CRL"))
      ;; the report itself
      (unless (= (length octets) +snp-report-size+)
        (%quote-reject "SEV-SNP report must be exactly ~d bytes, got ~d" +snp-report-size+ (length octets)))
      (let* ((report (parse-snp-report octets))
             (product (or (%snp-product octets)
                          (%quote-reject "report carries no supported CPUID product (version ~d, family #x~2,'0x model #x~2,'0x)"
                                         (snp-report-version report) (aref octets #x188) (aref octets #x189))))
             (signer-info (%le octets #x48 #x4c))
             (crl (handler-case (parse-amd-crl crl-der)
                    (error (e) (%quote-reject "parsing amd-crl collateral: ~a" e))))
             (vcek (handler-case (parse-certificate (getf vcek-entry :der))
                     (error (e) (%quote-reject "parsing the VCEK: ~a" e))))
             (ask (handler-case (parse-certificate (first chain))
                    (error (e) (%quote-reject "parsing the ASK: ~a" e))))
             (ark (handler-case (parse-certificate (second chain))
                    (error (e) (%quote-reject "parsing the ARK: ~a" e)))))
        (unless (= (%le octets #x34 #x38) 1)
          (%quote-reject "report signature algorithm ~d is not ECDSA P-384 SHA-384" (%le octets #x34 #x38)))
        (unless (zerop (ldb (byte 3 2) signer-info))
          (%quote-reject "report SIGNING_KEY is ~d, not the VCEK" (ldb (byte 3 2) signer-info)))
        (when (logbitp 1 signer-info)
          (%quote-reject "report masks CHIP_ID; masked platform identities are unsupported"))
        ;; anchors: the chain must BE the trusted root (and ASK, when pinned)
        (multiple-value-bind (trusted-ark trusted-ask) (%anchor-certs ark-pem ask-pem)
          (unless (equalp (cert-der ark) (cert-der trusted-ark))
            (%quote-reject "the document's ARK is not the trusted AMD root"))
          (when (and trusted-ask (not (equalp (cert-der ask) (cert-der trusted-ask))))
            (%quote-reject "the document's ASK is not the trusted AMD ASK")))
        ;; chain profile, signatures and names
        (loop for (label c) in (list (list "ARK" ark) (list "ASK" ask) (list "VCEK" vcek))
              unless (string= (cert-sig-alg-oid c) +snp-pss-oid+)
                do (%quote-reject "~a is not signed with RSASSA-PSS" label))
        (unless (%pss-link ark (cert-tbs ark) (cert-signature ark)) (%quote-reject "ARK self-signature invalid"))
        (unless (%pss-link ark (cert-tbs ask) (cert-signature ask)) (%quote-reject "ASK is not signed by the ARK"))
        (unless (%pss-link ask (cert-tbs vcek) (cert-signature vcek)) (%quote-reject "VCEK is not signed by the ASK"))
        (unless (equal (cert-subject-cn ark) (format nil "ARK-~a" product))
          (%quote-reject "ARK common name ~s is not ARK-~a" (cert-subject-cn ark) product))
        (unless (equal (cert-subject-cn ask) (format nil "SEV-~a" product))
          (%quote-reject "ASK common name ~s is not SEV-~a" (cert-subject-cn ask) product))
        (unless (equal (cert-subject-cn vcek) "SEV-VCEK")
          (%quote-reject "VCEK common name ~s is not SEV-VCEK" (cert-subject-cn vcek)))
        (dolist (pair (list (cons ark "ARK") (cons ask "ASK") (cons vcek "VCEK")))
          (unless (<= (cert-not-before (car pair)) now (cert-not-after (car pair)))
            (%quote-reject "~a is outside its validity period" (cdr pair))))
        ;; the VCEK names this product, this chip and this TCB
        (let ((pn (cert-extension vcek +snp-oid-product-name+)))
          (unless (and pn (search (%string-octets product) pn))
            (%quote-reject "VCEK is not issued for product ~a" product)))
        (let* ((hwid (%unwrap-octet-string (cert-extension vcek +snp-oid-chip-id+)))
               (chip (snp-report-chip-id report))
               (n (cdr (assoc product +snp-hwid-length-by-product+ :test #'string=))))
          (unless (and hwid (= (length hwid) n)
                       (equalp hwid (subseq chip 0 n))
                       (every #'zerop (subseq chip n)))
            (%quote-reject "VCEK hwid does not match the report CHIP_ID")))
        (loop for (oid . idx) in (cdr (assoc product +snp-tcb-oids-by-product+ :test #'string=))
              do (let ((ext (%vcek-int-ext vcek oid)))
                   (unless (and ext (= ext (aref octets (+ #x180 idx))))
                     (%quote-reject "VCEK TCB component ~a does not match REPORTED_TCB" oid))))
        ;; revocation: the CRL is the ARK's, current, and lists neither the ASK nor the VCEK
        (unless (string= (amd-crl-sig-alg-oid crl) +snp-pss-oid+)
          (%quote-reject "amd-crl collateral is not signed with RSASSA-PSS"))
        (unless (%pss-link ark (amd-crl-tbs crl) (amd-crl-signature crl))
          (%quote-reject "amd-crl collateral is not signed by the ARK"))
        (unless (equalp (amd-crl-issuer-der crl) (%cert-subject-der ark))
          (%quote-reject "amd-crl collateral is not issued by the ARK"))
        (unless (and (amd-crl-next-update crl)
                     (<= (amd-crl-this-update crl) now (amd-crl-next-update crl)))
          (%quote-reject "amd-crl collateral is outside its validity window"))
        (when (member (%cert-serial ask) (amd-crl-revoked crl))
          (%quote-reject "the ASK is revoked by the AMD CRL"))
        (when (member (%cert-serial vcek) (amd-crl-revoked crl))
          (%quote-reject "the VCEK is revoked by the AMD CRL"))
        ;; the report signature
        (let ((pt (handler-case (ec-point-from-spki-key +p384-curve+ (cert-spki-key vcek))
                    (attestation-error () nil))))
          (unless (and pt (verify-ecdsa +p384-curve+ pt (sha384 (subseq octets 0 #x2a0))
                                        (snp-report-r report) (snp-report-s report)))
            (%quote-reject "report signature does not verify under the VCEK")))
        (list :platform "sev-snp"
              :product product
              :octets octets
              :identity-hex (hex-string (snp-report-chip-id report))
              :launch-measurement (list :type +snp-sev-guest-v2+
                                        :registers (list (hex-string (snp-report-measurement report))))
              :report-data-hex (hex-string (snp-report-report-data report))
              :config (list :version (snp-report-version report)
                            :guest-svn (%le octets 4 8)
                            :guest-policy (snp-report-policy report)
                            :vmpl (snp-report-vmpl report)
                            :current-tcb (hex-string (%snp-tcb-bytes octets #x38))
                            :platform-info (%le octets #x40 #x48)
                            :reported-tcb (hex-string (%snp-tcb-bytes octets #x180))
                            :committed-tcb (hex-string (%snp-tcb-bytes octets #x1e0))
                            :launch-tcb (hex-string (%snp-tcb-bytes octets #x1f0))
                            :current-build (aref octets #x1e8) :current-minor (aref octets #x1e9)
                            :current-major (aref octets #x1ea)
                            :committed-build (aref octets #x1ec) :committed-minor (aref octets #x1ed)
                            :committed-major (aref octets #x1ee)))))))

;;; ---- the binding: our challenge is what the chip signed ---------------------

(defun v3-verify-sev-quote (document-octets nonce &key ark-pem ask-pem (now (- (get-universal-time) 2208988800)))
  "The envelope bound to NONCE, the quote authenticated, and the quote's own
REPORT_DATA equal to the one the envelope recomputed.  That last equality is what
makes the rest mean anything: it ties our fresh nonce, the endorsed keys and the
device evidence to a report AMD's chain signed.  Returns (values DOCUMENT QUOTE).
Signals V3-REJECT: ENVELOPE_REJECTED, QUOTE_REJECTED, or POLICY_REJECTED for a
genuine report that does not carry our REPORT_DATA."
  (let* ((doc (v3-check-envelope document-octets nonce))
         (q (v3-authenticate-sev-quote doc :ark-pem ark-pem :ask-pem ask-pem :now now)))
    (unless (string= (getf q :report-data-hex) (v3-doc-report-data-hex doc))
      (%v3-reject "POLICY_REJECTED" "the report's REPORT_DATA does not bind this document and nonce"))
    (values doc q)))
