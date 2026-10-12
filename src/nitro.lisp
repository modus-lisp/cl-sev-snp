;;;; nitro.lisp -- AWS Nitro Enclaves attestation documents (COSE_Sign1 / ES384).
;;;;
;;;; The sibling of snp.lisp: where that verifies an AMD SEV-SNP report, this verifies the
;;;; document an AWS Nitro enclave produces.  The shape is different in every particular:
;;;;
;;;;   * The document is CBOR, not a fixed-layout binary struct: a COSE_Sign1 (tag 18)
;;;;     array [protected, unprotected, payload, signature].
;;;;   * The signature is ES384 over the COSE Sig_structure, and -- unlike X.509 -- the
;;;;     r||s pair is RAW 96 bytes, not DER.  Feeding it to the DER parser is the classic
;;;;     mistake; it fails as "DER element overruns buffer".
;;;;   * The certificate chain travels INSIDE the signed payload (cabundle), so the whole
;;;;     chain is covered by the signature.  cabundle[0] is the AWS Nitro root itself.
;;;;   * The payload also carries the enclave's public_key and user_data, which is what
;;;;     makes the document useful: those fields are attested, not merely transported.
;;;;
;;;; Trust root: the AWS Nitro Enclaves root G1 certificate, pinned below.  It is the same
;;;; certificate AWS publishes at
;;;;   https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
;;;; (SHA-256 of the DER: 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b).
;;;; Pinning it here rather than trusting cabundle[0] is the whole point: a document that
;;;; ships its own root proves nothing about who issued it.

(in-package :cl-sev-snp)

;;; ---------------------------------------------------------------------------
;;; Minimal CBOR decoder (RFC 8949).  Only what an attestation document uses:
;;; unsigned/negative ints, byte and text strings, arrays, maps, tags, and the
;;; indefinite-length forms.  Returns (values VALUE NEXT-POSITION).
;;; ---------------------------------------------------------------------------

(defstruct (cbor-tag (:constructor mk-cbor-tag (tag value))) tag value)

(defun cbor-decode (v &optional (pos 0))
  "Decode one CBOR item from octet vector V at POS. Returns (values VALUE NEXT-POS)."
  (let* ((ib (aref v pos))
         (major (ash ib -5))
         (ai (logand ib #x1f)))
    (multiple-value-bind (val p)
        (cond ((< ai 24) (values ai (+ pos 1)))
              ((= ai 24) (values (aref v (+ pos 1)) (+ pos 2)))
              ((= ai 25) (values (logior (ash (aref v (+ pos 1)) 8) (aref v (+ pos 2))) (+ pos 3)))
              ((= ai 26) (values (loop for i from 1 to 4 for n = 0 then (logior (ash n 8) (aref v (+ pos i)))
                                       finally (return n)) (+ pos 5)))
              ((= ai 27) (values (loop for i from 1 to 8 for n = 0 then (logior (ash n 8) (aref v (+ pos i)))
                                       finally (return n)) (+ pos 9)))
              ((= ai 31) (values :indefinite (+ pos 1)))
              (t (%fail "CBOR: bad additional info ~a" ai)))
      (ecase major
        (0 (values val p))
        (1 (values (- -1 val) p))
        (2 (if (eq val :indefinite)
               (let ((chunks '()) (q p))
                 (loop (multiple-value-bind (x np) (cbor-decode v q)
                         (if (eq x :break)
                             (return (values (apply #'concatenate '(vector (unsigned-byte 8))
                                                    (nreverse chunks)) np))
                             (progn (push x chunks) (setf q np))))))
               (values (subseq v p (+ p val)) (+ p val))))
        (3 (if (eq val :indefinite)
               (let ((s (make-string-output-stream)) (q p))
                 (loop (multiple-value-bind (x np) (cbor-decode v q)
                         (if (eq x :break) (return (values (get-output-stream-string s) np))
                             (progn (write-string x s) (setf q np))))))
               (values (map 'string #'code-char (subseq v p (+ p val))) (+ p val))))
        (4 (if (eq val :indefinite)
               (let ((out '()) (q p))
                 (loop (multiple-value-bind (x np) (cbor-decode v q)
                         (if (eq x :break) (return (values (nreverse out) np))
                             (progn (push x out) (setf q np))))))
               (let ((out '()) (q p))
                 (dotimes (i val (values (nreverse out) q))
                   (multiple-value-bind (x np) (cbor-decode v q) (push x out) (setf q np))))))
        (5 (if (eq val :indefinite)
               (let ((out '()) (q p))
                 (loop (multiple-value-bind (k np) (cbor-decode v q)
                         (if (eq k :break) (return (values (nreverse out) np))
                             (multiple-value-bind (x np2) (cbor-decode v np)
                               (push (cons k x) out) (setf q np2))))))
               (let ((out '()) (q p))
                 (dotimes (i val (values (nreverse out) q))
                   (multiple-value-bind (k np) (cbor-decode v q)
                     (multiple-value-bind (x np2) (cbor-decode v np)
                       (push (cons k x) out) (setf q np2)))))))
        (6 (multiple-value-bind (x np) (cbor-decode v p) (values (mk-cbor-tag val x) np)))
        (7 (cond ((= ai 20) (values nil p)) ((= ai 21) (values t p))
                 ((= ai 22) (values nil p)) ((= ai 23) (values nil p))
                 ((= ai 31) (values :break p))
                 (t (values val p))))))))

(defun %cbor-head (major len)
  "Encode a CBOR head for MAJOR type and length LEN."
  (cond ((< len 24) (vector (logior (ash major 5) len)))
        ((< len 256) (vector (logior (ash major 5) 24) len))
        ((< len 65536) (vector (logior (ash major 5) 25) (ldb (byte 8 8) len) (ldb (byte 8 0) len)))
        (t (vector (logior (ash major 5) 26)
                   (ldb (byte 8 24) len) (ldb (byte 8 16) len)
                   (ldb (byte 8 8) len) (ldb (byte 8 0) len)))))

(defun %cat (&rest vs)
  (let ((out (make-array (reduce #'+ vs :key #'length) :element-type '(unsigned-byte 8))) (o 0))
    (dolist (v vs out) (replace out v :start1 o) (incf o (length v)))))

(defun %cose-sig-structure (protected payload)
  "COSE Sig_structure for a single signer: [\"Signature1\", protected, external_aad, payload]."
  (let ((ctx (map '(simple-array (unsigned-byte 8) (*)) #'char-code "Signature1")))
    (%cat (vector #x84)
          (%cbor-head 3 (length ctx)) ctx
          (%cbor-head 2 (length protected)) protected
          (vector #x40)                       ; empty external_aad
          (%cbor-head 2 (length payload)) payload)))

;;; ---------------------------------------------------------------------------
;;; The pinned AWS Nitro Enclaves root (G1).
;;; ---------------------------------------------------------------------------

(defparameter *aws-nitro-root-pem*
  "-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
"
  "The AWS Nitro Enclaves root G1 certificate (P-384). Pinned; see the file header.")

(defun nitro-root-certificate ()
  "Parse the pinned AWS Nitro root. Returns a CERT."
  (parse-certificate (first (pem-to-der-list *aws-nitro-root-pem*))))

;;; ---------------------------------------------------------------------------
;;; The document.
;;; ---------------------------------------------------------------------------

(defstruct nitro-doc
  raw            ; the octets as received
  module-id      ; string
  digest         ; string, e.g. "SHA384"
  timestamp      ; universal time
  pcrs           ; vector of 16 octet vectors
  certificate    ; the leaf CERT (the enclave's own)
  cabundle       ; list of CERT, leaf-ward first (cabundle[0] is the AWS root)
  public-key     ; octets, or NIL
  user-data      ; octets, or NIL
  nonce          ; octets, or NIL
  protected      ; the COSE protected header octets
  payload        ; the COSE payload octets
  signature)     ; the raw 96-byte r||s

(defun parse-nitro-doc (octets)
  "Parse an AWS Nitro attestation document (COSE_Sign1, tag 18) into a NITRO-DOC.
Signals ATTENTION-ERROR on anything malformed. Does NOT verify anything."
  (let* ((cose (cbor-decode octets))
         (cose (if (and (cbor-tag-p cose) (= (cbor-tag-tag cose) 18)) (cbor-tag-value cose) cose))
         (protected (nth 0 cose))
         (payload (nth 2 cose))
         (sig (nth 3 cose))
         (pl (cbor-decode payload))
         (g (lambda (k) (cdr (assoc k pl :test #'equal)))))
    (unless (and (vectorp protected) (vectorp payload) (vectorp sig))
      (%fail "Nitro: COSE_Sign1 is not [protected, unprotected, payload, signature]"))
    (unless (= (length sig) 96)
      (%fail "Nitro: signature is ~d bytes, expected raw 96 (r||s)" (length sig)))
    (let ((pcrs (funcall g "pcrs")))
      (make-nitro-doc
       :raw octets
       :module-id (funcall g "module_id")
       :digest (funcall g "digest")
       :timestamp (funcall g "timestamp")
       :pcrs (coerce (mapcar (lambda (p) (cdr p)) pcrs) 'vector)
       :certificate (parse-certificate (funcall g "certificate"))
       :cabundle (mapcar #'parse-certificate (funcall g "cabundle"))
       :public-key (funcall g "public_key")
       :user-data (funcall g "user_data")
       :nonce (funcall g "nonce")
       :protected protected
       :payload payload
       :signature sig))))

(defun nitro-doc-pcr (doc index)
  "PCR number INDEX (0..15) of DOC as octets."
  (aref (nitro-doc-pcrs doc) index))

(defun verify-nitro-doc (octets &key expected-pcr0 nonce-hex
                                      (now (- (get-universal-time) 2208988800)))
  "Verify an AWS Nitro attestation document. Returns (values DOC OK-P CHECKS).

CHECKS is an alist of (NAME . PASSED-P).  DOC is the parsed NITRO-DOC (NIL if it would not
parse).  What is checked:
  1. the COSE_Sign1 ES384 signature, under the document's own leaf certificate;
  2. the protected header's alg is ES384 (-35);
  3. the certificate chain terminates at the PINNED AWS Nitro root, and every link verifies;
  4. every certificate is within its validity window at NOW;
  5. the nonce, when NONCE-HEX is given, matches the one the caller sent;
  6. PCR0, when EXPECTED-PCR0 is given, matches the published measurement.
The caller is responsible for the last two: this function cannot know what you asked for."
  (let ((checks '()) (failures '()) (doc nil))
    (flet ((check (name ok &optional reason)
             (push (cons name (and ok t)) checks)
             (unless ok (push (or reason name) failures))))
      (handler-case
          (let* ((d (setf doc (parse-nitro-doc octets)))
                 (protected (nitro-doc-protected d))
                 (payload (nitro-doc-payload d))
                 (sig (nitro-doc-signature d))
                 (leaf (nitro-doc-certificate d))
                 (root (nitro-root-certificate))
                 (chain (append (nitro-doc-cabundle d) (list leaf)))
                 (hdr (cbor-decode protected))
                 (alg (cdr (assoc 1 hdr))))
            ;; 1. The COSE signature. Raw r||s, NOT DER.
            (let* ((pt (ec-point-from-spki-key +p384-curve+ (cert-spki-key leaf)))
                   (digest (sha384 (%cose-sig-structure protected payload))))
              (check "COSE_Sign1 ES384 signature"
                     (verify-ecdsa +p384-curve+ pt digest
                                   (%int-be sig 0 48) (%int-be sig 48 96))))
            (check "COSE alg is ES384 (-35)" (= alg -35))
            ;; 2. Chain: cabundle[0] must BE the pinned root, then each link verifies.
            (check "chain terminates at pinned AWS Nitro root"
                   (equalp (sha256 (cert-der (first chain))) (sha256 (cert-der root)))
                   "cabundle[0] is not the pinned AWS Nitro root")
            (loop for i from 1 below (length chain)
                  do (let* ((subj (nth i chain)) (iss (nth (1- i) chain))
                            (ipt (ec-point-from-spki-key +p384-curve+ (cert-spki-key iss)))
                            (d (sha384 (cert-tbs subj))))
                       (multiple-value-bind (r s) (ecdsa-der-signature-rs (cert-signature subj))
                         (check (format nil "chain link ~d: ~a" i (cert-subject-cn subj))
                                (verify-ecdsa +p384-curve+ ipt d r s)))))
            ;; 3. Validity windows.
            (loop for c in chain
                  do (check (format nil "validity: ~a" (cert-subject-cn c))
                            (and (<= (cert-not-before c) now) (<= now (cert-not-after c)))))
            ;; 4. Freshness and measurement, when the caller supplies what it asked for.
            (when nonce-hex
              (check "nonce matches request"
                     (and (nitro-doc-nonce d)
                          (string-equal (hex-string (nitro-doc-nonce d)) nonce-hex))))
            (when expected-pcr0
              (check "PCR0 matches published measurement"
                     (string-equal (hex-string (nitro-doc-pcr d 0)) expected-pcr0)))
            (values doc (null failures) (nreverse checks)))
        (error (e)
          (check "parse" nil (format nil "~a" e))
          (values nil nil (nreverse checks)))))))
