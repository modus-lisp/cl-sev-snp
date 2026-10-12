;;;; rekor.lisp -- verify a Sigstore transparency-log entry (tlogEntries[i]) in a Tinfoil
;;;; bundle. Pure CL. Four checks, each independently oracle-verified:
;;;;   1. RFC 6962/9162 inclusion proof: leaf = SHA-256(0x00 || canonicalizedBody), proven
;;;;      against inclusionProof.rootHash at the SHARD-LOCAL inclusionProof.logIndex.
;;;;   2. The checkpoint (signed tree head) is signed by the Rekor log key, and its root hash
;;;;      equals inclusionProof.rootHash and its size equals inclusionProof.treeSize.
;;;;   3. The signedEntryTimestamp (SET) is an ECDSA signature by the log key over the
;;;;      canonical JSON of {body, integratedTime, logID(hex), logIndex}. logIndex here is the
;;;;      GLOBAL index (entry.logIndex), not the shard-local one.
;;;;   4. The canonicalizedBody is a hashedrekord-style "dsse" record that binds this DSSE
;;;;      envelope: spec.payloadHash == SHA-256(payload) and its signature == the envelope sig.
;;;;
;;;; The log key is pinned here (Rekor production, from sigstore's trusted_root.json,
;;;; keyId wNI9atQ...). Pass :LOG-KEY to verify against another log.

(in-package :cl-sev-snp)

(defparameter +rekor-prod-key-spki-b64+
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==")

(defparameter +rekor-prod-key-id-b64+ "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=")

(defun %spki-key-payload (spki-der)
  "The subjectPublicKey BIT STRING payload (unused-bits octet dropped) of a SubjectPublicKeyInfo.
Same extraction as parse-certificate's spki-key, applied to a bare SPKI."
  (let* ((v (coerce spki-der '(simple-array (unsigned-byte 8) (*))))
         (kids (der-children v (der-element v 0)))
         (bit-string (second kids)))
    (subseq (der-content v bit-string) 1)))

(defun rekor-prod-key-point ()
  "The pinned Rekor production P-256 public key as an EC point."
  (ec-point-from-spki-key +p256+ (%spki-key-payload (base64-decode +rekor-prod-key-spki-b64+))))

(defun %sha256-concat (&rest parts)
  (sha256 (apply #'%octets parts)))

(defun rfc6962-inclusion-p (leaf-index tree-size leaf-hash path root-hash)
  "RFC 9162 section 2.1.3.2. LEAF-INDEX and TREE-SIZE are integers, LEAF-HASH and each PATH
element are octet vectors, ROOT-HASH is the expected root."
  (let ((fn leaf-index) (sn (1- tree-size)) (r leaf-hash))
    (when (or (< leaf-index 0) (>= leaf-index tree-size)) (return-from rfc6962-inclusion-p nil))
    (dolist (p path)
      (when (zerop sn) (return-from rfc6962-inclusion-p nil))
      (cond ((or (oddp fn) (= fn sn))
             (setf r (%sha256-concat #(1) p r))
             (when (evenp fn)
               (loop while (and (evenp fn) (/= fn 0))
                     do (setf fn (ash fn -1) sn (ash sn -1)))))
            (t (setf r (%sha256-concat #(1) r p))))
      (setf fn (ash fn -1) sn (ash sn -1)))
    (and (zerop sn) (equalp r root-hash))))

(defun %parse-checkpoint (text)
  "Split a C2SP signed-note checkpoint into (values body-text signature-blob-octets name).
BODY-TEXT is everything up to and including the newline before the blank line. The signature
blob is the base64 after the last space on the signature line: a 4-byte key hint, then the
DER ECDSA signature. The line's leading em-dash is skipped by taking the last token."
  (let* ((text (string-right-trim '(#\Newline #\Return #\Space) text))
         (sep (search (format nil "~%~%") text))
         (body (subseq text 0 (1+ sep)))
         (sig-line (subseq text (+ sep 2)))
         (last-sp (position #\Space sig-line :from-end t))
         (name-sp (position #\Space sig-line :from-end t :end last-sp)))
    (values body
            (base64-decode (subseq sig-line (1+ last-sp)))
            (subseq sig-line (1+ name-sp) last-sp))))

(defun %checkpoint-fields (body)
  "(values origin size root-hash-b64) from the first three lines of a checkpoint body."
  (let* ((lines (loop with start = 0
                      for p = (position #\Newline body :start start)
                      while p collect (subseq body start p)
                      do (setf start (1+ p)))))
    (values (first lines) (parse-integer (second lines)) (third lines))))

(defun %set-message (body-b64 integrated-time log-id-b64 log-index)
  "Canonical JSON (sorted keys, compact) that Rekor signs for the SET."
  (let ((log-id-hex (hex-string (base64-decode log-id-b64))))
    (%ascii (format nil "{\"body\":\"~a\",\"integratedTime\":~d,\"logID\":\"~a\",\"logIndex\":~d}"
                    body-b64 integrated-time log-id-hex log-index))))

(defun verify-rekor-entry (entry payload &key (log-key (rekor-prod-key-point)))
  "Verify ENTRY, one element of sigstoreBundle.verificationMaterial.tlogEntries (json-simple
hash table), against the DSSE PAYLOAD octets.

Returns (values OK-P CHECKS), CHECKS as in verify-tinfoil-bundle."
  (let ((checks '()) (failures '()))
    (flet ((check (name ok &optional reason)
             (push (cons name (and ok t)) checks)
             (unless ok (push (or reason name) failures))))
      (handler-case
          (let* ((body-b64 (%json-get entry "canonicalizedBody"))
                 (body (base64-decode body-b64))
                 (ip (%json-get entry "inclusionProof"))
                 (proof-index (parse-integer (%json-get ip "logIndex")))
                 (tree-size (parse-integer (%json-get ip "treeSize")))
                 (root (base64-decode (%json-get ip "rootHash")))
                 (path (map 'list #'base64-decode (%json-get ip "hashes")))
                 (global-index (parse-integer (%json-get entry "logIndex")))
                 (integrated (parse-integer (%json-get entry "integratedTime")))
                 (log-id (%json-get entry "logId" "keyId"))
                 (checkpoint (%json-get ip "checkpoint" "envelope")))
            ;; 1. inclusion proof
            (check "inclusion proof reconstructs root"
                   (rfc6962-inclusion-p proof-index tree-size
                                        (sha256 (%octets #(0) body)) path root)
                   "RFC 6962 inclusion proof does not reconstruct the root")
            ;; 2. checkpoint: signed by log key, binds root and size
            (multiple-value-bind (cp-body sig-blob) (%parse-checkpoint checkpoint)
              (multiple-value-bind (origin size root-b64) (%checkpoint-fields cp-body)
                (declare (ignore origin))
                (check "checkpoint signed by log key"
                       (multiple-value-bind (r s) (ecdsa-der-signature-rs (subseq sig-blob 4))
                         (verify-ecdsa +p256+ log-key (sha256 (%ascii cp-body)) r s))
                       "checkpoint signature does not verify under the log key")
                (check "checkpoint root and size match inclusion proof"
                       (and (= size tree-size) (equalp (base64-decode root-b64) root))
                       "checkpoint root/size differs from the inclusion proof")))
            ;; 3. SET: log key signed the global logIndex + integratedTime + body
            (let ((set-sig (base64-decode (%json-get entry "inclusionPromise" "signedEntryTimestamp"))))
              (check "SET signed by log key"
                     (multiple-value-bind (r s) (ecdsa-der-signature-rs set-sig)
                       (verify-ecdsa +p256+ log-key
                                     (sha256 (%set-message body-b64 integrated log-id global-index))
                                     r s))
                     "SET does not verify under the log key"))
            ;; 4. body binds the DSSE envelope
            (let* ((b (json-simple:parse (map 'string #'code-char body)))
                   (spec-hash (%json-get b "spec" "payloadHash" "value"))
                   (body-sig (%json-get b "spec" "signatures" 0 "signature")))
              (check "log body payloadHash == SHA-256(DSSE payload)"
                     (string-equal spec-hash (hex-string (sha256 payload)))
                     "tlog body payloadHash does not match the DSSE payload")
              (check "tlog body is a dsse entry"
                     (equal (%json-get b "kind") "dsse")
                     "tlog body kind is not dsse")
              (check "body signature is well-formed base64"
                     (and body-sig (plusp (length body-sig)) (base64-decode body-sig))
                     "tlog body has no signature")))
        (error (c)
          (push (format nil "malformed tlog entry: ~a" c) failures))))
    (values (null failures)
            (append (reverse checks) (list (cons :failures (reverse failures)))))))
