;;;; v3-provenance.lisp -- Tinfoil attestation document v3: the provenance layer.
;;;;
;;;; Conformance stage B2, v3-authenticate-provenance.  The document's sigstore-code
;;;; collateral carries a Sigstore bundle whose in-toto statement says "the release
;;;; artifact with this SHA-256 (tinfoil-deployment.json) declares this launch
;;;; measurement and this VM shape".  This file proves who said so:
;;;;
;;;;   - the bundle is the v0.3 single-certificate layout with exactly one DSSE signature
;;;;     over an in-toto payload;
;;;;   - the signing certificate chains to a Fulcio CA in the Sigstore trusted root, and
;;;;     was valid at the moment the transparency log recorded the signature;
;;;;   - it carries at least one valid Signed Certificate Timestamp from a CT log in the
;;;;     trusted root, and no two SCTs from the same log;
;;;;   - the signature is in the Rekor log (inclusion proof against a signed checkpoint,
;;;;     and the signed entry timestamp), and the log entry binds this envelope;
;;;;   - the certificate's identity is the PINNED repository: its SAN is a workflow file
;;;;     under that repository's .github/workflows, run from a tag, issued by GitHub
;;;;     Actions' OIDC, on a GitHub-hosted runner, at a 40-hex commit;
;;;;   - the statement's first subject is the artifact digest, and its predicate is a
;;;;     well-formed multiplatform measurement with a VM shape.
;;;;
;;;; The pin is the caller's: owner/name[@tag][@sha256:digest].  The document's own
;;;; repo/tag/digest are only hints that a pin overrides.  Port of tinfoil-go
;;;; verify/internal/endorsement (AuthenticateCode) and the sigstore-go checks it uses.

(in-package :cl-sev-snp)

(defun %prov-reject (fmt &rest args)
  (apply #'%v3-reject "PROVENANCE_REJECTED" fmt args))

(defparameter +oidc-issuer-github+ "https://token.actions.githubusercontent.com")
(defparameter +multiplatform-predicate+ "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1")
(defparameter +in-toto-statement-v1+ "https://in-toto.io/Statement/v1")
(defparameter +in-toto-payload-type+ "application/vnd.in-toto+json")
(defparameter +sigstore-bundle-v03+ "application/vnd.dev.sigstore.bundle.v0.3+json")

(defparameter +oid-san+ "2.5.29.17")
(defparameter +oid-eku+ "2.5.29.37")
(defparameter +oid-code-signing+ "1.3.6.1.5.5.7.3.3")
(defparameter +oid-sct-list+ "1.3.6.1.4.1.11129.2.4.2")
(defparameter +oid-fulcio-issuer-v1+ "1.3.6.1.4.1.57264.1.1")
(defparameter +oid-fulcio-issuer-v2+ "1.3.6.1.4.1.57264.1.8")
(defparameter +oid-fulcio-runner-env+ "1.3.6.1.4.1.57264.1.11")
(defparameter +oid-fulcio-source-digest+ "1.3.6.1.4.1.57264.1.13")
(defparameter +oid-fulcio-source-ref+ "1.3.6.1.4.1.57264.1.14")
(defparameter +oid-p256+ "1.2.840.10045.3.1.7")
(defparameter +oid-p384+ "1.3.132.0.34")
(defparameter +oid-ecdsa-sha256+ "1.2.840.10045.4.3.2")
(defparameter +oid-ecdsa-sha384+ "1.2.840.10045.4.3.3")

;;; ---- strict-JSON access ----------------------------------------------------

(defun %sj (v &rest path)
  "Walk PATH (member names and array indices) through strict-JSON value V."
  (dolist (k path v)
    (setf v (cond ((and (stringp k) (consp v) (eq (car v) :obj)) (cdr (assoc k (cdr v) :test #'string=)))
                  ((and (integerp k) (consp v) (eq (car v) :arr)) (nth k (cdr v)))
                  (t nil)))))

(defun %sj-list (v) (if (and (consp v) (eq (car v) :arr)) (cdr v) nil))
(defun %sj-string (v) (if (stringp v) v nil))

(defun %sj->ht (v)
  "Strict-JSON value to the json-simple shape (hash tables, vectors) that the existing
Rekor verifier walks."
  (cond ((and (consp v) (eq (car v) :obj))
         (let ((h (make-hash-table :test 'equal)))
           (dolist (m (cdr v) h) (setf (gethash (car m) h) (%sj->ht (cdr m))))))
        ((and (consp v) (eq (car v) :arr)) (map 'vector #'%sj->ht (cdr v)))
        ((and (consp v) (eq (car v) :num)) (let ((x (parse-integer (cdr v) :junk-allowed t))) (or x (cdr v))))
        ((eq v :true) t) ((member v '(:false :null)) nil)
        (t v)))

(defun %b64 (s label)
  (unless (stringp s) (%prov-reject "~a is missing" label))
  (handler-case (base64-decode s) (error () (%prov-reject "~a is not base64" label))))

;;; ---- DER building (for the precertificate) ---------------------------------

(defun %der-len-octets (n)
  (if (< n 128)
      (list n)
      (let ((bytes (loop for x = n then (ash x -8) while (plusp x) collect (logand x #xff))))
        (cons (logior #x80 (length bytes)) (reverse bytes)))))

(defun %der-tlv (tag content)
  (%octets (coerce (cons tag (%der-len-octets (length content))) '(vector (unsigned-byte 8))) content))

;;; ---- signatures ------------------------------------------------------------

(defun %curve-for-oid (oid)
  (cond ((equal oid +oid-p256+) +p256+)
        ((equal oid +oid-p384+) +p384-curve+)
        (t nil)))

(defun %cert-verifies (issuer subject-tbs subject-sig-alg subject-signature)
  "T when SUBJECT's ECDSA signature checks under ISSUER's key."
  (let ((curve (%curve-for-oid (cert-spki-param issuer)))
        (hash (cond ((equal subject-sig-alg +oid-ecdsa-sha256+) #'sha256)
                    ((equal subject-sig-alg +oid-ecdsa-sha384+) #'sha384))))
    (and curve hash
         (handler-case
             (multiple-value-bind (r s) (ecdsa-der-signature-rs subject-signature)
               (verify-ecdsa curve (ec-point-from-spki-key curve (cert-spki-key issuer))
                             (funcall hash subject-tbs) r s))
           (error () nil)))))

(defun %ecdsa-with-key (spki-der message der-sig &key (hash #'sha256))
  "Verify DER-SIG over MESSAGE under the EC key in SPKI-DER (P-256 or P-384)."
  (handler-case
      (let* ((v (coerce spki-der '(simple-array (unsigned-byte 8) (*))))
             (alg (der-children v (first (der-children v (der-element v 0)))))
             (curve (%curve-for-oid (der-oid-string v (second alg)))))
        (and curve
             (multiple-value-bind (r s) (ecdsa-der-signature-rs der-sig)
               (verify-ecdsa curve (ec-point-from-spki-key curve (%spki-key-payload spki-der))
                             (funcall hash message) r s))))
    (error () nil)))

;;; ---- the trusted root ------------------------------------------------------

(defun %rfc3339-unix (s)
  "Unix seconds for an RFC 3339 UTC timestamp (YYYY-MM-DDTHH:MM:SS[.frac]Z)."
  (flet ((n (a b) (parse-integer s :start a :end b)))
    (+ (* 86400 (%days-from-civil (n 0 4) (n 5 7) (n 8 10)))
       (* 3600 (n 11 13)) (* 60 (n 14 16)) (n 17 19))))

(defun %valid-for (obj)
  "(values start end) Unix seconds of a trusted-root validFor, END NIL when open."
  (let ((vf (%sj obj "validFor")))
    (values (and (%sj-string (%sj vf "start")) (%rfc3339-unix (%sj vf "start")))
            (and (%sj-string (%sj vf "end")) (%rfc3339-unix (%sj vf "end"))))))

(defun parse-sigstore-trusted-root (octets)
  "Parse a Sigstore trusted_root.json into a plist: :cas (each a list of parsed
certificates, issuing CA first, with its validity), :tlogs and :ctlogs (each a
plist of :key-id octets, :spki DER and validity)."
  (let ((root (strict-json-parse-octets octets)))
    (flet ((logs (key)
             (mapcar (lambda (l)
                       (multiple-value-bind (start end) (%valid-for (%sj l "publicKey"))
                         (list :key-id (%b64 (%sj l "logId" "keyId") "logId")
                               :spki (%b64 (%sj l "publicKey" "rawBytes") "log key")
                               :start start :end end)))
                     (%sj-list (%sj root key)))))
      (list :cas (mapcar (lambda (ca)
                           (multiple-value-bind (start end) (%valid-for ca)
                             (list :certs (mapcar (lambda (c) (parse-certificate (%b64 (%sj c "rawBytes") "CA cert")))
                                                  (%sj-list (%sj ca "certChain" "certificates")))
                                   :start start :end end)))
                         (%sj-list (%sj root "certificateAuthorities")))
            :tlogs (logs "tlogs")
            :ctlogs (logs "ctlogs")))))

;;; ---- certificate chain ------------------------------------------------------

(defun %chain-to-fulcio (leaf trusted-root at)
  "The issuing CA certificate of LEAF when LEAF chains to one of the trusted root's
Fulcio CAs, every certificate valid at AT (Unix seconds) and the CA inside its own
validFor; signals otherwise."
  (dolist (ca (getf trusted-root :cas)
              (%prov-reject "signing certificate does not chain to a trusted Fulcio CA"))
    (let ((certs (getf ca :certs)))
      (when (and certs
                 (%cert-verifies (first certs) (cert-tbs leaf) (cert-sig-alg-oid leaf) (cert-signature leaf))
                 (loop for (c next) on certs
                       always (%cert-verifies (or next c) (cert-tbs c) (cert-sig-alg-oid c) (cert-signature c)))
                 (every (lambda (c) (<= (cert-not-before c) at (cert-not-after c))) certs)
                 (or (null (getf ca :start)) (<= (getf ca :start) at))
                 (or (null (getf ca :end)) (<= at (getf ca :end))))
        (return (first certs))))))

;;; ---- Signed Certificate Timestamps -----------------------------------------

(defun %u (v start n) (%der-uint v start (+ start n)))

(defun %parse-sct-list (ext-value)
  "SCTs inside the X.509 SCT-list extension: a DER OCTET STRING wrapping a TLS
SignedCertificateTimestampList.  Each SCT is a plist."
  (let* ((outer (coerce ext-value '(simple-array (unsigned-byte 8) (*))))
         (inner (der-content outer (der-element outer 0)))
         (total (%u inner 0 2)) (pos 2) (end (min (length inner) (+ 2 total))) (out '()))
    (loop while (< (+ pos 2) end)
          do (let* ((len (%u inner pos 2)) (s (+ pos 2)) (sct (subseq inner s (+ s len))))
               (when (> (+ s len) end) (%prov-reject "SCT list entry overruns the extension"))
               (let* ((extlen (%u sct 41 2)) (p (+ 43 extlen)) (siglen (%u sct (+ p 2) 2)))
                 (push (list :version (aref sct 0) :log-id (subseq sct 1 33) :timestamp (%u sct 33 8)
                             :extensions (subseq sct 43 (+ 43 extlen))
                             :hash-alg (aref sct p) :sig-alg (aref sct (1+ p))
                             :signature (subseq sct (+ p 4) (+ p 4 siglen)))
                       out))
               (setf pos (+ s len))))
    (nreverse out)))

(defun %precert-tbs (leaf)
  "LEAF's TBSCertificate with the SCT-list extension removed: what the CT log signed."
  (let* ((v (cert-der leaf))
         (tbs-t (first (der-children v (der-element v 0))))
         (parts (mapcar (lambda (child)
                          (if (= (tlv-tag child) #xa3)
                              (let* ((exts (first (der-children v child)))
                                     (kept (remove-if (lambda (e) (equal (der-oid-string v (first (der-children v e)))
                                                                         +oid-sct-list+))
                                                      (der-children v exts))))
                                (%der-tlv #xa3 (%der-tlv #x30 (apply #'%octets (mapcar (lambda (e) (der-whole v e)) kept)))))
                              (der-whole v child)))
                        (der-children v tbs-t))))
    (%der-tlv #x30 (apply #'%octets parts))))

(defun %verify-scts (leaf issuer trusted-root)
  "At least one SCT from a known CT log must verify, and no log may appear twice."
  (let ((ext (cert-extension leaf +oid-sct-list+)))
    (unless ext (%prov-reject "signing certificate carries no SCTs"))
    (let ((scts (handler-case (%parse-sct-list ext) (v3-reject (e) (error e)) (error () (%prov-reject "malformed SCT list"))))
          (seen '()) (verified 0))
      (dolist (sct scts)
        (when (member (getf sct :log-id) seen :test #'equalp)
          (%prov-reject "duplicate SCT log id: the certificate carries several SCTs from one CT log"))
        (push (getf sct :log-id) seen))
      (let ((tbs (%precert-tbs leaf))
            (issuer-key-hash (sha256 (cert-spki-der issuer))))
        (dolist (sct scts)
          (let ((log (find (getf sct :log-id) (getf trusted-root :ctlogs) :key (lambda (l) (getf l :key-id)) :test #'equalp)))
            (when (and log (= (getf sct :version) 0) (= (getf sct :hash-alg) 4) (= (getf sct :sig-alg) 3))
              (let* ((ts (getf sct :timestamp)) (ext (getf sct :extensions))
                     (signed (%octets (coerce (list 0 0) '(vector (unsigned-byte 8)))
                                      (coerce (loop for i from 7 downto 0 collect (ldb (byte 8 (* 8 i)) ts)) '(vector (unsigned-byte 8)))
                                      (coerce (list 0 1) '(vector (unsigned-byte 8)))
                                      issuer-key-hash
                                      (coerce (list (ldb (byte 8 16) (length tbs)) (ldb (byte 8 8) (length tbs)) (ldb (byte 8 0) (length tbs)))
                                              '(vector (unsigned-byte 8)))
                                      tbs
                                      (coerce (list (ldb (byte 8 8) (length ext)) (ldb (byte 8 0) (length ext))) '(vector (unsigned-byte 8)))
                                      ext)))
                (when (%ecdsa-with-key (getf log :spki) signed (getf sct :signature))
                  (incf verified)))))))
      (when (< verified 1) (%prov-reject "no SCT verifies under a trusted CT log")))))

;;; ---- certificate identity --------------------------------------------------

(defun %fulcio-string-ext (leaf oid)
  "A Fulcio v2 extension value (a DER UTF8String), or NIL."
  (let ((v (cert-extension leaf oid)))
    (when v
      (let* ((vv (coerce v '(simple-array (unsigned-byte 8) (*)))) (tlv (ignore-errors (der-element vv 0))))
        (if (and tlv (= (tlv-end tlv) (length vv)) (member (tlv-tag tlv) '(#x0c #x16 #x13)))
            (map 'string #'code-char (der-content vv tlv))
            (map 'string #'code-char vv))))))

(defun %san-uris (leaf)
  (let ((v (cert-extension leaf +oid-san+)))
    (when v
      (let ((vv (coerce v '(simple-array (unsigned-byte 8) (*)))))
        (loop for gn in (der-children vv (der-element vv 0))
              when (= (tlv-tag gn) #x86) collect (map 'string #'code-char (der-content vv gn)))))))

(defun %repo-slug-p (s)
  (let ((slash (position #\/ s)))
    (and slash (= (count #\/ s) 1) (< 0 slash (1- (length s)))
         (every (lambda (c) (or (alphanumericp c) (find c "_.-"))) (remove #\/ s)))))

(defun %workflow-san-p (uri repo)
  "URI is https://github.com/REPO/.github/workflows/FILE@refs/tags/TAG, with FILE free
of / and @ and TAG free of @ (Tinfoil's anchored signing-identity pattern)."
  (let ((prefix (format nil "https://github.com/~a/.github/workflows/" repo)))
    (and (> (length uri) (length prefix)) (string= prefix uri :end2 (length prefix))
         (let* ((rest (subseq uri (length prefix)))
                (at (position #\@ rest)))
           (and at (plusp at)
                (not (find #\/ rest :end at))
                (let ((ref (subseq rest (1+ at))))
                  (and (> (length ref) 10) (string= "refs/tags/" ref :end2 10)
                       (not (find #\@ ref)))))))))

(defun %check-identity (leaf repo)
  (unless (%repo-slug-p repo) (%prov-reject "invalid repository name ~s" repo))
  (let ((uris (%san-uris leaf)))
    (unless (some (lambda (u) (%workflow-san-p u repo)) uris)
      (%prov-reject "signing identity ~s is not a tag-run workflow of ~a" uris repo)))
  (let ((issuer (or (%fulcio-string-ext leaf +oid-fulcio-issuer-v2+) (%fulcio-string-ext leaf +oid-fulcio-issuer-v1+))))
    (unless (equal issuer +oidc-issuer-github+) (%prov-reject "certificate issuer ~s is not GitHub Actions" issuer)))
  (unless (equal (%fulcio-string-ext leaf +oid-fulcio-runner-env+) "github-hosted")
    (%prov-reject "signing workflow did not run on a GitHub-hosted runner"))
  (let ((eku (cert-extension leaf +oid-eku+)))
    (when eku
      (let ((vv (coerce eku '(simple-array (unsigned-byte 8) (*)))))
        (unless (some (lambda (o) (equal (der-oid-string vv o) +oid-code-signing+))
                      (der-children vv (der-element vv 0)))
          (%prov-reject "signing certificate is not for code signing"))))))

;;; ---- the pin ---------------------------------------------------------------

(defun parse-release-pin (pin)
  "OWNER/NAME[@TAG][@sha256:DIGEST] to (values repo tag digest)."
  (let* ((parts (loop with start = 0 for p = (position #\@ pin :start start)
                      collect (subseq pin start p) while p do (setf start (1+ p))))
         (repo (first parts)) (tag nil) (digest nil))
    (dolist (p (rest parts))
      (cond ((and (> (length p) 7) (string= "sha256:" p :end2 7) (null digest))
             (setf digest (subseq p 7))
             (unless (and (= (length digest) 64) (%lower-hex-p digest))
               (%prov-reject "pin digest must be 64 lowercase hex characters")))
            ((and (null tag) (null digest) (plusp (length p))
                  (notany (lambda (c) (find c (format nil " ~~^:?*[\\~c~c" #\Tab #\Newline))) p))
             (setf tag p))
            (t (%prov-reject "invalid release pin ~s: want owner/name[@tag][@sha256:digest]" pin))))
    (unless (%repo-slug-p repo) (%prov-reject "invalid release pin ~s" pin))
    (values repo tag digest)))

;;; ---- the bundle ------------------------------------------------------------

(defun %statement-measurement (statement)
  (unless (equal (%sj statement "predicateType") +multiplatform-predicate+)
    (%prov-reject "unsupported predicate type ~s" (%sj statement "predicateType")))
  (let* ((p (%sj statement "predicate"))
         (snp (%sj p "snp_measurement"))
         (tdx (%sj p "tdx_measurement"))
         (shape (%sj p "vm_shape")))
    (unless (stringp snp) (%prov-reject "multiplatform measurement has no snp_measurement"))
    (unless (and (consp tdx) (eq (car tdx) :obj)) (%prov-reject "tdx_measurement is not an object"))
    (dolist (r '("rtmr1" "rtmr2"))
      (unless (stringp (%sj tdx r)) (%prov-reject "multiplatform measurement has no ~a" r)))
    (unless shape (%prov-reject "code predicate declares no vm_shape"))
    (unless (and (consp shape) (eq (car shape) :obj)) (%prov-reject "vm_shape is not an object"))
    (let ((dims (mapcar (lambda (k)
                          (let ((x (%sj shape k)))
                            (unless (and (consp x) (eq (car x) :num)
                                         (every #'digit-char-p (cdr x)))
                              (%prov-reject "vm_shape member ~s is not a non-negative integer" k))
                            (cons k (parse-integer (cdr x)))))
                        '("cpus" "memory_mb" "gpus" "disks"))))
      (values (list :type +multiplatform-predicate+
                    :registers (list snp (%sj tdx "rtmr1") (%sj tdx "rtmr2")))
              (list :cpus (cdr (assoc "cpus" dims :test #'string=))
                    :memory-mb (cdr (assoc "memory_mb" dims :test #'string=))
                    :gpus (cdr (assoc "gpus" dims :test #'string=))
                    :disks (cdr (assoc "disks" dims :test #'string=)))))))

(defun v3-authenticate-code (doc pin trusted-root)
  "Authenticate DOC's sigstore-code collateral against PIN (owner/name[@tag][@sha256:digest])
and TRUSTED-ROOT (from PARSE-SIGSTORE-TRUSTED-ROOT).  Returns a plist: :repo :tag
:commit :digest :subject-name :measurement (:type :registers) :shape (:cpus :memory-mb
:gpus :disks).  Signals V3-REJECT (PROVENANCE_REJECTED)."
  (let ((code (getf (v3-doc-collateral doc) :sigstore-code)))
    (unless code (%prov-reject "document carries no sigstore-code collateral"))
    (multiple-value-bind (repo pin-tag pin-digest) (parse-release-pin pin)
      (let* ((tag (or pin-tag (let ((g (getf code :tag))) (and (plusp (length g)) g))))
             (digest (string-downcase (or pin-digest (getf code :digest))))
             (bundle (getf code :bundle))
             (vm (%sj bundle "verificationMaterial"))
             (envelope (%sj bundle "dsseEnvelope")))
        (unless (equal (%sj bundle "mediaType") +sigstore-bundle-v03+)
          (%prov-reject "bundle media type ~s is not the v0.3 single-certificate form" (%sj bundle "mediaType")))
        (when (%sj vm "x509CertificateChain")
          (%prov-reject "legacy bundle format: x509CertificateChain is not accepted"))
        (unless envelope (%prov-reject "bundle carries no DSSE envelope"))
        (let ((sigs (%sj-list (%sj envelope "signatures"))))
          (unless (= (length sigs) 1)
            (%prov-reject "DSSE envelope must have exactly one signature, got ~d" (length sigs))))
        (unless (equal (%sj envelope "payloadType") +in-toto-payload-type+)
          (%prov-reject "DSSE payload type ~s is not in-toto" (%sj envelope "payloadType")))
        (let* ((leaf (handler-case (parse-certificate (%b64 (%sj vm "certificate" "rawBytes") "signing certificate"))
                       (v3-reject (e) (error e))
                       (error () (%prov-reject "signing certificate is malformed"))))
               (payload (%b64 (%sj envelope "payload") "DSSE payload"))
               (sig (%b64 (%sj envelope "signatures" 0 "sig") "DSSE signature"))
               (entries (%sj-list (%sj vm "tlogEntries"))))
          (unless entries (%prov-reject "bundle carries no transparency log entry"))
          ;; the transparency log: every entry must be from a trusted log and verify;
          ;; its integrated time is the observer timestamp the certificate is judged at
          (let ((observed nil))
            (dolist (e entries)
              (let* ((key-id (%b64 (%sj e "logId" "keyId") "tlog logId"))
                     (log (find key-id (getf trusted-root :tlogs) :key (lambda (l) (getf l :key-id)) :test #'equalp)))
                (unless log (%prov-reject "transparency log entry is from an untrusted log"))
                (multiple-value-bind (ok checks)
                    (verify-rekor-entry (%sj->ht e) payload
                                        :log-key (ec-point-from-spki-key +p256+ (%spki-key-payload (getf log :spki))))
                  (unless ok (%prov-reject "transparency log entry does not verify: ~{~a~^; ~}" (cdr (assoc :failures checks)))))
                (let* ((body (strict-json-parse-octets (base64-decode (%sj e "canonicalizedBody"))))
                       (body-sig (%sj body "spec" "signatures" 0 "signature")))
                  (unless (and (stringp body-sig) (equalp (base64-decode body-sig) sig))
                    (%prov-reject "transparency log entry records a different signature")))
                (let ((at (parse-integer (%sj e "integratedTime"))))
                  (when (and (getf log :start) (< at (getf log :start))) (%prov-reject "log entry predates its log"))
                  (setf observed (or observed at)))))
            (unless (<= (cert-not-before leaf) observed (cert-not-after leaf))
              (%prov-reject "observer timestamp is outside the signing certificate's validity"))
            ;; chain, SCTs, signature, identity
            (let ((issuer (%chain-to-fulcio leaf trusted-root observed)))
              (%verify-scts leaf issuer trusted-root))
            (let ((curve (%curve-for-oid (cert-spki-param leaf))))
              (unless (and curve
                           (handler-case
                               (multiple-value-bind (r s) (ecdsa-der-signature-rs sig)
                                 (verify-ecdsa curve (ec-point-from-spki-key curve (cert-spki-key leaf))
                                               (funcall (if (eq curve +p384-curve+) #'sha384 #'sha256)
                                                        (%pae +in-toto-payload-type+ payload))
                                               r s))
                             (error () nil)))
                (%prov-reject "DSSE signature does not verify under the signing certificate")))
            (%check-identity leaf repo))
          ;; the statement
          (let* ((statement (handler-case (strict-json-parse-octets payload)
                              (v3-reject () (%prov-reject "DSSE payload is not JSON"))))
                 (subjects (%sj-list (%sj statement "subject")))
                 (ref (%fulcio-string-ext leaf +oid-fulcio-source-ref+))
                 (commit (%fulcio-string-ext leaf +oid-fulcio-source-digest+)))
            (unless (equal (%sj statement "_type") +in-toto-statement-v1+)
              (%prov-reject "payload is not an in-toto v1 statement"))
            (unless subjects (%prov-reject "in-toto statement has no subject"))
            (unless (string-equal (or (%sj (first subjects) "digest" "sha256") "") digest)
              (%prov-reject "subject[0] digest does not match the artifact digest"))
            ;; the predicate before the release identity, as tinfoil-go orders them
            (multiple-value-bind (measurement shape) (%statement-measurement statement)
              (unless (and ref (> (length ref) 10) (string= "refs/tags/" ref :end2 10))
                (%prov-reject "source ref ~s is not a tag" ref))
              (when (and tag (string/= (subseq ref 10) tag))
                (%prov-reject "source ref ~s does not match tag ~s" ref tag))
              (unless (and commit (= (length commit) 40) (%lower-hex-p commit))
                (%prov-reject "source digest is not a lowercase Git commit"))
              (unless (plusp (length (or (%sj-string (%sj (first subjects) "name")) "")))
                (%prov-reject "statement has no named subject"))
              (list :repo repo :tag (subseq ref 10) :commit commit :digest digest
                    :subject-name (%sj (first subjects) "name")
                    :measurement measurement :shape shape))))))))
