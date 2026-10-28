;;;; v3.lisp -- Tinfoil attestation document v3: the envelope layer.
;;;;
;;;; A v3 document (https://tinfoil.sh/predicate/attestation/v3) is a challenge, CPU
;;;; evidence, two ENDORSED sections and an array of collateral entries.  The endorsed
;;;; sections are bound into the CPU quote's REPORT_DATA:
;;;;
;;;;   crypto_material_hash = SHA-256(base64-decoded crypto_material bytes)
;;;;   device_evidence_hash = SHA-256(base64-decoded device_evidence bytes)
;;;;   REPORT_DATA[0:32]    = SHA-256("https://tinfoil.sh/report-data/v1"
;;;;                                  || nonce || crypto_material_hash || device_evidence_hash)
;;;;   REPORT_DATA[32:64]   = zeros
;;;;
;;;; This file is the LOCAL CONSISTENCY check (conformance stage B1, v3-check-envelope).
;;;; It authenticates nothing: a document that passes says only that its parts agree
;;;; with each other and with the nonce we sent.  Nothing in it is trusted until the
;;;; quote proves the hardware signed that REPORT_DATA (the quote layer).
;;;;
;;;; The rules are a port of tinfoil-go verify/document (Parse, decode, bind) and
;;;; verify/document/collateral (Decode, validate), including the strictness of Go's
;;;; json/v2 with RejectUnknownMembers: unknown members reject case-sensitively,
;;;; duplicate member names reject everywhere, invalid UTF-8 and trailing data reject,
;;;; hex must be lowercase and of exact length, base64 must be canonical.  The suite
;;;; that grades it is tinfoil-conformance vectors/v3/envelope.

(in-package :cl-sev-snp)

(defconstant +v3-nonce-size+ 32)

(defparameter +v3-format+ "https://tinfoil.sh/predicate/attestation/v3")
(defparameter +v3-report-data-algorithm+ "https://tinfoil.sh/report-data/v1")
(defparameter +v3-crypto-material-format+ "https://tinfoil.sh/crypto-material/v1")
(defparameter +v3-device-evidence-format+ "https://tinfoil.sh/device-evidence/v1")
(defparameter +v3-sev-snp-report-format+ "https://tinfoil.sh/format/sev-snp-report/v1")
(defparameter +v3-tdx-quote-format+ "https://tinfoil.sh/format/tdx-quote/v1")
(defparameter +v3-key-spki-fp-sha256+ "https://tinfoil.sh/key/spki-fp-sha256/v1")
(defparameter +v3-key-x25519-hpke+ "https://tinfoil.sh/key/x25519-hpke/v1")

(defparameter +coll-format-v2+ "https://tinfoil.sh/predicate/attestation-collaterals/v2")
(defparameter +coll-format-v3+ "https://tinfoil.sh/predicate/attestation-collaterals/v3")
(defparameter +coll-amd-vcek+ "https://tinfoil.sh/collateral/amd-vcek/v1")
(defparameter +coll-amd-crl+ "https://tinfoil.sh/collateral/amd-crl/v1")
(defparameter +coll-intel-pcs+ "https://tinfoil.sh/collateral/intel-pcs/v1")
(defparameter +coll-sigstore-code+ "https://tinfoil.sh/collateral/sigstore-code/v1")
(defparameter +coll-sigstore-platform+ "https://tinfoil.sh/collateral/sigstore-platform/v1")
(defparameter +coll-sigstore-freshness+ "https://tinfoil.sh/collateral/sigstore-freshness/v1")
(defparameter +coll-artifact-freshness+ "https://tinfoil.sh/collateral/artifact-freshness/v1")
(defparameter +coll-config-endorsement+ "https://tinfoil.sh/collateral/config-endorsement/v1")
(defparameter +coll-config+ "https://tinfoil.sh/collateral/config/v1")
(defparameter +coll-igvm-runtime+ "https://tinfoil.sh/collateral/igvm-runtime/v1")

;;; ---- the rejection ---------------------------------------------------------

(define-condition v3-reject (error)
  ((code :initarg :code :reader v3-reject-code)
   (reason :initarg :reason :reader v3-reject-reason))
  (:report (lambda (c s) (format s "~a: ~a" (v3-reject-code c) (v3-reject-reason c))))
  (:documentation "A v3 verification refused the document.  CODE names the layer that
refused it (ENVELOPE_REJECTED, QUOTE_REJECTED, ...), as the conformance taxonomy does."))

(defun %v3-reject (code fmt &rest args)
  (error 'v3-reject :code code :reason (apply #'format nil fmt args)))

(defun %env-reject (fmt &rest args)
  (apply #'%v3-reject "ENVELOPE_REJECTED" fmt args))

;;; ---- strict UTF-8 ----------------------------------------------------------

(defun %strict-utf8 (octets)
  "Decode OCTETS as UTF-8, rejecting overlong forms, surrogates, code points above
U+10FFFF and truncated sequences."
  (let ((out (make-string-output-stream)) (i 0) (n (length octets)))
    (flet ((cont (k)
             (let ((b (if (< k n) (aref octets k) (%env-reject "truncated UTF-8 sequence"))))
               (unless (= (logand b #xC0) #x80) (%env-reject "invalid UTF-8 continuation byte"))
               (logand b #x3F))))
      (loop while (< i n)
            do (let ((b (aref octets i)) (cp 0) (len 0) (min 0))
                 (cond ((< b #x80) (setf cp b len 1 min 0))
                       ((= (logand b #xE0) #xC0) (setf cp (logand b #x1F) len 2 min #x80))
                       ((= (logand b #xF0) #xE0) (setf cp (logand b #x0F) len 3 min #x800))
                       ((= (logand b #xF8) #xF0) (setf cp (logand b #x07) len 4 min #x10000))
                       (t (%env-reject "invalid UTF-8 lead byte #x~2,'0x" b)))
                 (loop for k from 1 below len do (setf cp (logior (ash cp 6) (cont (+ i k)))))
                 (when (or (< cp min) (> cp #x10FFFF) (<= #xD800 cp #xDFFF))
                   (%env-reject "invalid UTF-8 code point"))
                 (write-char (code-char cp) out)
                 (incf i len))))
    (get-output-stream-string out)))

;;; ---- strict JSON -----------------------------------------------------------
;;;
;;; Values: (:obj . ((key . value) ...)) in document order, (:arr . (value ...)),
;;; strings, (:num . "text"), and :true :false :null.

(defun %json-ws-p (c) (member c '(#\Space #\Tab #\Newline #\Return)))

(defun strict-json-parse (text)
  "Parse TEXT as exactly one JSON value under json/v2 strictness: duplicate member
names reject, lone surrogate escapes reject, raw control characters in strings reject,
and anything but whitespace after the value rejects."
  (let ((pos 0) (n (length text)))
    (labels ((peek () (if (< pos n) (char text pos) nil))
             (skip () (loop while (and (< pos n) (%json-ws-p (char text pos))) do (incf pos)))
             (expect (c)
               (unless (eql (peek) c) (%env-reject "JSON: expected ~s at ~d" c pos))
               (incf pos))
             (lit (word value)
               (unless (and (<= (+ pos (length word)) n)
                            (string= word text :start2 pos :end2 (+ pos (length word))))
                 (%env-reject "JSON: bad literal at ~d" pos))
               (incf pos (length word))
               value)
             (hex4 ()
               (unless (<= (+ pos 4) n) (%env-reject "JSON: truncated \\u escape"))
               (let ((v (parse-integer text :start pos :end (+ pos 4) :radix 16 :junk-allowed t)))
                 (unless (and v (every (lambda (c) (digit-char-p c 16)) (subseq text pos (+ pos 4))))
                   (%env-reject "JSON: bad \\u escape"))
                 (incf pos 4)
                 v))
             (str ()
               (expect #\")
               (let ((out (make-string-output-stream)))
                 (loop
                   (let ((c (peek)))
                     (cond ((null c) (%env-reject "JSON: unterminated string"))
                           ((char= c #\") (incf pos) (return (get-output-stream-string out)))
                           ((< (char-code c) #x20) (%env-reject "JSON: control character in string"))
                           ((char= c #\\)
                            (incf pos)
                            (let ((e (peek)))
                              (incf pos)
                              (case e
                                (#\" (write-char #\" out)) (#\\ (write-char #\\ out))
                                (#\/ (write-char #\/ out)) (#\b (write-char (code-char 8) out))
                                (#\f (write-char (code-char 12) out)) (#\n (write-char #\Newline out))
                                (#\r (write-char #\Return out)) (#\t (write-char #\Tab out))
                                (#\u (let ((u (hex4)))
                                       (cond ((<= #xD800 u #xDBFF)
                                              (unless (and (< (+ pos 1) n) (char= (char text pos) #\\)
                                                           (char= (char text (1+ pos)) #\u))
                                                (%env-reject "JSON: lone high surrogate"))
                                              (incf pos 2)
                                              (let ((lo (hex4)))
                                                (unless (<= #xDC00 lo #xDFFF)
                                                  (%env-reject "JSON: bad low surrogate"))
                                                (write-char (code-char (+ #x10000 (ash (- u #xD800) 10)
                                                                          (- lo #xDC00)))
                                                            out)))
                                             ((<= #xDC00 u #xDFFF) (%env-reject "JSON: lone low surrogate"))
                                             (t (write-char (code-char u) out)))))
                                (t (%env-reject "JSON: bad escape")))))
                           (t (write-char c out) (incf pos)))))))
             (num ()
               (let ((start pos))
                 (when (eql (peek) #\-) (incf pos))
                 (cond ((eql (peek) #\0) (incf pos))
                       ((and (peek) (digit-char-p (peek)))
                        (loop while (and (peek) (digit-char-p (peek))) do (incf pos)))
                       (t (%env-reject "JSON: bad number at ~d" start)))
                 (when (eql (peek) #\.)
                   (incf pos)
                   (unless (and (peek) (digit-char-p (peek))) (%env-reject "JSON: bad fraction"))
                   (loop while (and (peek) (digit-char-p (peek))) do (incf pos)))
                 (when (member (peek) '(#\e #\E))
                   (incf pos)
                   (when (member (peek) '(#\+ #\-)) (incf pos))
                   (unless (and (peek) (digit-char-p (peek))) (%env-reject "JSON: bad exponent"))
                   (loop while (and (peek) (digit-char-p (peek))) do (incf pos)))
                 (cons :num (subseq text start pos))))
             (value ()
               (skip)
               (let ((c (peek)))
                 (case c
                   (#\{ (obj)) (#\[ (arr)) (#\" (str))
                   (#\t (lit "true" :true)) (#\f (lit "false" :false)) (#\n (lit "null" :null))
                   (t (if (and c (or (char= c #\-) (digit-char-p c)))
                          (num)
                          (%env-reject "JSON: unexpected ~s at ~d" c pos))))))
             (obj ()
               (expect #\{)
               (skip)
               (let ((members '()))
                 (if (eql (peek) #\})
                     (incf pos)
                     (loop
                       (skip)
                       (let ((k (str)))
                         (when (assoc k members :test #'string=)
                           (%env-reject "JSON: duplicate member ~s" k))
                         (skip) (expect #\:)
                         (push (cons k (value)) members))
                       (skip)
                       (case (peek)
                         (#\, (incf pos))
                         (#\} (incf pos) (return))
                         (t (%env-reject "JSON: expected , or } at ~d" pos)))))
                 (cons :obj (nreverse members))))
             (arr ()
               (expect #\[)
               (skip)
               (let ((items '()))
                 (if (eql (peek) #\])
                     (incf pos)
                     (loop
                       (push (value) items)
                       (skip)
                       (case (peek)
                         (#\, (incf pos))
                         (#\] (incf pos) (return))
                         (t (%env-reject "JSON: expected , or ] at ~d" pos)))))
                 (cons :arr (nreverse items)))))
      (let ((v (value)))
        (skip)
        (when (< pos n) (%env-reject "JSON: trailing data at ~d" pos))
        v))))

(defun strict-json-parse-octets (octets)
  (strict-json-parse (%strict-utf8 octets)))

;;; Struct-style access, the way json/v2 fills a Go struct: an absent member or
;;; null leaves the zero value, a member of the wrong kind rejects, and any member
;;; the struct does not declare rejects.

(defun %obj (v allowed label)
  "Members of object V, rejecting a non-object and any member not in ALLOWED."
  (unless (and (consp v) (eq (car v) :obj)) (%env-reject "~a is not an object" label))
  (dolist (m (cdr v))
    (unless (member (car m) allowed :test #'string=)
      (%env-reject "~a has unknown member ~s" label (car m))))
  (cdr v))

(defun %member (members key) (cdr (assoc key members :test #'string=)))

(defun %str (members key label)
  "The string member KEY, \"\" when absent or null."
  (let ((v (%member members key)))
    (cond ((or (null v) (eq v :null)) "")
          ((stringp v) v)
          (t (%env-reject "~a.~a is not a string" label key)))))

(defun %arr (members key label)
  "(values ITEMS PRESENT-P) for the array member KEY; absent or null is not present."
  (let ((v (%member members key)))
    (cond ((or (null v) (eq v :null)) (values nil nil))
          ((and (consp v) (eq (car v) :arr)) (values (cdr v) t))
          (t (%env-reject "~a.~a is not an array" label key)))))

(defun %present-p (members key)
  (let ((v (%member members key))) (and v (not (eq v :null)))))

;;; ---- canonical hex and base64 ----------------------------------------------

(defun %lower-hex-p (s) (every (lambda (c) (or (digit-char-p c) (find c "abcdef"))) s))

(defun %decode-lower-hex (label s want)
  "Lowercase hex of exactly WANT bytes, or reject (canonical.DecodeLowerHex)."
  (unless (%lower-hex-p s) (%env-reject "~a is not lowercase hex" label))
  (unless (evenp (length s)) (%env-reject "~a is not hex" label))
  (unless (= (length s) (* 2 want)) (%env-reject "~a must be ~d bytes, got ~d" label want (floor (length s) 2)))
  (let ((v (make-array want :element-type '(unsigned-byte 8))))
    (dotimes (i want v)
      (setf (aref v i) (parse-integer s :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun %decode-canonical-base64 (label s)
  "Standard base64, padded, no whitespace, and re-encoding to exactly S
(base64.StdEncoding.Strict plus the round-trip check)."
  (unless (and (zerop (mod (length s) 4))
               (every (lambda (c) (or (find c +b64-alphabet+) (char= c #\=))) s)
               (let ((p (position #\= s)))
                 (or (null p) (and (>= p (- (length s) 2)) (every (lambda (c) (char= c #\=)) (subseq s p))))))
    (%env-reject "decoding ~a: not standard padded base64" label))
  (let ((octets (base64-decode s)))
    (unless (string= (base64-encode octets) s)
      (%env-reject "~a is not canonical base64" label))
    octets))

;;; ---- sections --------------------------------------------------------------

(defstruct (v3-document (:conc-name v3-doc-))
  format nonce-hex report-data-hex cpu-format report
  crypto-material-hash device-evidence-hash
  crypto-material-bytes device-evidence-bytes
  crypto-items device-items collateral collateral-format
  expected-report-data)

(defun %parse-crypto-material (encoded)
  (when (string= encoded "") (%env-reject "crypto_material section is missing"))
  (let* ((bytes (%decode-canonical-base64 "crypto_material" encoded))
         (top (%obj (strict-json-parse-octets bytes) '("format" "items") "crypto_material")))
    (unless (string= (%str top "format" "crypto_material") +v3-crypto-material-format+)
      (%env-reject "unsupported crypto_material section format"))
    (multiple-value-bind (items present) (%arr top "items" "crypto_material")
      (unless present (%env-reject "crypto_material.items is missing"))
      (let ((seen '()) (out '()))
        (dolist (it items)
          (let* ((m (%obj it '("id" "format" "data") "crypto_material item"))
                 (id (%str m "id" "item")) (fmt (%str m "format" "item")) (data (%str m "data" "item")))
            (when (or (string= id "") (string= fmt "")) (%env-reject "crypto_material item is incomplete"))
            (when (member id seen :test #'string=) (%env-reject "duplicate crypto_material item id ~s" id))
            (push id seen)
            (cond ((or (string= fmt +v3-key-spki-fp-sha256+) (string= fmt +v3-key-x25519-hpke+))
                   (%decode-lower-hex (format nil "crypto_material item ~s data" id) data 32))
                  ((string= data "") (%env-reject "crypto_material item ~s data is empty" id))
                  ((not (and (%lower-hex-p data) (evenp (length data))))
                   (%env-reject "crypto_material item ~s data is not lowercase hex" id)))
            (push (list :id id :format fmt :data data) out)))
        (values (nreverse out) bytes)))))

(defun %parse-device-evidence (encoded)
  (when (string= encoded "") (%env-reject "device_evidence section is missing"))
  (let* ((bytes (%decode-canonical-base64 "device_evidence" encoded))
         (top (%obj (strict-json-parse-octets bytes) '("format" "items") "device_evidence")))
    (unless (string= (%str top "format" "device_evidence") +v3-device-evidence-format+)
      (%env-reject "unsupported device_evidence section format"))
    (multiple-value-bind (items present) (%arr top "items" "device_evidence")
      (unless present (%env-reject "device_evidence.items is missing"))
      (let ((seen '()) (out '()))
        (dolist (it items)
          (let* ((m (%obj it '("id" "kind" "vendor" "format" "evidence") "device_evidence item"))
                 (id (%str m "id" "item")))
            ;; Go types these as strings, so a non-string kind/vendor/format rejects.
            (dolist (k '("kind" "vendor" "format")) (%str m k "device_evidence item"))
            (when (string= id "") (%env-reject "device_evidence item has no id"))
            (when (member id seen :test #'string=) (%env-reject "duplicate device_evidence item id ~s" id))
            (push id seen)
            (push (list :id id :kind (%str m "kind" "item") :vendor (%str m "vendor" "item")
                        :format (%str m "format" "item") :evidence (%member m "evidence"))
                  out)))
        (values (nreverse out) bytes)))))

;;; ---- collateral ------------------------------------------------------------

(defun %canonical-semver-p (tag)
  "TAG is vMAJOR.MINOR.PATCH[-PRERELEASE] with no build metadata, as Go's
semver.Canonical would print it."
  (and (> (length tag) 1) (char= (char tag 0) #\v)
       (let* ((body (subseq tag 1))
              (dash (position #\- body))
              (core (subseq body 0 dash))
              (pre (and dash (subseq body (1+ dash))))
              (parts (loop with start = 0 for p = (position #\. core :start start)
                           collect (subseq core start p) while p do (setf start (1+ p)))))
         (flet ((num-p (s) (and (plusp (length s)) (every #'digit-char-p s)
                                (or (= (length s) 1) (char/= (char s 0) #\0)))))
           (and (not (find #\+ body))
                (= (length parts) 3) (every #'num-p parts)
                (or (null pre)
                    (let ((ids (loop with start = 0 for p = (position #\. pre :start start)
                                     collect (subseq pre start p) while p do (setf start (1+ p)))))
                      (every (lambda (id)
                               (and (plusp (length id))
                                    (every (lambda (c) (or (alphanumericp c) (char= c #\-))) id)
                                    (or (notevery #'digit-char-p id) (num-p id))))
                             ids))))))))

(defun %coll-data (entry allowed label)
  (%obj (getf entry :data) allowed label))

(defun %decode-collateral (format entries)
  "Port of collateral.Decode plus decodeCollateral's format rules.  Returns a plist
of the entries this verifier uses."
  (unless (member format (list "" +coll-format-v2+ +coll-format-v3+) :test #'string=)
    (%env-reject "unsupported collateral format ~s" format))
  ;; validate: every entry complete, ids unique, role known, data a JSON object
  (let ((seen '()))
    (dolist (e entries)
      (let ((id (getf e :id)))
        (when (or (string= id "") (string= (getf e :format) ""))
          (%env-reject "collateral entry is incomplete"))
        (when (member id seen :test #'string=) (%env-reject "duplicate collateral entry id ~s" id))
        (push id seen)
        (unless (member (getf e :role) '("endorsement" "reference-values") :test #'string=)
          (%env-reject "collateral entry ~s has unknown role" id))
        (unless (and (consp (getf e :data)) (eq (car (getf e :data)) :obj))
          (%env-reject "collateral entry ~s data is not a valid JSON object" id)))))
  (let ((vcek nil) (crl nil) (code nil) (platform nil) (config nil) (runtime nil) (freshness '()))
    (dolist (e entries)
      (let* ((id (getf e :id)) (fmt (getf e :format)) (role (getf e :role))
             (cpu (member "cpu" (getf e :subjects) :test #'string=)))
        (flet ((is (f) (string= fmt f)))
          (cond
            ((or (string= id "tinfoil-config") (is +coll-config-endorsement+) (is +coll-config+))
             (unless (and (string= id "tinfoil-config") (or (is +coll-config-endorsement+) (is +coll-config+))
                          (string= role "reference-values"))
               (%env-reject "conflicting collateral entry for \"tinfoil-config\""))
             (let* ((d (%coll-data e '("endorsement_ref" "config_base64" "sigstore_bundle") "config collateral"))
                    (ref (%str d "endorsement_ref" "config")) (bundle (%member d "sigstore_bundle")))
               (if (is +coll-config+)
                   (when (or (string/= ref "") bundle)
                     (%env-reject "plain config collateral cannot contain an endorsement"))
                   (progn
                     (unless (and (> (length ref) 7) (string= "sha256:" ref :end2 7))
                       (%env-reject "endorsement_ref must be a SHA-256 reference"))
                     (%decode-lower-hex "endorsement_ref" (subseq ref 7) 32)
                     (unless (and (consp bundle) (eq (car bundle) :obj))
                       (%env-reject "sigstore_bundle must be an object"))))
               (when (zerop (length (%decode-canonical-base64 "config_base64" (%str d "config_base64" "config"))))
                 (%env-reject "config_base64 must not be empty"))
               (setf config d)))
            ((or (string= id "runtime") (is +coll-igvm-runtime+))
             (unless (and (string= id "runtime") (is +coll-igvm-runtime+) (string= role "reference-values"))
               (%env-reject "conflicting collateral entry for \"runtime\""))
             (let ((d (%coll-data e '("repo" "tag" "digest" "manifest_base64" "sigstore_bundle") "runtime collateral")))
               (unless (string= (%str d "repo" "runtime") "tinfoilsh/cvmimage")
                 (%env-reject "runtime repository must be tinfoilsh/cvmimage"))
               (unless (%canonical-semver-p (%str d "tag" "runtime"))
                 (%env-reject "runtime tag must be a canonical semantic version"))
               (%decode-lower-hex "runtime digest" (%str d "digest" "runtime") 32)
               (%decode-canonical-base64 "manifest_base64" (%str d "manifest_base64" "runtime"))
               (let ((b (%member d "sigstore_bundle")))
                 (unless (and (consp b) (eq (car b) :obj)) (%env-reject "sigstore_bundle must be an object")))
               (setf runtime d)))
            ((or (is +coll-artifact-freshness+) (string= id "runtime-freshness"))
             (unless (and (member id '("platform-freshness" "runtime-freshness") :test #'string=)
                          (is +coll-artifact-freshness+) (string= role "reference-values"))
               (%env-reject "conflicting artifact freshness collateral ~s" id))
             (let ((d (%coll-data e '("sigstore_bundle") "freshness collateral")))
               (unless (%present-p d "sigstore_bundle") (%env-reject "freshness entry is missing sigstore_bundle"))
               (push (list id fmt d) freshness)))
            ((and (string= role "endorsement") (is +coll-amd-vcek+))
             (let ((d (%coll-data e '("vcek_der_base64" "cert_chain_pem") "amd-vcek collateral")))
               (let ((der (%decode-canonical-base64 "vcek_der_base64" (%str d "vcek_der_base64" "amd-vcek"))))
                 (when (and cpu (null vcek))
                   (setf vcek (list :der der :chain-pem (%str d "cert_chain_pem" "amd-vcek")))))))
            ((and (string= role "endorsement") (is +coll-amd-crl+))
             (let* ((d (%coll-data e '("crl_der_base64") "amd-crl collateral"))
                    (der (%decode-canonical-base64 "crl_der_base64" (%str d "crl_der_base64" "amd-crl"))))
               (when (and cpu (null crl)) (setf crl der))))
            ((and (string= role "endorsement") (is +coll-intel-pcs+))
             ;; TDX collateral: carried, not decoded here; this verifier is SEV-SNP only.
             nil)
            ((and (string= role "reference-values") (or (is +coll-sigstore-code+) (is +coll-sigstore-platform+)))
             (let ((d (%coll-data e '("repo" "tag" "digest" "sigstore_bundle") "sigstore collateral")))
               (when (string= (%str d "digest" "sigstore") "") (%env-reject "sigstore entry ~s is missing digest" id))
               (unless (%present-p d "sigstore_bundle") (%env-reject "sigstore entry ~s is missing sigstore_bundle" id))
               (let ((ref (list :repo (%str d "repo" "s") :tag (%str d "tag" "s") :digest (%str d "digest" "s")
                                :bundle (%member d "sigstore_bundle"))))
                 (if (is +coll-sigstore-code+)
                     (unless code (setf code ref))
                     (unless platform (setf platform ref))))))
            ((and (string= role "reference-values") (is +coll-sigstore-freshness+))
             (let ((d (%coll-data e '("sigstore_bundle") "freshness collateral")))
               (unless (%present-p d "sigstore_bundle") (%env-reject "freshness entry is missing sigstore_bundle"))
               (push (list id fmt d) freshness)))))))
    (if (string= format +coll-format-v3+)
        (when code (%env-reject "legacy code collateral is incompatible with collateral v3"))
        (when (or config runtime) (%env-reject "config and runtime collateral require collateral v3")))
    (dolist (f freshness)
      (unless (eq (string= format +coll-format-v3+) (string= (second f) +coll-artifact-freshness+))
        (%env-reject "freshness collateral is incompatible with ~s" format)))
    (list :vcek vcek :crl crl :sigstore-code code :sigstore-platform platform
          :config config :runtime runtime :freshness freshness)))

(defun %parse-collateral-entries (members)
  (multiple-value-bind (items present) (%arr members "collateral" "document")
    (declare (ignore present))
    (mapcar (lambda (it)
              (let ((m (%obj it '("id" "role" "format" "subjects" "data") "collateral entry")))
                (list :id (%str m "id" "entry") :role (%str m "role" "entry") :format (%str m "format" "entry")
                      :subjects (multiple-value-bind (s p) (%arr m "subjects" "entry")
                                  (declare (ignore p))
                                  (mapcar (lambda (x) (if (stringp x) x (%env-reject "subjects must be strings")))
                                          s))
                      :data (%member m "data"))))
            items)))

;;; ---- the envelope ----------------------------------------------------------

(defun v3-report-data (nonce crypto-hash device-hash)
  "REPORT_DATA per https://tinfoil.sh/report-data/v1: 64 bytes, the first 32 the
SHA-256 of the algorithm URI and the three 32-byte inputs, the rest zero."
  (let ((rd (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
        (h (sha256 (concatenate '(vector (unsigned-byte 8))
                                (%string-octets +v3-report-data-algorithm+)
                                nonce crypto-hash device-hash))))
    (replace rd h)
    rd))

(defun v3-decode-document (document-octets)
  "Apply the structural rules alone (Tinfoil's decode): strict parse, every section
and collateral entry checked, but no nonce binding.  The quote layer authenticates
from this; the challenge is bound by V3-CHECK-ENVELOPE."
  (%v3-envelope document-octets nil))

(defun v3-check-envelope (document-octets expected-nonce)
  "Strictly parse a v3 document and check its bindings against EXPECTED-NONCE (the
32 bytes we sent): nonce equality, both endorsed-section hashes, and the
REPORT_DATA ladder.  Returns a V3-DOCUMENT whose EXPECTED-REPORT-DATA is what the
CPU quote must bind.  Signals V3-REJECT (ENVELOPE_REJECTED) on any failure.  Like
Tinfoil's Parse, this authenticates nothing."
  (unless (and expected-nonce (= (length expected-nonce) +v3-nonce-size+))
    (%env-reject "expected nonce must be ~d bytes" +v3-nonce-size+))
  (%v3-envelope document-octets expected-nonce))

(defun %v3-envelope (document-octets expected-nonce)
  (let* ((top (%obj (strict-json-parse-octets document-octets)
                    '("format" "challenge" "cpu_evidence" "crypto_material" "device_evidence"
                      "collateral_format" "collateral")
                    "document"))
         (challenge (if (%present-p top "challenge")
                        (%obj (%member top "challenge") '("nonce" "report_data" "report_data_algorithm") "challenge")
                        '()))
         (cpu (if (%present-p top "cpu_evidence")
                  (%obj (%member top "cpu_evidence") '("format" "report_base64" "endorsed") "cpu_evidence")
                  '()))
         (endorsed (if (%present-p cpu "endorsed")
                       (%obj (%member cpu "endorsed") '("crypto_material_hash" "device_evidence_hash") "endorsed")
                       '())))
    (unless (string= (%str top "format" "document") +v3-format+)
      (%env-reject "unsupported document format"))
    ;; challenge
    (unless (string= (%str challenge "report_data_algorithm" "challenge") +v3-report-data-algorithm+)
      (%env-reject "unsupported challenge.report_data_algorithm"))
    (%decode-lower-hex "challenge.nonce" (%str challenge "nonce" "challenge") +v3-nonce-size+)
    (%decode-lower-hex "challenge.report_data" (%str challenge "report_data" "challenge") 64)
    ;; cpu evidence
    (%decode-lower-hex "cpu_evidence.endorsed.crypto_material_hash" (%str endorsed "crypto_material_hash" "e") 32)
    (%decode-lower-hex "cpu_evidence.endorsed.device_evidence_hash" (%str endorsed "device_evidence_hash" "e") 32)
    (when (or (string= (%str cpu "format" "cpu_evidence") "") (string= (%str cpu "report_base64" "cpu_evidence") ""))
      (%env-reject "cpu_evidence is incomplete"))
    (let ((report (%decode-canonical-base64 "cpu_evidence.report_base64" (%str cpu "report_base64" "cpu_evidence"))))
      (multiple-value-bind (crypto-items crypto-bytes) (%parse-crypto-material (%str top "crypto_material" "document"))
        (multiple-value-bind (device-items device-bytes) (%parse-device-evidence (%str top "device_evidence" "document"))
          (let* ((coll-format (%str top "collateral_format" "document"))
                 (collateral (%decode-collateral coll-format (%parse-collateral-entries top)))
                 (nonce-hex (%str challenge "nonce" "challenge"))
                 (crypto-hash (sha256 crypto-bytes))
                 (device-hash (sha256 device-bytes)))
            ;; bind (Tinfoil's bind), only when the caller supplied its nonce
            (when expected-nonce
              (unless (string= nonce-hex (hex-string expected-nonce))
                (%env-reject "challenge nonce does not match the expected nonce"))
              (unless (string= (hex-string crypto-hash) (%str endorsed "crypto_material_hash" "e"))
                (%env-reject "crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash"))
              (unless (string= (hex-string device-hash) (%str endorsed "device_evidence_hash" "e"))
                (%env-reject "device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash")))
            (let ((rd (and expected-nonce (v3-report-data expected-nonce crypto-hash device-hash))))
              (when (and rd (string/= (hex-string rd) (%str challenge "report_data" "challenge")))
                (%env-reject "challenge report_data does not match the recomputed value"))
              (make-v3-document
               :format +v3-format+ :nonce-hex nonce-hex
               :report-data-hex (and rd (hex-string rd)) :cpu-format (%str cpu "format" "cpu_evidence") :report report
               :crypto-material-hash crypto-hash :device-evidence-hash device-hash
               :crypto-material-bytes crypto-bytes :device-evidence-bytes device-bytes
               :crypto-items crypto-items :device-items device-items
               :collateral collateral :collateral-format coll-format
               :expected-report-data rd))))))))
