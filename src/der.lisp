;;;; der.lisp -- minimal DER reader and X.509 certificate parser. Pure CL.
;;;;
;;;; Only what SEV-SNP and sigstore need: TLV walking, OIDs, times, the
;;;; SubjectPublicKeyInfo, the TBS bytes that are signed, and the extensions.

(in-package :cl-sev-snp)

(defstruct (tlv (:constructor make-tlv (tag header start end)))
  tag
  header   ; offset of the tag byte (the full encoding is [header, end))
  start    ; offset of the content
  end)     ; offset one past the content

(defun %der-uint (v s e)
  (let ((n 0)) (loop for i from s below e do (setf n (+ (* n 256) (aref v i)))) n))

(defun der-element (v pos)
  "The TLV at POS in octet vector V."
  (when (>= (+ pos 1) (length v)) (%fail "DER truncated at ~d" pos))
  (let* ((tag (aref v pos)) (b (aref v (+ pos 1))))
    (multiple-value-bind (cs len)
        (if (< b 128)
            (values (+ pos 2) b)
            (let ((nb (- b 128)))
              (values (+ pos 2 nb) (%der-uint v (+ pos 2) (+ pos 2 nb)))))
      (when (> (+ cs len) (length v)) (%fail "DER element overruns buffer at ~d" pos))
      (make-tlv tag pos cs (+ cs len)))))

(defun der-children (v tlv)
  "Direct child TLVs of TLV in buffer V."
  (let ((out '()) (pos (tlv-start tlv)))
    (loop while (< pos (tlv-end tlv))
          do (let ((x (der-element v pos)))
               (push x out)
               (setf pos (tlv-end x))))
    (nreverse out)))

(defun der-content (v tlv) (subseq v (tlv-start tlv) (tlv-end tlv)))
(defun der-whole (v tlv) (subseq v (tlv-header tlv) (tlv-end tlv)))

(defun der-oid-string (v tlv)
  "Dotted OID string for an OBJECT IDENTIFIER TLV."
  (let* ((bytes (der-content v tlv))
         (first (aref bytes 0))
         (a0 (min 2 (floor first 40)))
         (arcs '()) (n 0))
    (loop for i from 1 below (length bytes)
          do (setf n (logior (ash n 7) (ldb (byte 7 0) (aref bytes i))))
             (unless (logbitp 7 (aref bytes i)) (push n arcs) (setf n 0)))
    (format nil "~d.~d~{.~d~}" a0 (- first (* 40 a0)) (nreverse arcs))))

(defun %days-from-civil (y m d)
  (let* ((y (if (<= m 2) (- y 1) y))
         (era (floor y 400))
         (yoe (- y (* era 400)))
         (doy (+ (floor (+ (* 153 (if (> m 2) (- m 3) (+ m 9))) 2) 5) (- d 1)))
         (doe (+ (* yoe 365) (floor yoe 4) (- (floor yoe 100)) doy)))
    (+ (* era 146097) doe -719468)))

(defun der-time-unix (v tlv)
  "Unix seconds for a UTCTime (#x17) or GeneralizedTime (#x18)."
  (let* ((txt (map 'string #'code-char (der-content v tlv)))
         (gen (= (tlv-tag tlv) #x18))
         (num (lambda (a b) (parse-integer txt :start a :end b)))
         (year (if gen (funcall num 0 4)
                   (let ((yy (funcall num 0 2))) (if (< yy 50) (+ 2000 yy) (+ 1900 yy)))))
         (o (if gen 4 2)))
    (+ (* 86400 (%days-from-civil year (funcall num o (+ o 2)) (funcall num (+ o 2) (+ o 4))))
       (* 3600 (funcall num (+ o 4) (+ o 6)))
       (* 60 (funcall num (+ o 6) (+ o 8)))
       (funcall num (+ o 8) (+ o 10)))))

;;; ---- X.509 ----

(defstruct cert
  der           ; whole certificate (octets)
  tbs           ; the to-be-signed TLV encoding (exactly the bytes covered by the signature)
  sig-alg-oid   ; signatureAlgorithm OID (dotted)
  signature     ; signature value (BIT STRING payload without the unused-bits octet)
  spki-oid      ; SubjectPublicKeyInfo algorithm OID
  spki-param    ; algorithm parameter OID (EC named curve) or NIL
  spki-key      ; subjectPublicKey payload (BIT STRING payload without unused-bits octet)
  spki-der      ; full SubjectPublicKeyInfo encoding
  subject-cn issuer-cn
  not-before not-after
  extensions)   ; alist: dotted OID -> extension value octets (OCTET STRING content)

(defun %rdn-cn (v name-tlv)
  "The commonName (2.5.4.3) value inside a Name, or NIL."
  (dolist (rdn (der-children v name-tlv))
    (dolist (atv (der-children v rdn))
      (let ((kids (der-children v atv)))
        (when (and (= (length kids) 2)
                   (string= (der-oid-string v (first kids)) "2.5.4.3"))
          (return-from %rdn-cn
            (map 'string #'code-char (der-content v (second kids))))))))
  nil)

(defun parse-certificate (der)
  "Parse a DER X.509 certificate into a CERT. Signals ATTESTATION-ERROR on malformed input."
  (let* ((v (coerce der '(simple-array (unsigned-byte 8) (*))))
         (top (der-element v 0))
         (kids (der-children v top)))
    (unless (= (length kids) 3) (%fail "certificate has ~d top-level fields" (length kids)))
    (destructuring-bind (tbs-t sig-alg-t sig-t) kids
      (let* ((tbs (der-children v tbs-t))
             (base (if (= (tlv-tag (first tbs)) #xa0) 1 0)) ; explicit [0] version present?
             (issuer (nth (+ base 2) tbs))
             (validity (der-children v (nth (+ base 3) tbs)))
             (subject (nth (+ base 4) tbs))
             (spki (der-children v (nth (+ base 5) tbs)))
             (spki-alg (der-children v (first spki)))
             (param (second spki-alg))
             (exts-t (find #xa3 (nthcdr (+ base 6) tbs) :key #'tlv-tag))
             (exts (when exts-t
                     (loop for seq in (der-children v (first (der-children v exts-t)))
                           for parts = (der-children v seq)
                           collect (cons (der-oid-string v (first parts))
                                         (der-content v (car (last parts))))))))
        (make-cert
         :der v
         :tbs (der-whole v tbs-t)
         :sig-alg-oid (der-oid-string v (first (der-children v sig-alg-t)))
         :signature (subseq (der-content v sig-t) 1)
         :spki-oid (der-oid-string v (first spki-alg))
         :spki-param (and param (= (tlv-tag param) #x06) (der-oid-string v param))
         :spki-key (subseq (der-content v (second spki)) 1)
         :spki-der (der-whole v (nth (+ base 5) tbs))
         :subject-cn (%rdn-cn v subject)
         :issuer-cn (%rdn-cn v issuer)
         :not-before (der-time-unix v (first validity))
         :not-after (der-time-unix v (second validity))
         :extensions exts)))))

(defun cert-extension (cert oid)
  (cdr (assoc oid (cert-extensions cert) :test #'string=)))
