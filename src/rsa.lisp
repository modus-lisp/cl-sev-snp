;;;; rsa.lisp -- RSASSA-PSS signature verification (RFC 8017 section 8.1.2 / 9.1.2). Pure CL.
;;;;
;;;; The hash, MGF1 hash and salt length are parameters: SEV-SNP's ARK/ASK use SHA-384 with
;;;; salt 48, but nothing here hard-codes that.

(in-package :cl-sev-snp)

(defun %octets (&rest parts)
  "Concatenate octet vectors / lists of octets."
  (let* ((vs (mapcar (lambda (p) (coerce p '(simple-array (unsigned-byte 8) (*)))) parts))
         (out (make-array (reduce #'+ vs :key #'length) :element-type '(unsigned-byte 8)))
         (k 0))
    (dolist (v vs out)
      (replace out v :start1 k)
      (incf k (length v)))))

(defun %int-be (v &optional (start 0) (end (length v)))
  (%der-uint v start end))

(defun %int-to-octets (n len)
  (let ((out (make-array len :element-type '(unsigned-byte 8))))
    (loop for i from (1- len) downto 0
          do (setf (aref out i) (ldb (byte 8 0) n) n (ash n -8)))
    out))

(defun %modexp (base e n)
  (let ((r 1) (b (mod base n)))
    (loop while (> e 0)
          do (when (oddp e) (setf r (mod (* r b) n)))
             (setf b (mod (* b b) n) e (ash e -1)))
    r))

(defun %mgf1 (hash seed len)
  (let ((out '()) (got 0) (counter 0))
    (loop while (< got len)
          do (let ((h (funcall hash (%octets seed (%int-to-octets counter 4)))))
               (push h out) (incf got (length h)) (incf counter)))
    (subseq (apply #'%octets (nreverse out)) 0 len)))

(defun %xor-octets (a b)
  (let ((out (make-array (length a) :element-type '(unsigned-byte 8))))
    (dotimes (i (length a) out) (setf (aref out i) (logxor (aref a i) (aref b i))))))

(defun %const-time-equal (a b)
  (and (= (length a) (length b))
       (zerop (reduce #'logior (map 'list (lambda (x y) (logxor x y)) a b) :initial-value 0))))

(defun verify-rsa-pss (n e message signature
                       &key (hash #'sha384) (hash-len 48) (salt-len 48))
  "T iff SIGNATURE is a valid RSASSA-PSS signature of MESSAGE under the RSA public key (N, E).
HASH is the hash function (octets -> octets, of length HASH-LEN), used for the message digest
and for MGF1."
  (let* ((k (ceiling (integer-length n) 8))
         (s (%int-be signature)))
    (when (or (/= (length signature) k) (>= s n)) (return-from verify-rsa-pss nil))
    (let* ((em-bits (1- (integer-length n)))
           (em-len (ceiling em-bits 8))
           (em (%int-to-octets (%modexp s e n) em-len))
           (m-hash (funcall hash message)))
      (when (or (< em-len (+ hash-len salt-len 2))
                (/= (aref em (1- em-len)) #xbc))
        (return-from verify-rsa-pss nil))
      (let* ((db-len (- em-len hash-len 1))
             (masked (subseq em 0 db-len))
             (h (subseq em db-len (+ db-len hash-len)))
             (db (%xor-octets masked (%mgf1 hash h db-len))))
        ;; The unused leading bits of DB must be zero.
        (when (/= (logand (aref masked 0) (lognot (1- (ash 1 (- 8 (- (* 8 em-len) em-bits))))))
                  0)
          (return-from verify-rsa-pss nil))
        (setf (aref db 0) (logand (aref db 0) #x7f))
        (let ((ps-end (- db-len salt-len 1)))
          (dotimes (i ps-end)
            (unless (zerop (aref db i)) (return-from verify-rsa-pss nil)))
          (unless (= (aref db ps-end) 1) (return-from verify-rsa-pss nil))
          (let* ((salt (subseq db (1+ ps-end)))
                 (h2 (funcall hash (%octets (make-array 8 :element-type '(unsigned-byte 8)
                                                          :initial-element 0)
                                            m-hash salt))))
            (%const-time-equal h h2)))))))

(defun rsa-public-key-from-spki-key (key-octets)
  "(values n e) from the RSAPublicKey DER inside an RSA SubjectPublicKeyInfo."
  (let* ((v (coerce key-octets '(simple-array (unsigned-byte 8) (*))))
         (seq (der-element v 0))
         (ints (der-children v seq)))
    (values (%int-be v (tlv-start (first ints)) (tlv-end (first ints)))
            (%int-be v (tlv-start (second ints)) (tlv-end (second ints))))))
