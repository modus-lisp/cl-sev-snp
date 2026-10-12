;;;; hash.lisp -- SHA-256, SHA-384, SHA-512 in pure CL (FIPS 180-4).
;;;;
;;;; The round constants and initial values are not typed in: they are the fractional
;;;; parts of prime roots, computed exactly with integer roots at load time (see
;;;; %PRIME-ROOT-FRACTION). The test suite checks the output against known digests.

(in-package :cl-sev-snp)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun %primes (n)
  (let ((out '()) (k 2))
    (loop while (< (length out) n)
          do (when (loop for p in out never (zerop (mod k p))) (setf out (append out (list k))))
             (incf k))
    out))

(defun %iroot (n k)
  "Floor of the K-th root of the non-negative integer N (exact integer Newton)."
  (if (< n 2) n
      (let ((x (ash 1 (ceiling (integer-length n) k))))
        (loop
          (let ((y (floor (+ (* (1- k) x) (floor n (expt x (1- k)))) k)))
            (when (>= y x) (return x))
            (setf x y))))))

(defun %prime-root-fraction (p root bits)
  "First BITS bits of the fractional part of P^(1/ROOT)."
  (ldb (byte bits 0) (%iroot (ash p (* root bits)) root)))

(defparameter +sha256-k+
  (coerce (mapcar (lambda (p) (%prime-root-fraction p 3 32)) (%primes 64))
          'simple-vector))
(defparameter +sha256-h0+
  (coerce (mapcar (lambda (p) (%prime-root-fraction p 2 32)) (%primes 8))
          'simple-vector))
(defparameter +sha512-k+
  (coerce (mapcar (lambda (p) (%prime-root-fraction p 3 64)) (%primes 80))
          'simple-vector))
(defparameter +sha512-h0+
  (coerce (mapcar (lambda (p) (%prime-root-fraction p 2 64)) (%primes 8))
          'simple-vector))
(defparameter +sha384-h0+
  ;; SHA-384 uses the ninth..sixteenth primes for its initial values.
  (coerce (mapcar (lambda (p) (%prime-root-fraction p 2 64)) (last (%primes 16) 8))
          'simple-vector))

(declaim (inline %rotr32 %rotr64))
(defun %rotr32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n))
  (logand #xffffffff (logior (ash x (- n)) (ash x (- 32 n)))))
(defun %rotr64 (x n)
  (declare (type (unsigned-byte 64) x) (type (integer 0 63) n))
  (logand #xffffffffffffffff (logior (ash x (- n)) (ash x (- 64 n)))))

(defun %pad (message block-bytes length-bytes)
  "Merkle-Damgard padding: 0x80, zeros, then the bit length big-endian in LENGTH-BYTES."
  (let* ((len (length message))
         (bit-len (* 8 len))
         (total (* block-bytes (ceiling (+ len 1 length-bytes) block-bytes)))
         (out (make-array total :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out message)
    (setf (aref out len) #x80)
    (loop for i from 0 below length-bytes
          do (setf (aref out (- total 1 i)) (ldb (byte 8 (* 8 i)) bit-len)))
    out))

(defun %be-word (v i nbytes)
  (let ((w 0))
    (dotimes (j nbytes w)
      (setf w (logior (ash w 8) (aref v (+ i j)))))))

(defun %word-bytes (words nbytes)
  "Concatenate WORDS (each NBYTES wide) big-endian into an octet vector."
  (let ((out (make-array (* nbytes (length words)) :element-type '(unsigned-byte 8))))
    (loop for w across words for k from 0
          do (dotimes (j nbytes)
               (setf (aref out (+ (* k nbytes) j))
                     (ldb (byte 8 (* 8 (- nbytes 1 j))) w))))
    out))

(defun %sha256-core (message)
  (let* ((msg (%pad message 64 8))
         (h (copy-seq +sha256-h0+))
         (w (make-array 64 :element-type '(unsigned-byte 32)))
         (k +sha256-k+))
    (loop for off from 0 below (length msg) by 64
          do (dotimes (tt 16) (setf (aref w tt) (%be-word msg (+ off (* 4 tt)) 4)))
             (loop for tt from 16 below 64
                   do (let* ((w15 (aref w (- tt 15)))
                             (w2 (aref w (- tt 2)))
                             (s0 (logxor (%rotr32 w15 7) (%rotr32 w15 18) (ash w15 -3)))
                             (s1 (logxor (%rotr32 w2 17) (%rotr32 w2 19) (ash w2 -10))))
                        (setf (aref w tt)
                              (logand #xffffffff (+ s1 (aref w (- tt 7)) s0 (aref w (- tt 16)))))))
             (let ((a (svref h 0)) (b (svref h 1)) (c (svref h 2)) (d (svref h 3))
                   (e (svref h 4)) (f (svref h 5)) (g (svref h 6)) (hh (svref h 7)))
               (dotimes (tt 64)
                 (let* ((s1 (logxor (%rotr32 e 6) (%rotr32 e 11) (%rotr32 e 25)))
                        (ch (logxor (logand e f) (logand (logxor e #xffffffff) g)))
                        (t1 (logand #xffffffff (+ hh s1 ch (svref k tt) (aref w tt))))
                        (s0 (logxor (%rotr32 a 2) (%rotr32 a 13) (%rotr32 a 22)))
                        (maj (logxor (logand a b) (logand a c) (logand b c)))
                        (t2 (logand #xffffffff (+ s0 maj))))
                   (setf hh g g f f e
                         e (logand #xffffffff (+ d t1))
                         d c c b b a
                         a (logand #xffffffff (+ t1 t2)))))
               (loop for v in (list a b c d e f g hh) for i from 0
                     do (setf (svref h i) (logand #xffffffff (+ (svref h i) v))))))
    h))

(defun sha256 (message)
  "SHA-256 digest of the octet vector MESSAGE, as an octet vector."
  (%word-bytes (%sha256-core message) 4))

(defun %sha512-core (message h-init)
  (let* ((msg (%pad message 128 16))
         (h (copy-seq h-init))
         (w (make-array 80 :element-type '(unsigned-byte 64)))
         (k +sha512-k+))
    (loop for off from 0 below (length msg) by 128
          do (dotimes (tt 16) (setf (aref w tt) (%be-word msg (+ off (* 8 tt)) 8)))
             (loop for tt from 16 below 80
                   do (let* ((w15 (aref w (- tt 15)))
                             (w2 (aref w (- tt 2)))
                             (s0 (logxor (%rotr64 w15 1) (%rotr64 w15 8) (ash w15 -7)))
                             (s1 (logxor (%rotr64 w2 19) (%rotr64 w2 61) (ash w2 -6))))
                        (setf (aref w tt)
                              (ldb (byte 64 0) (+ s1 (aref w (- tt 7)) s0 (aref w (- tt 16)))))))
             (let ((a (svref h 0)) (b (svref h 1)) (c (svref h 2)) (d (svref h 3))
                   (e (svref h 4)) (f (svref h 5)) (g (svref h 6)) (hh (svref h 7)))
               (dotimes (tt 80)
                 (let* ((s1 (logxor (%rotr64 e 14) (%rotr64 e 18) (%rotr64 e 41)))
                        (ch (logxor (logand e f) (logand (logxor e #xffffffffffffffff) g)))
                        (t1 (ldb (byte 64 0) (+ hh s1 ch (svref k tt) (aref w tt))))
                        (s0 (logxor (%rotr64 a 28) (%rotr64 a 34) (%rotr64 a 39)))
                        (maj (logxor (logand a b) (logand a c) (logand b c)))
                        (t2 (ldb (byte 64 0) (+ s0 maj))))
                   (setf hh g g f f e
                         e (ldb (byte 64 0) (+ d t1))
                         d c c b b a
                         a (ldb (byte 64 0) (+ t1 t2)))))
               (loop for v in (list a b c d e f g hh) for i from 0
                     do (setf (svref h i) (ldb (byte 64 0) (+ (svref h i) v))))))
    h))

(defun sha512 (message)
  "SHA-512 digest of the octet vector MESSAGE."
  (%word-bytes (%sha512-core message +sha512-h0+) 8))

(defun sha384 (message)
  "SHA-384 digest (SHA-512 with different IV, truncated to 48 bytes)."
  (subseq (%word-bytes (%sha512-core message +sha384-h0+) 8) 0 48))
