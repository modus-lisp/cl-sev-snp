;;;; ec.lisp -- ECDSA signature verification over NIST prime curves (FIPS 186-4 6.4). Pure CL.
;;;;
;;;; Affine arithmetic with modular inverses; slow but short and easy to audit. Covers
;;;; P-256 (sigstore/Fulcio leaves) and P-384 (SEV-SNP report and VCEK).

(in-package :cl-sev-snp)

(defstruct (ec-curve (:conc-name curve-)) name prime n a b gx gy)

(defparameter +p256+
  (make-ec-curve :name "P-256"
              :prime #xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
              :n #xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
              :a #xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
              :b #x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
              :gx #x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
              :gy #x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))

(defparameter +p384-curve+
  (make-ec-curve :name "P-384"
              :prime (- (expt 2 384) (expt 2 128) (expt 2 96) (- (expt 2 32)) 1)
              :n #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
              :a (- (expt 2 384) (expt 2 128) (expt 2 96) (- (expt 2 32)) 4)
              :b #xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
              :gx #xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
              :gy #x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F))

(defun %mod-inv (a m)
  (let ((r0 m) (r1 (mod a m)) (t0 0) (t1 1))
    (loop until (zerop r1)
          do (let ((q (floor r0 r1)))
               (psetf r0 r1 r1 (- r0 (* q r1)))
               (psetf t0 t1 t1 (- t0 (* q t1)))))
    (mod t0 m)))

(defun %ec-add (c p1 p2)
  "Affine point addition on curve C. Points are (x y), NIL is infinity."
  (let ((p (curve-prime c)))
    (cond ((null p1) p2)
          ((null p2) p1)
          (t (destructuring-bind (x1 y1) p1
               (destructuring-bind (x2 y2) p2
                 (cond ((and (= x1 x2) (= (mod (+ y1 y2) p) 0)) nil)
                       (t (let* ((l (if (= x1 x2)
                                        (mod (* (+ (* 3 x1 x1) (curve-a c))
                                                (%mod-inv (* 2 y1) p)) p)
                                        (mod (* (- y2 y1) (%mod-inv (- x2 x1) p)) p)))
                                 (x3 (mod (- (* l l) x1 x2) p))
                                 (y3 (mod (- (* l (- x1 x3)) y1) p)))
                            (list x3 y3))))))))))

(defun %ec-mul (c k pt)
  (let ((r nil) (q pt))
    (loop while (> k 0)
          do (when (oddp k) (setf r (%ec-add c r q)))
             (setf q (%ec-add c q q) k (ash k -1)))
    r))

(defun on-curve-p (c x y)
  (let ((p (curve-prime c)))
    (and (< -1 x p) (< -1 y p)
         (= (mod (* y y) p)
            (mod (+ (* x x x) (* (curve-a c) x) (curve-b c)) p)))))

(defun ec-point-from-spki-key (c key-octets)
  "Decode an uncompressed SEC1 point (0x04 || X || Y) from a SubjectPublicKeyInfo key."
  (let* ((len (floor (1- (length key-octets)) 2)))
    (unless (and (= (length key-octets) (1+ (* 2 len))) (= (aref key-octets 0) 4))
      (%fail "not an uncompressed EC point"))
    (let ((x (%int-be key-octets 1 (1+ len)))
          (y (%int-be key-octets (1+ len) (1+ (* 2 len)))))
      (unless (on-curve-p c x y) (%fail "EC point is not on ~a" (curve-name c)))
      (list x y))))

(defun verify-ecdsa (c public-point digest r s)
  "T iff (R, S) is a valid ECDSA signature of DIGEST (octets) under PUBLIC-POINT on curve C.
The digest is truncated to the bit length of the group order, per FIPS 186-4 6.4."
  (let* ((n (curve-n c))
         (nbits (integer-length n))
         (e (%int-be digest))
         (e (if (> (* 8 (length digest)) nbits) (ash e (- nbits (* 8 (length digest)))) e)))
    (when (not (and (< 0 r n) (< 0 s n))) (return-from verify-ecdsa nil))
    (let* ((w (%mod-inv s n))
           (u1 (mod (* e w) n))
           (u2 (mod (* r w) n))
           (pt (%ec-add c (%ec-mul c u1 (list (curve-gx c) (curve-gy c)))
                        (%ec-mul c u2 public-point))))
      (and pt (= (mod (first pt) n) r)))))

(defun ecdsa-der-signature-rs (der-sig)
  "(values r s) from a DER-encoded ECDSA-Sig-Value SEQUENCE { r INTEGER, s INTEGER }."
  (let* ((v (coerce der-sig '(simple-array (unsigned-byte 8) (*))))
         (ints (der-children v (der-element v 0))))
    (values (%int-be v (tlv-start (first ints)) (tlv-end (first ints)))
            (%int-be v (tlv-start (second ints)) (tlv-end (second ints))))))
