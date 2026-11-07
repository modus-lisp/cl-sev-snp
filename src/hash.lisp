;;;; hash.lisp -- SHA-256, SHA-384, SHA-512, from natrium.
;;;;
;;;; This file used to carry its own FIPS 180-4 implementation; natrium's is the org's
;;;; canonical one, 3x (SHA-256) and 25x (SHA-512) faster on SBCL, and like this one
;;;; pure CL with no dependencies.  The test suite still checks known digests.

(in-package :cl-sev-snp)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(declaim (inline %u8v))
(defun %u8v (x) (coerce x 'octets))

(defun sha256 (message)
  "SHA-256 digest of the octet vector MESSAGE, as an octet vector."
  (natrium:sha256 (%u8v message)))

(defun sha384 (message)
  "SHA-384 digest of the octet vector MESSAGE, as an octet vector."
  (natrium:sha384 (%u8v message)))

(defun sha512 (message)
  "SHA-512 digest of the octet vector MESSAGE, as an octet vector."
  (natrium:sha512 (%u8v message)))
