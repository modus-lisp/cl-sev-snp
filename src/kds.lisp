;;;; kds.lisp -- network layer for cl-sev-snp (seal/http, pure CL). Kept out of the pure core.
;;;;
;;;;   fetch-amd-chain   -> (values ASK-DER ARK-DER) from AMD KDS (PEM, ASK first then ARK)
;;;;   fetch-tinfoil-bundle -> parsed Tinfoil attestation document (json-simple)
;;;;   verify-tinfoil-live  -> fetch both, then run verify-tinfoil-bundle.
;;;;
;;;; The ARK is trusted only as far as its fetch path. A caller that needs a pinned root should
;;;; compare the ARK SPKI SHA-256 against a value it holds out of band (see
;;;; +pinned-ark-spki-sha256+ below, unset by default).

(in-package :cl-sev-snp)

(defparameter *amd-kds-chain-url* "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain")
(defparameter *tinfoil-attestation-url* "https://atc.tinfoil.sh/attestation")

(defvar *pinned-ark-spki-sha256* "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831"
  "Hex SHA-256 of the ARK SubjectPublicKeyInfo. When non-NIL, fetch-amd-chain refuses a chain whose
ARK does not match. The default is the Genoa ARK (CN=ARK-Genoa) as served by
https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain; it is the AMD root of trust for the Tinfoil
enclave, so pinning it turns the KDS fetch from a trust-the-network step into a check.")

(defun %http-get-octets (url)
  "GET URL and return the body as octets; a non-2xx status is an error (as
dexador signalled)."
  (let* ((r (seal.http:http-get url))
         (status (seal.http:response-status r)))
    (unless (<= 200 status 299) (%fail "GET ~a: HTTP ~d" url status))
    (coerce (seal.http:response-body r) '(simple-array (unsigned-byte 8) (*)))))

(defun fetch-amd-chain (&key (url *amd-kds-chain-url*))
  "Fetch the Genoa ASK+ARK chain. Returns (values ASK-DER ARK-DER)."
  (let* ((pem (map 'string #'code-char (%http-get-octets url)))
         (ders (pem-to-der-list pem)))
    (unless (= (length ders) 2) (%fail "AMD KDS chain: expected 2 certs, got ~d" (length ders)))
    (let ((ask (first ders)) (ark (second ders)))
      (when *pinned-ark-spki-sha256*
        (let ((got (hex-string (sha256 (cert-spki-der (parse-certificate ark))))))
          (unless (string-equal got *pinned-ark-spki-sha256*)
            (%fail "ARK SPKI does not match the pinned hash (got ~a)" got))))
      (values ask ark))))

(defun fetch-tinfoil-bundle (&key (url *tinfoil-attestation-url*))
  "Fetch the Tinfoil attestation document and parse it. Returns a json-simple hash table."
  (json-simple:parse (map 'string #'code-char (%http-get-octets url))))

(defun verify-tinfoil-live (&key (tinfoil-url *tinfoil-attestation-url*) (kds-url *amd-kds-chain-url*))
  "Fetch the Tinfoil bundle and the AMD chain, then verify. Returns (values OK-P CHECKS)."
  (let ((bundle (fetch-tinfoil-bundle :url tinfoil-url)))
    (multiple-value-bind (ask ark) (fetch-amd-chain :url kds-url)
      (verify-tinfoil-bundle bundle ark ask))))
