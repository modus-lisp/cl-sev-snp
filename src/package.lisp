;;;; package.lisp
(defpackage :cl-sev-snp
  (:use :common-lisp)
  (:export
   ;; hashes
   #:sha256 #:sha384 #:sha512
   ;; encoding
   #:base64-decode #:base64-encode #:hex-string #:pem-to-der-list
   ;; x509 / DER
   #:parse-certificate #:cert-subject-cn #:cert-issuer-cn #:cert-spki-der
   #:cert-spki-key #:cert-tbs #:cert-signature #:cert-sig-alg-oid #:cert-extension
   #:cert-not-before #:cert-not-after #:cert-der
   ;; RSA-PSS / ECDSA
   #:verify-rsa-pss #:verify-ecdsa
   ;; SNP report
   #:parse-snp-report #:snp-report-octets #:snp-report-version #:snp-report-policy
   #:snp-report-measurement #:snp-report-report-data #:snp-report-chip-id
   #:snp-report-debug-p #:verify-snp-report
   ;; Tinfoil bundle
   #:verify-tinfoil-bundle #:tinfoil-bundle-report-data
   ;; AWS Nitro attestation documents (COSE_Sign1 / ES384)
   #:parse-nitro-doc #:verify-nitro-doc #:nitro-doc-p #:nitro-doc-pcr
   #:nitro-doc-public-key #:nitro-doc-user-data #:nitro-doc-nonce
   #:nitro-doc-certificate #:nitro-doc-cabundle #:nitro-doc-module-id
   #:nitro-doc-timestamp #:nitro-doc-digest #:nitro-doc-pcrs
   #:nitro-root-certificate #:*aws-nitro-root-pem*
   #:cbor-decode #:cbor-tag #:cbor-tag-p #:cbor-tag-tag #:cbor-tag-value
   ;; Rekor transparency log (tlogEntries)
   #:verify-rekor-entry #:rekor-prod-key-point #:rfc6962-inclusion-p
   ;; network (cl-sev-snp/kds)
   #:fetch-amd-chain #:fetch-tinfoil-bundle #:verify-tinfoil-live
   ;; errors
   #:attestation-error))
