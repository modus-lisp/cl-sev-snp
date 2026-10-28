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
   ;; Tinfoil attestation document v3
   #:v3-check-envelope #:v3-decode-document #:v3-report-data #:strict-json-parse #:strict-json-parse-octets
   #:v3-reject #:v3-reject-code #:v3-reject-reason
   #:v3-document #:v3-doc-format #:v3-doc-nonce-hex #:v3-doc-report-data-hex #:v3-doc-cpu-format
   #:v3-doc-report #:v3-doc-crypto-material-hash #:v3-doc-device-evidence-hash
   #:v3-doc-crypto-material-bytes #:v3-doc-device-evidence-bytes
   #:v3-doc-crypto-items #:v3-doc-device-items #:v3-doc-collateral #:v3-doc-collateral-format
   #:v3-doc-expected-report-data
   #:v3-authenticate-sev-quote #:v3-verify-sev-quote #:parse-amd-crl
   #:v3-authenticate-code #:parse-sigstore-trusted-root #:parse-release-pin
   ;; SEV-SNP launch measurement, recomputed
   #:snp-launch-measurement #:tinfoil-deployment-measurement #:read-file-octets
   ;; our policy and the chain of custody
   #:sev-snp-params #:*sev-snp-defaults* #:sev-report-fields #:v3-validate-sev-policy #:v3-verify-chain
   ;; errors
   #:attestation-error))
