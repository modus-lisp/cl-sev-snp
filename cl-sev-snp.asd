;;;; cl-sev-snp.asd -- AMD SEV-SNP report and Tinfoil attestation verification.
;;;;
;;;; :cl-sev-snp        pure Common Lisp (depends only on cram for gzip and json-simple
;;;;                    for the bundle), no FFI.
;;;; :cl-sev-snp/kds    optional network layer (AMD KDS chain, Tinfoil bundle fetch) via
;;;;                    dexador. Kept separate so the verifier core stays dependency-free.

(asdf:defsystem :cl-sev-snp
  :description "SEV-SNP attestation verification: ARK/ASK/VCEK chain, report signature, Tinfoil bundle (DSSE/sigstore), pure CL."
  :license "MIT"
  :depends-on (:cram :json-simple)
  :serial t
  :components ((:module "src"
                :components ((:file "package")
                             (:file "hash")
                             (:file "encoding")
                             (:file "der")
                             (:file "rsa")
                             (:file "ec")
                             (:file "snp")
                             (:file "tinfoil")
                             (:file "rekor")))))

(asdf:defsystem :cl-sev-snp/kds
  :description "Network fetch for cl-sev-snp: AMD KDS certificate chain and Tinfoil attestation bundle (uses dexador)."
  :license "MIT"
  :depends-on (:cl-sev-snp :dexador)
  :serial t
  :components ((:module "src" :components ((:file "kds")))))

(asdf:defsystem :cl-sev-snp/tests
  :description "Tests for cl-sev-snp against a captured Tinfoil bundle and AMD KDS chain."
  :license "MIT"
  :depends-on (:cl-sev-snp)
  :serial t
  :components ((:module "t" :components ((:file "tests")))))
