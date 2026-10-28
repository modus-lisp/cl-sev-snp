;;;; v3-policy.lisp -- OUR policy over an authenticated SEV-SNP quote, and the whole
;;;; chain of custody for a Tinfoil v3 document.
;;;;
;;;; Authentication (v3-quote.lisp) says a report is genuine.  This file says whether its
;;;; genuine contents are acceptable to US.  The acceptable values are the parameters of
;;;; "trust sev-snp(...)": each has a default here, and a caller overrides any of them
;;;; explicitly (operandi's --trust).  They are deliberately NOT taken at run time from
;;;; the provider's own signed platform policy -- that would put the provider's signature
;;;; back into the chain -- although the defaults below were reviewed against it.
;;;;
;;;; DEFAULTS, AND WHERE THEY CAME FROM.  The TCB floors, firmware build and API version
;;;; are copied from tinfoilsh/cvmimage platform-v0.1.5 (platform-endorsements-classic.json,
;;;; sha256 30db0144...706b, signature verified), policies amd-genoa-prod and amd-turin-prod,
;;;; on 2026-10-20.  They are a snapshot to be reviewed against AMD's security bulletins,
;;;; not a live feed.  The fixed invariants (debug off, migration agent off, provisional
;;;; firmware refused, VMPL 0, alias check complete) are not snapshots: nothing
;;;; confidential runs with them otherwise.

(in-package :cl-sev-snp)

(defun %policy-reject (fmt &rest args)
  (apply #'%v3-reject "POLICY_REJECTED" fmt args))

;;; ---- report fields ---------------------------------------------------------

(defparameter +tcb-layout+
  '(("Genoa" . ((:bl . 0) (:tee . 1) (:snp . 6) (:ucode . 7)))
    ("Turin" . ((:fmc . 0) (:bl . 1) (:tee . 2) (:snp . 3) (:ucode . 7))))
  "Where each SPL sits in an 8-byte TCB_VERSION, per product line (see v3-quote.lisp).")

(defun %tcb-parts (octets offset product)
  (loop for (name . byte) in (cdr (assoc product +tcb-layout+ :test #'string=))
        collect name collect (aref octets (+ offset byte))))

(defun sev-report-fields (octets product)
  "The policy-relevant fields of a 1184-byte SNP report, decoded."
  (let ((policy (%le octets 8 16)) (info (%le octets #x40 #x48)))
    (list :guest-svn (%le octets 4 8)
          :abi-minor (ldb (byte 8 0) policy) :abi-major (ldb (byte 8 8) policy)
          :smt (logbitp 16 policy) :migrate-ma (logbitp 18 policy) :debug (logbitp 19 policy)
          :single-socket (logbitp 20 policy)
          :family-id (subseq octets #x10 #x20) :image-id (subseq octets #x20 #x30)
          :vmpl (%le octets #x30 #x34)
          :smt-enabled (logbitp 0 info) :tsme-enabled (logbitp 1 info) :ecc-enabled (logbitp 2 info)
          :rapl-disabled (logbitp 3 info) :ciphertext-hiding-dram (logbitp 4 info)
          :alias-check-complete (logbitp 5 info)
          :host-data (subseq octets #xc0 #xe0)
          :current-tcb (%tcb-parts octets #x38 product)
          :reported-tcb (%tcb-parts octets #x180 product)
          :committed-tcb (%tcb-parts octets #x1e0 product)
          :launch-tcb (%tcb-parts octets #x1f0 product)
          :current-build (aref octets #x1e8) :current-minor (aref octets #x1e9) :current-major (aref octets #x1ea)
          :committed-build (aref octets #x1ec) :committed-minor (aref octets #x1ed) :committed-major (aref octets #x1ee))))

;;; ---- the parameters of "trust sev-snp(...)" ---------------------------------

(defparameter *sev-snp-defaults*
  '(:debug nil :migrate-ma nil :vmpl 0 :permit-provisional-firmware nil :alias-check-complete t
    :smt :any :single-socket :any :tsme-enabled :any :ecc-enabled :any
    :host-data :zero :image-id :zero :family-id :zero :minimum-guest-svn 0
    :minimum-tcb (("Genoa" :bl 7 :tee 0 :snp 14 :ucode 72)
                  ("Turin" :fmc 1 :bl 1 :tee 1 :snp 4 :ucode 82))
    :minimum-launch-tcb (("Genoa" :bl 7 :tee 0 :snp 14 :ucode 72)
                         ("Turin" :fmc 1 :bl 1 :tee 1 :snp 4 :ucode 82))
    :minimum-build (("Genoa" . 21) ("Turin" . 0))
    :minimum-api-version (("Genoa" 1 55) ("Turin" 1 58)))
  "Every parameter of trust sev-snp(...) and its default.  :ANY means the default does not
constrain it; a caller who cares sets it.  Override with SEV-SNP-PARAMS.")

(defun sev-snp-params (&rest overrides)
  "The defaults with OVERRIDES (a plist) applied.  An unknown parameter is an error, so
a typo cannot silently leave the default in force."
  (let ((params (copy-list *sev-snp-defaults*)))
    (loop for (k v) on overrides by #'cddr
          do (unless (member k *sev-snp-defaults*)
               (error "unknown sev-snp parameter ~s" k))
             (setf (getf params k) v))
    params))

(defun %tcb>= (have floor)
  (loop for (name min) on floor by #'cddr
        always (>= (or (getf have name) -1) min)))

(defun v3-validate-sev-policy (quote params)
  "Check an authenticated QUOTE (from V3-AUTHENTICATE-SEV-QUOTE, which must carry the
report octets under :OCTETS) against PARAMS.  Returns the decoded fields; signals
V3-REJECT (POLICY_REJECTED) naming the first parameter the report does not meet."
  (let* ((product (getf quote :product))
         (f (sev-report-fields (getf quote :octets) product)))
    (flet ((want (key actual)
             (let ((w (getf params key)))
               (cond ((eq w :any))
                     ((eq w :zero) (unless (every #'zerop actual)
                                     (%policy-reject "~(~a~) is not zero" key)))
                     ((not (eql (and w t) (and actual t)))
                      (%policy-reject "~(~a~) is ~a, sev-snp(~(~a~)=~a) requires ~a" key actual key w w))))))
      (want :debug (getf f :debug))
      (want :migrate-ma (getf f :migrate-ma))
      (want :smt (getf f :smt))
      (want :single-socket (getf f :single-socket))
      (want :alias-check-complete (getf f :alias-check-complete))
      (want :tsme-enabled (getf f :tsme-enabled))
      (want :ecc-enabled (getf f :ecc-enabled))
      (want :host-data (getf f :host-data))
      (want :image-id (getf f :image-id))
      (want :family-id (getf f :family-id)))
    (unless (= (getf f :vmpl) (getf params :vmpl))
      (%policy-reject "report VMPL is ~d, sev-snp(vmpl=~d)" (getf f :vmpl) (getf params :vmpl)))
    (unless (>= (getf f :guest-svn) (getf params :minimum-guest-svn))
      (%policy-reject "guest SVN ~d is below the minimum" (getf f :guest-svn)))
    (let ((tcb (cdr (assoc product (getf params :minimum-tcb) :test #'string=)))
          (launch (cdr (assoc product (getf params :minimum-launch-tcb) :test #'string=))))
      (unless tcb (%policy-reject "no minimum TCB is set for product ~a" product))
      (dolist (which '(:current-tcb :reported-tcb :committed-tcb))
        (unless (%tcb>= (getf f which) tcb)
          (%policy-reject "~(~a~) ~s is below sev-snp(minimum-tcb=~s)" which (getf f which) tcb)))
      (unless (and launch (%tcb>= (getf f :launch-tcb) launch))
        (%policy-reject "launch TCB ~s is below sev-snp(minimum-launch-tcb=~s)" (getf f :launch-tcb) launch)))
    (let ((build (cdr (assoc product (getf params :minimum-build) :test #'string=)))
          (api (cdr (assoc product (getf params :minimum-api-version) :test #'string=))))
      (unless (>= (getf f :current-build) (or build 0))
        (%policy-reject "firmware build ~d is below ~d" (getf f :current-build) build))
      (when api
        (unless (or (> (getf f :current-major) (first api))
                    (and (= (getf f :current-major) (first api)) (>= (getf f :current-minor) (second api))))
          (%policy-reject "firmware API ~d.~d is below ~d.~d" (getf f :current-major) (getf f :current-minor)
                          (first api) (second api)))))
    (unless (getf params :permit-provisional-firmware)
      (unless (and (equal (getf f :current-tcb) (getf f :committed-tcb))
                   (= (getf f :current-build) (getf f :committed-build))
                   (= (getf f :current-major) (getf f :committed-major))
                   (= (getf f :current-minor) (getf f :committed-minor)))
        (%policy-reject "firmware is provisional (current differs from committed)")))
    f))

;;; ---- the chain of custody --------------------------------------------------

(defun v3-verify-chain (document-octets nonce
                        &key pin ark-pem ask-pem sigstore-root (params (sev-snp-params))
                          deployment-octets ovmf-octets (now (- (get-universal-time) 2208988800)))
  "Verify every link from our nonce to the container definition, and report which links
were PROVEN here and which remain for the caller to DECLARE trusted.

  DOCUMENT-OCTETS, NONCE   the v3 document fetched with our fresh 32-byte nonce
  PIN                      owner/name[@tag][@sha256:digest] of the container definition
  ARK-PEM, ASK-PEM         the trusted AMD root for the report's product line
  SIGSTORE-ROOT            parsed Sigstore trusted root (PARSE-SIGSTORE-TRUSTED-ROOT)
  PARAMS                   sev-snp(...) parameters (SEV-SNP-PARAMS)
  DEPLOYMENT-OCTETS, OVMF-OCTETS  optional: the definition artifact and its firmware, to
                           recompute the launch measurement instead of believing the signer

Returns a plist: :custody (list of (LINK STATUS DETAIL), STATUS :proven or :declare),
:quote :code :fields :gpus.  Signals V3-REJECT at the first failing link."
  (multiple-value-bind (doc q) (v3-verify-sev-quote document-octets nonce :ark-pem ark-pem :ask-pem ask-pem :now now)
    (let* ((code (v3-authenticate-code doc pin sigstore-root))
           (expected (first (getf (getf code :measurement) :registers)))
           (actual (first (getf (getf q :launch-measurement) :registers)))
           (fields (v3-validate-sev-policy q params))
           (gpus (getf (getf code :shape) :gpus))
           (recomputed nil))
      (unless (string= expected actual)
        (%policy-reject "the report's measurement ~a is not the pinned definition's ~a" actual expected))
      (when (and deployment-octets ovmf-octets)
        (unless (string= (hex-string (sha256 deployment-octets)) (getf code :digest))
          (%policy-reject "the supplied definition is not the signed artifact"))
        (setf recomputed (tinfoil-deployment-measurement
                          (json-simple:parse (map 'string #'code-char deployment-octets)) ovmf-octets))
        (unless (string= recomputed expected)
          (%policy-reject "recomputed measurement ~a differs from the signed one" recomputed)))
      (let ((device-items (v3-doc-device-items doc)))
        (when (and (zerop gpus) device-items)
          (%policy-reject "the definition declares no GPUs but the document carries device evidence"))
        (when (and (plusp gpus) (/= (length device-items) gpus))
          (%policy-reject "the definition declares ~d GPUs, the document carries evidence for ~d"
                          gpus (length device-items))))
      (list
       :custody
       (remove nil
               (list
                (list "sev-snp report signed by AMD" :proven
                      (format nil "~a chip ~a..., chain to the pinned ARK, CRL current"
                              (getf q :product) (subseq (getf q :identity-hex) 0 16)))
                (list "our nonce and the endorsed keys bound into the report" :proven
                      (format nil "REPORT_DATA ~a..." (subseq (getf q :report-data-hex) 0 16)))
                (list "sev-snp parameters met" :proven
                      (format nil "debug off, migration agent off, VMPL ~d, TCB ~s"
                              (getf fields :vmpl) (getf fields :current-tcb)))
                (list "container definition signed from the pinned repository" :proven
                      (format nil "~a@~a commit ~a, Rekor + CT logged" (getf code :repo) (getf code :tag) (getf code :commit)))
                (list "running image is the signed definition" :proven
                      (format nil "measurement ~a..." (subseq actual 0 16)))
                (if recomputed
                    (list "definition's measurement recomputed here" :proven
                          "from the definition's firmware, kernel/initrd hashes and cmdline")
                    (list "definition's measurement recomputed here" :declare
                          "not recomputed: the signer's statement of the measurement is trusted"))
                (when (plusp gpus)
                  (list "GPUs in confidential mode" :declare
                        (format nil "~d GPU evidence item~:p present; NVIDIA evidence is not verified here (declare nvidia)" gpus)))
                (list "the container source does what its definition says" :declare
                      (format nil "audit ~a@~a and the images it pins (declare image:~a)"
                              (getf code :repo) (getf code :tag) (subseq actual 0 16)))))
       :quote q :code code :fields fields :gpus gpus))))
