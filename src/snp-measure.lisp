;;;; snp-measure.lisp -- AMD SEV-SNP launch measurement (MEASUREMENT field of the
;;;; attestation report), recomputed in pure Common Lisp.
;;;;
;;;; Reproduces what QEMU + KVM + the AMD-SP do when launching an SNP guest with
;;;; OVMF and "measured direct boot" (-kernel/-initrd/-append with
;;;; kernel-hashes=on), i.e. the algorithm of virtee/sev-snp-measure 0.0.12 in
;;;; `--mode snp --vmm-type QEMU`, which is what Tinfoil's measure-image-action
;;;; invokes (internal/orchestrator/orchestrator.go, measureSNP):
;;;;
;;;;   --mode snp --vcpus N --vcpu-type EPYC-v4 --vmm-type QEMU
;;;;   --ovmf OVMF.fd --kernel K --initrd I --append CMDLINE --guest-features 0x1
;;;;
;;;; The launch digest LD starts at 48 zero bytes and for every page the
;;;; hypervisor hands to SNP_LAUNCH_UPDATE becomes
;;;;     LD := SHA-384( PAGE_INFO )      (SNP ABI spec, PAGE_INFO, 0x70 bytes)
;;;;     PAGE_INFO = LD(48) || CONTENTS(48) || len u16 =0x70 || page_type u8
;;;;                 || is_imi u8 =0 || vmpl3..1 perms u8 =0 || reserved u8 =0
;;;;                 || gpa u64
;;;; in this order:
;;;;   1. every 4 KiB page of the OVMF image, NORMAL (type 1), mapped so it ends
;;;;      at 4 GiB, CONTENTS = SHA-384(page);
;;;;   2. every section of OVMF's SEV metadata ("ASEV") table, in table order:
;;;;      SNP_SEC_MEM / SVSM_CAA -> ZERO pages (type 3), SNP_SECRETS -> type 5,
;;;;      CPUID -> type 6 (all with CONTENTS = 48 zero bytes), and
;;;;      SNP_KERNEL_HASHES -> a NORMAL page holding QEMU's SEV hashes table at
;;;;      the offset OVMF's SEV_HASH_TABLE_RV_GUID entry names;
;;;;   3. one VMSA page (type 2, gpa #xFFFFFFFFF000) per vCPU: the BSP's with
;;;;      RIP=#xFFF0/CS.base=#xFFFF0000, every AP's from OVMF's SEV-ES reset
;;;;      block.  This is the only vCPU-count-dependent input.
;;;;
;;;; The kernel and initrd enter ONLY through their SHA-256 in the hashes table,
;;;; so their binaries are not needed: the published manifest hashes suffice.
;;;; The cmdline entry is SHA-256 of the cmdline's UTF-8 bytes PLUS a trailing
;;;; NUL (QEMU hashes the NUL-terminated string it passes to the kernel).

(in-package :cl-sev-snp)

(deftype %octets () '(simple-array (unsigned-byte 8) (*)))

(defun %octet-vector (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun %le-put (vec offset value nbytes)
  (dotimes (i nbytes vec)
    (setf (aref vec (+ offset i)) (ldb (byte 8 (* 8 i)) value))))

(defun %le-get (vec offset nbytes)
  (let ((v 0))
    (dotimes (i nbytes v)
      (setf v (logior v (ash (aref vec (+ offset i)) (* 8 i)))))))

(defun %concat-octets (&rest vecs)
  (let* ((out (%octet-vector (reduce #'+ vecs :key #'length))) (pos 0))
    (dolist (v vecs out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun %utf8-octets (string)
  "UTF-8 encoding of STRING (no BOM, no terminator)."
  (let ((out (make-array (length string) :element-type '(unsigned-byte 8)
                                         :adjustable t :fill-pointer 0)))
    (loop for ch across string
          for c = (char-code ch)
          do (cond ((< c #x80) (vector-push-extend c out))
                   ((< c #x800)
                    (vector-push-extend (logior #xC0 (ash c -6)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   ((< c #x10000)
                    (vector-push-extend (logior #xE0 (ash c -12)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   (t
                    (vector-push-extend (logior #xF0 (ash c -18)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -12) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))))
    (coerce out '%octets)))

(defun %hex-octets (hex)
  (let ((out (%octet-vector (floor (length hex) 2))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun read-file-octets (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((v (%octet-vector (file-length s))))
      (read-sequence v s)
      v)))

;;; ------------------------------------------------------------------ GUIDs
;;; EFI GUIDs are stored "bytes_le": the first three fields little-endian.

(defun %guid-octets (string)
  "Mixed-endian (EFI / Python uuid.bytes_le) octets of the GUID STRING
   \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"."
  (let* ((hex (remove #\- string))
         (be (%hex-octets hex))
         (out (%octet-vector 16)))
    (replace out (reverse (subseq be 0 4)) :start1 0)
    (replace out (reverse (subseq be 4 6)) :start1 4)
    (replace out (reverse (subseq be 6 8)) :start1 6)
    (replace out (subseq be 8 16) :start1 8)
    out))

(defparameter +ovmf-table-footer-guid+ "96b582de-1fb2-45f7-baea-a366c55a082d")
(defparameter +sev-hash-table-rv-guid+ "7255371f-3a3b-4b04-927b-1da6efa8d454")
(defparameter +sev-es-reset-block-guid+ "00f771de-1a7e-4fcb-890e-68c77e2fb44e")
(defparameter +ovmf-sev-metadata-guid+ "dc886566-984a-4798-a75e-5585a7bf67cc")

(defparameter +sev-hash-table-header-guid+ "9438d606-4f22-4cc9-b479-a793d411fd21")
(defparameter +sev-kernel-entry-guid+ "4de79437-abd2-427f-b835-d5b172d2045b")
(defparameter +sev-initrd-entry-guid+ "44baf731-3a2f-4bd7-9af1-41e29169781d")
(defparameter +sev-cmdline-entry-guid+ "97d02dd8-bd20-4c94-aa78-e7714d36ab2a")

;;; ------------------------------------------------------------------ OVMF parsing

(defun ovmf-footer-table (ovmf)
  "OVMF's GUIDed footer table (OvmfPkg ResetVector): an alist (GUID-OCTETS . DATA).
   The table ends 32 bytes before the end of the image; each entry is
   DATA || size u16 || guid(16), walked backwards from the footer entry."
  (let* ((size (length ovmf))
         (hdr 18)
         (footer (- size 32 hdr))
         (table '()))
    (unless (equalp (subseq ovmf (+ footer 2) (+ footer 18))
                    (%guid-octets +ovmf-table-footer-guid+))
      (return-from ovmf-footer-table nil))
    (let* ((table-size (- (%le-get ovmf footer 2) hdr))
           (end footer)
           (start (- footer table-size)))
      (loop while (>= (- end start) hdr)
            do (let* ((eh (- end hdr))
                      (esize (%le-get ovmf eh 2))
                      (guid (subseq ovmf (+ eh 2) (+ eh 18))))
                 (when (< esize hdr) (error "OVMF footer table: invalid entry size ~D" esize))
                 (push (cons guid (subseq ovmf (- end esize) eh)) table)
                 (decf end esize))))
    table))

(defun %ovmf-table-u32 (table guid-string)
  (let ((e (assoc (%guid-octets guid-string) table :test #'equalp)))
    (unless e (error "OVMF footer table lacks GUID ~A" guid-string))
    (%le-get (cdr e) 0 4)))

(defun ovmf-sev-metadata (ovmf table)
  "The OVMF SEV metadata sections, in table order, as a list of
   (GPA SIZE TYPE) where TYPE is 1 SNP_SEC_MEM, 2 SNP_SECRETS, 3 CPUID,
   4 SVSM_CAA, #x10 SNP_KERNEL_HASHES."
  (let* ((off-from-end (%ovmf-table-u32 table +ovmf-sev-metadata-guid+))
         (start (- (length ovmf) off-from-end)))
    (unless (equalp (subseq ovmf start (+ start 4)) (map '%octets #'char-code "ASEV"))
      (error "Wrong SEV metadata signature"))
    (unless (= 1 (%le-get ovmf (+ start 8) 4)) (error "Wrong SEV metadata version"))
    (loop with n = (%le-get ovmf (+ start 12) 4)
          for i below n
          for p = (+ start 16 (* 12 i))
          collect (list (%le-get ovmf p 4) (%le-get ovmf (+ p 4) 4) (%le-get ovmf (+ p 8) 4)))))

;;; ------------------------------------------------------------------ launch digest

(defconstant +vmsa-gpa+ #xFFFFFFFFF000)

(defstruct (gctx (:constructor %make-gctx)) (ld (%octet-vector 48)))

(defun %gctx-update (g page-type gpa contents)
  (assert (= 48 (length contents)))
  (let ((info (%octet-vector #x70)))
    (replace info (gctx-ld g) :start1 0)
    (replace info contents :start1 48)
    (%le-put info 96 #x70 2)
    (setf (aref info 98) page-type)     ; is_imi, vmpl perms, reserved stay 0
    (%le-put info 104 gpa 8)
    (setf (gctx-ld g) (sha384 info))))

(defun %gctx-normal-pages (g gpa data)
  (assert (zerop (mod (length data) 4096)))
  (loop for off from 0 below (length data) by 4096
        do (%gctx-update g 1 (+ gpa off) (sha384 (subseq data off (+ off 4096))))))

(defun %gctx-typed-pages (g type gpa length)
  (assert (zerop (mod length 4096)))
  (loop for off from 0 below length by 4096
        do (%gctx-update g type (+ gpa off) (%octet-vector 48))))

;;; ------------------------------------------------------------------ SEV hashes table

(defun sev-hashes-table (kernel-sha256 initrd-sha256 cmdline-sha256)
  "QEMU's SevHashTable (target/i386/sev.c), padded to 16 bytes: 176 octets.
   header guid(16) len u16(=168), then cmdline, initrd, kernel entries, each
   guid(16) len u16(=50) sha256(32)."
  (flet ((entry (guid hash)
           (assert (= 32 (length hash)))
           (%concat-octets (%guid-octets guid) (%le-put (%octet-vector 2) 0 50 2) hash)))
    (%concat-octets (%guid-octets +sev-hash-table-header-guid+)
                    (%le-put (%octet-vector 2) 0 168 2)
                    (entry +sev-cmdline-entry-guid+ cmdline-sha256)
                    (entry +sev-initrd-entry-guid+ initrd-sha256)
                    (entry +sev-kernel-entry-guid+ kernel-sha256)
                    (%octet-vector 8))))

(defun cmdline-sha256 (cmdline)
  "SHA-256 of CMDLINE as QEMU hashes it: UTF-8 bytes plus a trailing NUL.
   An empty/NIL cmdline hashes the single NUL byte."
  (sha256 (%concat-octets (if cmdline (%utf8-octets cmdline) (%octet-vector 0))
                          (%octet-vector 1))))

;;; ------------------------------------------------------------------ VMSA

(defun cpuid-signature (family model stepping)
  "CPUID Fn0000_0001_EAX for FAMILY/MODEL/STEPPING (AMD pub. 25481)."
  (multiple-value-bind (flo fhi) (if (> family #xF) (values #xF (logand (- family #xF) #xFF))
                                     (values family 0))
    (logior (ash fhi 20) (ash (logand (ash model -4) #xF) 16) (ash flo 8)
            (ash (logand model #xF) 4) (logand stepping #xF))))

(defparameter +vcpu-signatures+
  `(("EPYC-v4" . ,(cpuid-signature 23 1 2))        ; #x800F12, what Tinfoil uses
    ("EPYC-Rome" . ,(cpuid-signature 23 49 0))
    ("EPYC-Milan" . ,(cpuid-signature 25 1 1))
    ("EPYC-Genoa" . ,(cpuid-signature 25 17 0))))

(defun vmsa-page (eip sev-features vcpu-sig)
  "The 4 KiB initial VMSA (SEV-ES save area) KVM/QEMU builds for a vCPU whose
   reset vector is EIP, as sev-snp-measure models it for VMM type QEMU."
  (let ((p (%octet-vector 4096)))
    (flet ((seg (off sel attr limit base)
             (%le-put p off sel 2) (%le-put p (+ off 2) attr 2)
             (%le-put p (+ off 4) limit 4) (%le-put p (+ off 8) base 8))
           (u64 (off v) (%le-put p off v 8))
           (u32 (off v) (%le-put p off v 4))
           (u16 (off v) (%le-put p off v 2)))
      (seg #x00 0 #x93 #xFFFF 0)                               ; es
      (seg #x10 #xF000 #x9B #xFFFF (logand eip #xFFFF0000))    ; cs
      (seg #x20 0 #x93 #xFFFF 0)                               ; ss
      (seg #x30 0 #x93 #xFFFF 0)                               ; ds
      (seg #x40 0 #x93 #xFFFF 0)                               ; fs
      (seg #x50 0 #x93 #xFFFF 0)                               ; gs
      (seg #x60 0 0 #xFFFF 0)                                  ; gdtr
      (seg #x70 0 #x82 #xFFFF 0)                               ; ldtr
      (seg #x80 0 0 #xFFFF 0)                                  ; idtr
      (seg #x90 0 #x8B #xFFFF 0)                               ; tr
      (u64 #xD0 #x1000)                                        ; efer (SVME)
      (u64 #x148 #x40)                                         ; cr4 (MCE)
      (u64 #x158 #x10)                                         ; cr0
      (u64 #x160 #x400)                                        ; dr7
      (u64 #x168 #xFFFF0FF0)                                   ; dr6
      (u64 #x170 #x2)                                          ; rflags
      (u64 #x178 (logand eip #xFFFF))                          ; rip
      (u64 #x268 #x0007040600070406)                           ; g_pat
      (u64 #x310 vcpu-sig)                                     ; rdx
      (u64 #x3B0 sev-features)                                 ; sev_features
      (u64 #x3E8 #x1)                                          ; xcr0
      (u32 #x408 #x1F80)                                       ; mxcsr
      (u16 #x410 #x37F))                                       ; x87_fcw
    p))

;;; ------------------------------------------------------------------ the measurement

(defun snp-launch-measurement (&key ovmf-octets kernel-sha256 initrd-sha256 cmdline
                                    (vcpus 1) (vcpu-signature (cdr (assoc "EPYC-v4" +vcpu-signatures+
                                                                          :test #'string=)))
                                    (guest-features #x1))
  "The 48-byte SEV-SNP launch digest for OVMF-OCTETS booted with measured direct
   boot.  KERNEL-SHA256 / INITRD-SHA256 are 32-octet digests of the kernel and
   initrd files (NIL kernel = no direct boot: the hashes page is measured as a
   ZERO page; NIL initrd with a kernel = SHA-256 of the empty string, as QEMU).
   CMDLINE is the -append string.  GUEST-FEATURES is SEV_FEATURES of every VMSA."
  (let* ((ovmf ovmf-octets)
         (g (%make-gctx))
         (table (ovmf-footer-table ovmf))
         (ovmf-gpa (- #x100000000 (length ovmf)))
         (reset-eip (%ovmf-table-u32 table +sev-es-reset-block-guid+))
         (hashes (and kernel-sha256
                      (sev-hashes-table kernel-sha256 (or initrd-sha256 (sha256 (%octet-vector 0)))
                                        (cmdline-sha256 cmdline)))))
    ;; 1. the firmware image
    (%gctx-normal-pages g ovmf-gpa ovmf)
    ;; 2. OVMF's SEV metadata sections
    (dolist (sec (ovmf-sev-metadata ovmf table))
      (destructuring-bind (gpa size type) sec
        (ecase type
          ((1 4) (%gctx-typed-pages g 3 gpa size))          ; SEC_MEM, SVSM_CAA -> ZERO
          (2 (%gctx-update g 5 gpa (%octet-vector 48)))      ; SECRETS
          (3 (%gctx-update g 6 gpa (%octet-vector 48)))      ; CPUID
          (#x10                                              ; KERNEL_HASHES
           (if hashes
               (let* ((off (logand (%ovmf-table-u32 table +sev-hash-table-rv-guid+) #xFFF))
                      (page (%octet-vector size)))
                 (assert (= size 4096))
                 (replace page hashes :start1 off)
                 (%gctx-normal-pages g gpa page))
               (%gctx-typed-pages g 3 gpa size))))))
    (when (and hashes (notany (lambda (s) (= (third s) #x10)) (ovmf-sev-metadata ovmf table)))
      (error "Kernel specified but OVMF metadata has no SNP_KERNEL_HASHES section"))
    ;; 3. one VMSA per vCPU
    (let ((bsp (sha384 (vmsa-page #xFFFFFFF0 guest-features vcpu-signature)))
          (ap (sha384 (vmsa-page reset-eip guest-features vcpu-signature))))
      (dotimes (i vcpus)
        (%gctx-update g 2 +vmsa-gpa+ (if (zerop i) bsp ap))))
    (gctx-ld g)))

;;; ------------------------------------------------------------------ Tinfoil manifests

(defun tinfoil-deployment-measurement (deployment ovmf-octets &key (cmdline nil cmdline-p))
  "Hex SEV-SNP measurement for DEPLOYMENT, a tinfoil-deployment.json parsed by
   JSON-SIMPLE:PARSE (hash tables), booting OVMF-OCTETS.  Parameters are
   Tinfoil's measure-image-action ones: EPYC-v4, guest features #x1, QEMU,
   vcpus = vm_shape.cpus.  Checks OVMF-OCTETS against firmware.sev_snp.sha256.
   CMDLINE overrides the manifest's (for negative tests)."
  (flet ((get-in (&rest keys)
           (let ((v deployment))
             (dolist (k keys v) (setf v (gethash k v))))))
    (let ((want-fw (get-in "firmware" "sev_snp" "sha256")))
      (when want-fw
        (unless (string-equal want-fw (hex-string (sha256 ovmf-octets)))
          (error "OVMF sha256 ~A does not match manifest firmware ~A"
                 (hex-string (sha256 ovmf-octets)) want-fw))))
    (hex-string
     (snp-launch-measurement :ovmf-octets ovmf-octets
                             :kernel-sha256 (%hex-octets (get-in "hashes" "kernel"))
                             :initrd-sha256 (%hex-octets (get-in "hashes" "initrd"))
                             :cmdline (if cmdline-p cmdline (get-in "cmdline"))
                             :vcpus (get-in "vm_shape" "cpus")))))
