# inte overlay source

Neutered `oplus_kernel_security_check.c` (OPlus kernel-integrity module, builds `inte.ko`).
Source ported from OnePlus mt6993 GPL release; two detection emits removed (ko-hash +
syscall-table events), all hashing preserved. Built per-KMI by the `build_inte_overlay`
path in `OnePlus-KsuNext_NMS/.github/actions/build-kernel`; the resulting `inte.ko` lands
in `../modules/` and is baked by the module_overlay patch.
