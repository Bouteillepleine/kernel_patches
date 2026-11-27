# arb_guard

Stops OnePlus/OPPO's kernel-triggered anti-rollback (ARB) commit. Stock
`qcom-scm.ko` exports `qcom_scm_update_rollback_version()`, which issues the
TrustZone SMC `svc=QCOM_SCM_SVC_BOOT cmd=0x1E` that blows the rollback fuses
when userspace writes `update_arb`.

`arb_guard-<android>-<kver>.patch` (android14-6.1, android15-6.6, android16-6.12)
hooks `load_module()` just before `layout_and_allocate()`. For the module named `qcom_scm` only, it finds that
function in the image the phone supplies and, if it starts with `PACIASP` and
no relocation falls in the next 12 bytes, rewrites them to
`AUTIASP; MOV W0, #0; RET`. Every other byte stays the firmware's own, so OTAs
that update `qcom-scm` keep working, and a firmware whose module has no such
function (Nord CE6 Global 16.0.5.1301, for one) loads untouched. Success logs
at `pr_debug` only.

`patch_arb.py STOCK.ko OUT.ko` applies the same 12 bytes offline and
`patch_arb.py --verify FILE.ko` checks them; the hook was validated against it
on OP13T CN 16.0.10.500 and OP13 Global 17.0.0.102 (6.6.118), OP12 Global
16.0.10.601 and Nord 5 Global 16.0.5.1302 (6.1.157): byte-identical results.
