# arb_guard

Stops OnePlus's kernel-triggered anti-rollback (ARB) commit. Stock `qcom-scm.ko`
exports `qcom_scm_update_rollback_version()`, which issues the TrustZone SMC
`svc=QCOM_SCM_SVC_BOOT cmd=0x1E` that blows the rollback fuses when userspace
writes `update_arb`. The overlay module is the stock vendor binary with that one
function stubbed to `return 0`; every other byte is OnePlus's.

## Patch

`patch_arb.py STOCK.ko OUT.ko` keeps the function's `PACIASP` landing pad and
writes `AUTIASP; MOV W0, #0; RET` over the next 12 bytes. It refuses to run if
the symbol is missing, if the first instruction is not `PACIASP`, or if a
relocation falls inside the patched range. `patch_arb.py --verify FILE.ko`
exits 0 only when the stub is in place.

## Modules

| file | stock source | stock sha256 | patched sha256 |
| --- | --- | --- | --- |
| `modules/qcom-scm_sm8750_android15-6.6.118_noarb.ko` | CPH2653 (OnePlus 13 Global) 17.0.0.102, vendor_boot | `e483b58dee90fad05a1bcc840ae8c0fad5a7a2c67bbcbd4c9af856e5a7dc856b` | `d29228f1d26546458448d5b18d66f27e6d9d73119f9b33786233157159a8ea7d` |

PKX110 (OnePlus 13T China) 16.0.10.500 ships the same code (no function-size
differences, the same 92 exports and CRCs; only `.BTF`, `.modinfo` and the
build-id differ), so one module serves sm8750 6.6.118 on A16 and A17.

## Use

The builders embed it as `qcom-scm.ko` only for configs with `"arb_guard": true`,
keyed on SoC, Android branch and the tree's exact sublevel. A firmware whose
stock module has no `qcom_scm_update_rollback_version` (e.g. Nord CE6 Global
16.0.5.1301) does not need, and must not get, an overlay.
