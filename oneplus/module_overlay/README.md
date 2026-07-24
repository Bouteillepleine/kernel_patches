# module_overlay

Replaces a module image supplied by userspace with a copy embedded in the
kernel image at build time, so a known-good `.ko` is always the one that
gets loaded.

## Layout

| path | purpose |
| --- | --- |
| `0001-module-...-<android>-<kver>.patch` | the mechanism, one variant per GKI branch |
| `modules/*.ko` | prebuilt module images to embed |

## How a module is matched

`convert_overlay.sh` derives the match key from the **file name**: it strips
the `.ko` suffix and folds `-` to `_`, exactly as `scripts/Makefile.lib`
does. The result is compared against `info->name` -- the module's own
`MODULE_NAME` -- at load time.

That means a file in `modules/` must be named after the module it replaces
and nothing else. `qcom-scm.ko` matches the module `qcom_scm`;
`qcom-scm_sm8750_A16_android15-6.6.89.ko` does **not** -- it would be
registered under the key `qcom_scm_sm8750_A16_android15_6.6.89`, which no
module ever reports.

The descriptive suffixes used in this directory exist so that several
device/OS/kernel variants of the same module can live side by side. The
consumer is responsible for selecting one and **renaming it to the bare
module name** when copying it into
`kernel/module/module_overlay/modules/` (or `kernel/module_overlay/modules/`
on 5.10 and 5.15). The suffix grammar, in descending priority, is:

```
<module>_<model>_<osver>_<kver>.ko
<module>_<soc>_<osver>_<kver>.ko
<module>_<model>_<osver>.ko
<module>_<soc>_<osver>.ko
<module>_<model>.ko
<module>_<soc>.ko
<module>_<kver>.ko
```

## Requirements

* `zstd` and `xxd` must be on `PATH` at build time. `convert_overlay.sh`
  fails the build if either is missing rather than silently emitting an
  empty overlay table.
* `convert_overlay.sh` is committed executable; it is invoked directly by
  the generated `Makefile`.

## Embedded images

An embedded `.ko` still goes through the normal loader checks after
interception -- signature, vermagic and `__versions` CRCs. With
`CONFIG_MODVERSIONS=y` the release portion of vermagic is ignored, so a
differing `LOCALVERSION` is harmless, but the module's symbol CRCs must
match the KMI of the kernel being built.
