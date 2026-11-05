#!/usr/bin/env python3
"""Put task_struct's ANDROID_KABI slots back in the order the ROM expects.

ONE copy, called by every builder -- same reasoning as apply_nomount_stack.sh.

WHY THIS EXISTS. ANDROID_KABI_USE() spends one of task_struct's reserved
padding slots, so which field lands in which slot is part of the ABI even though
the struct's size never changes. OnePlus' published android14-6.1 source from
.157 onwards adds dmabuf_info and, with CONFIG_SLIM_SCHED set (which their own
gki_defconfig sets), lays the slots out as

    2 = sched_prop, 3 = scx, 4 = dmabuf_info

while the production kernel their prebuilt vendor modules were compiled against
uses

    2 = dmabuf_info, 3 = sched_prop, 4 = scx

A kernel built from the published source therefore has every vendor module
reading task_struct through the wrong slot -- dmabuf_info where sched_prop
lives and back again, on every task -- and the device does not reach userspace.

Nothing catches this earlier: the slots are reused padding, so the struct size,
the exported symbol CRCs and MODVERSIONS all agree. .118 and .141 are unaffected
because dmabuf_info does not exist there at all.

Credit: diagnosed and fixed first in WildKernels/OnePlus_KernelSU_SUSFS
(10170ccb, "Fix task_struct KABI alignment 6.1.157 and above").

The guard is the published layout itself rather than a sublevel number, so this
no-ops on every tree that does not carry it -- including the day OnePlus fixes
the ordering upstream.
"""

import io
import os
import re
import sys

BUGGY = re.compile(
    r"(\tANDROID_KABI_USE\(1, unsigned int saved_state\);\n)"
    r"#ifdef CONFIG_SLIM_SCHED\n"
    r"\tANDROID_KABI_USE\(2, unsigned long sched_prop\);\n"
    r"\tANDROID_KABI_USE\(3, struct sched_ext_entity \*scx\);\n"
    r"\tANDROID_KABI_USE\(4, struct task_dma_buf_info \*dmabuf_info\);\n"
    r"#else\n"
    r"\tANDROID_KABI_USE\(2, struct task_dma_buf_info \*dmabuf_info\);\n"
    r"\tANDROID_KABI_RESERVE\(3\);\n"
    r"\tANDROID_KABI_RESERVE\(4\);\n"
    r"#endif"
)

FIXED = (
    "\\1"
    "\tANDROID_KABI_USE(2, struct task_dma_buf_info *dmabuf_info);\n"
    "#ifdef CONFIG_SLIM_SCHED\n"
    "\tANDROID_KABI_USE(3, unsigned long sched_prop);\n"
    "\tANDROID_KABI_USE(4, struct sched_ext_entity *scx);\n"
    "#else\n"
    "\tANDROID_KABI_RESERVE(3);\n"
    "\tANDROID_KABI_RESERVE(4);\n"
    "#endif"
)

ALREADY = "\tANDROID_KABI_USE(2, struct task_dma_buf_info *dmabuf_info);\n#ifdef CONFIG_SLIM_SCHED"


def main():
    tree = os.environ.get("COMMON_KERNEL_FOLDER", "")
    if not tree or not os.path.isdir(os.path.join(tree, "include", "linux")):
        print("::error::fix_oplus_task_struct_kabi: COMMON_KERNEL_FOLDER=%r is not a kernel tree" % tree)
        return 1

    path = os.path.join(tree, "include", "linux", "sched.h")
    print("::group::Fix OPlus task_struct KABI slots")
    if not os.path.isfile(path):
        print("   no include/linux/sched.h, nothing to do")
        print("::endgroup::")
        return 0

    s = io.open(path, encoding="utf-8").read()

    if ALREADY in s:
        print("   slots already in the dmabuf_info=2 order, nothing to do")
        print("::endgroup::")
        return 0
    if not BUGGY.search(s):
        print("   this tree does not carry the split-slot layout, nothing to do")
        print("::endgroup::")
        return 0

    out, n = BUGGY.subn(FIXED, s, count=1)
    if n != 1 or ALREADY not in out:
        print("::error::fix_oplus_task_struct_kabi: the slot reorder did not apply cleanly")
        return 1
    io.open(path, "w", encoding="utf-8").write(out)
    print("   reordered task_struct slots to dmabuf_info=2, sched_prop=3, scx=4")
    print("::endgroup::")
    return 0


if __name__ == "__main__":
    sys.exit(main())
