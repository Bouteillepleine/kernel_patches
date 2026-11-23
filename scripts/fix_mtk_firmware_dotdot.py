#!/usr/bin/env python3
"""Let the MediaTek tfa98xx codec load its firmware from the odm root.

ONE copy, called by every builder -- same reasoning as apply_nomount_stack.sh.

WHY THIS EXISTS. 5.10.226 backported name_contains_dotdot() into
drivers/base/firmware_loader/main.c, which refuses any firmware name carrying a
".." component. On MediaTek platforms the tfa98xx speaker codec asks for
'../../odm/firmware/tfa98xx.cnt' -- a relative traversal out of the firmware
search root into /odm/firmware -- so from .226 onwards the request fails -22,
the container never loads, the codec stays uninitialised and the internal
speaker is silent:

    tfa98xx tfa98xx.6-0035: Firmware load for '../../odm/firmware/tfa98xx.cnt'
      refused, path contains '..' component
    tfa98xx_load_container(): request_firmware  rc=-22

The name comes from the vendor module, which we do not rebuild, so the kernel
side is the only place it can be fixed.

WHAT IT DOES. Adds name_is_confined_vendor_firmware(), which admits the two
fixed odm firmware roots and nothing else, rejects a name that keeps traversing
once past the root, and gates the refusal on it. Every other name is refused
exactly as before.

Credit: diagnosed and fixed first in WildKernels/OnePlus_KernelSU_SUSFS
(61c5d51, "feat(compat): add rule for MTK tfa98xx firmware dotdot exception",
their issue #287).

WHY THE SOC GATE IS NOT OPTIONAL. This widens a path-traversal guard, so it has
to reach the three MediaTek builds that need it and nothing else. Shape alone
does not say that: name_contains_dotdot() is in the Qualcomm sm8850 6.12 tree
and in AOSP android16-6.12 as well, so a tree-shape test on its own would relax
the guard fleet-wide. OP_SOC decides, the caller gates on it too, and an OP_SOC
this script cannot classify is an error rather than a silent widening.

Beyond that the guard is the published shape, not a sublevel number, so this
no-ops on a tree that predates name_contains_dotdot() and on the day the
exception arrives from OnePlus or upstream.
"""

import io
import os
import sys

REL = "drivers/base/firmware_loader/main.c"

MTK_SOC_PREFIXES = ("dimensity", "helio", "mediatek", "mt")

HELPER = '''
static bool name_is_confined_vendor_firmware(const char *name)
{
\tstatic const char * const allowed_roots[] = {
\t\t"../../odm/firmware/",
\t\t"../odm/firmware/",
\t};
\tsize_t i;

\tfor (i = 0; i < ARRAY_SIZE(allowed_roots); i++) {
\t\tsize_t len = strlen(allowed_roots[i]);

\t\tif (strncmp(name, allowed_roots[i], len) != 0)
\t\t\tcontinue;
\t\tif (strstr(name + len, "..") != NULL)
\t\t\treturn false;
\t\treturn true;
\t}

\treturn false;
}
'''

DEFINITION = "static bool name_contains_dotdot(const char *name)\n"
CALL_SITE = "\tif (name_contains_dotdot(name)) {\n"
PATCHED_CALL_SITE = (
    "\tif (name_contains_dotdot(name) &&\n"
    "\t    !name_is_confined_vendor_firmware(name)) {\n"
)
MARKER = "name_is_confined_vendor_firmware"


def fail(msg):
    print("::error::fix_mtk_firmware_dotdot: %s" % msg)
    return 1


def main():
    tree = os.environ.get("COMMON_KERNEL_FOLDER", "")
    if not tree or not os.path.isdir(os.path.join(tree, "drivers", "base")):
        return fail("COMMON_KERNEL_FOLDER=%r is not a kernel tree" % tree)

    print("::group::Fix MTK firmware dotdot exception")

    soc = os.environ.get("OP_SOC", "").strip().lower()
    if not soc:
        print("::endgroup::")
        return fail("OP_SOC is not set; refusing to widen the dotdot guard blind")
    if not soc.startswith(MTK_SOC_PREFIXES):
        print("   %s is not a MediaTek SoC, the dotdot guard stays as it is" % soc)
        print("::endgroup::")
        return 0

    path = os.path.join(tree, REL)
    if not os.path.isfile(path):
        print("   no %s, nothing to do" % REL)
        print("::endgroup::")
        return 0

    s = io.open(path, encoding="utf-8").read()

    if MARKER in s:
        print("   the odm firmware exception is already in this tree, nothing to do")
        print("::endgroup::")
        return 0
    if DEFINITION not in s:
        print("   this tree has no name_contains_dotdot(), nothing to do")
        print("::endgroup::")
        return 0

    if s.count(DEFINITION) != 1:
        print("::endgroup::")
        return fail("name_contains_dotdot() is defined %d times in %s"
                    % (s.count(DEFINITION), REL))
    if s.count(CALL_SITE) != 1:
        print("::endgroup::")
        return fail("expected one `if (name_contains_dotdot(name)) {` in %s, found %d"
                    % (REL, s.count(CALL_SITE)))

    # After name_contains_dotdot(), not before it: the doc comment above that
    # function belongs to it, and the helper is not what it describes.
    body = s.index(DEFINITION) + len(DEFINITION)
    end = s.find("\n}\n", body)
    if end < 0:
        print("::endgroup::")
        return fail("could not find the end of name_contains_dotdot() in %s" % REL)
    end += len("\n}\n")

    out = s[:end] + HELPER + s[end:]
    out = out.replace(CALL_SITE, PATCHED_CALL_SITE, 1)

    if out.count(MARKER) != 2 or CALL_SITE in out:
        print("::endgroup::")
        return fail("the odm firmware exception did not apply cleanly")

    io.open(path, "w", encoding="utf-8").write(out)
    print("   %s: ../odm/firmware/ and ../../odm/firmware/ admitted for %s" % (REL, soc))
    print("::endgroup::")
    return 0


if __name__ == "__main__":
    sys.exit(main())
