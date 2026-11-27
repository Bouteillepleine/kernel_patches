# usage: patch_arb.py STOCK.ko OUT.ko | patch_arb.py --verify FILE.ko
# Stub qcom_scm_update_rollback_version() in a stock qcom-scm.ko: keep its PACIASP landing pad,
# then AUTIASP; MOV W0,#0; RET. Every other byte stays stock. Refuses to touch anything unexpected.
import sys, struct
verify = sys.argv[1] == '--verify'
src = sys.argv[2] if verify else sys.argv[1]
dst = None if verify else sys.argv[2]
d = bytearray(open(src, 'rb').read())
shoff, = struct.unpack_from('<Q', d, 0x28); es, n, si = struct.unpack_from('<HHH', d, 0x3a)
sh = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * es) for i in range(n)]
so = sh[si][4]; nm = lambda o: d[so + o:d.index(b'\0', so + o)].decode()
sym = next(s for s in sh if nm(s[0]) == '.symtab'); strt = sh[sym[6]]
fn = None
for i in range(sym[5] // 24):
    no, info, oth, shn, val, sz = struct.unpack_from('<IBBHQQ', d, sym[4] + i * 24)
    if d[strt[4] + no:d.index(b'\0', strt[4] + no)] == b'qcom_scm_update_rollback_version' and info & 0xf == 2:
        fn = (shn, val, sz)
assert fn, 'symbol not found'
shn, val, sz = fn; text = sh[shn]; off = text[4] + val
PACIASP, AUTIASP, MOV_W0_0, RET = 0xd503233f, 0xd50323bf, 0x52800000, 0xd65f03c0
if verify:
    ok = struct.unpack_from('<IIII', d, off) == (PACIASP, AUTIASP, MOV_W0_0, RET)
    print('stubbed' if ok else 'NOT stubbed'); sys.exit(0 if ok else 1)
assert struct.unpack_from('<I', d, off)[0] == PACIASP, 'first insn is not PACIASP'
# no relocation may land in the 12 patched bytes
for s in sh:
    if s[1] == 4 and s[7] == shn:
        for j in range(s[5] // 24):
            r_off, r_info, r_add = struct.unpack_from('<QQq', d, s[4] + j * 24)
            assert not (val + 4 <= r_off < val + 16), f'relocation at +{r_off - val:#x} inside patch'
struct.pack_into('<III', d, off + 4, AUTIASP, MOV_W0_0, RET)
open(dst, 'wb').write(d)
print(f'patched {sz}-byte qcom_scm_update_rollback_version at file+{off:#x}')
