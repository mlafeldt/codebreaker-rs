# Unpack ps2-packer N2E (UCL NRV2E, 8-bit) ELF into a plain ELF32 MIPS LE.
import struct, sys
src_path, out_path = sys.argv[1], sys.argv[2]
f = open(src_path, 'rb').read()
e_entry, e_phoff = struct.unpack_from('<II', f, 0x18)
p_off, p_vaddr = struct.unpack_from('<II', f, e_phoff + 4)
v2o = lambda v: v - p_vaddr + p_off
hdr = struct.unpack_from('<I', f, v2o(e_entry - 8 + 4))[0]
oep, size, bss, dest = struct.unpack_from('<IIII', f, v2o(hdr))
src = f; ilen = v2o(hdr) + 16
dst = bytearray(); bb = 0
def getbit():
    global bb, ilen
    if bb & 0x7f:
        bb = (bb * 2) & 0x1ff
    else:
        bb = src[ilen] * 2 + 1; ilen += 1
    return (bb >> 8) & 1
last_m_off = 1
while True:
    while getbit():
        dst.append(src[ilen]); ilen += 1
    m_off = 1
    while True:
        m_off = m_off * 2 + getbit()
        if getbit(): break
        m_off = (m_off - 1) * 2 + getbit()
    if m_off == 2:
        m_off = last_m_off; m_len = getbit()
    else:
        m_off = ((m_off - 3) * 256 + src[ilen]) & 0xffffffff; ilen += 1
        if m_off == 0xffffffff: break
        m_len = (m_off ^ 0xffffffff) & 1
        m_off >>= 1; m_off += 1; last_m_off = m_off
    if m_len: m_len = 1 + getbit()
    elif getbit(): m_len = 3 + getbit()
    else:
        m_len += 1
        while True:
            m_len = m_len * 2 + getbit()
            if getbit(): break
        m_len += 3
    m_len += m_off > 0x500
    p = len(dst) - m_off
    for i in range(m_len + 1):
        dst.append(dst[p + i])
print(f"oep={oep:#x} dest={dest:#x} hdr_size={size:#x} bss={bss:#x} out={len(dst):#x} consumed={ilen:#x}/{len(f):#x}")
ehdr = struct.pack('<4sBBBB8sHHIIIIIHHHHHH', b'\x7fELF', 1, 1, 1, 0, b'\0'*8, 2, 8, 1, oep, 52, 0, 0, 52, 32, 1, 0, 0, 0)
# The stub zero-fills bss + 1 bytes starting at dest + size (not at the end of
# the decompressed data), so memsz covers that whole range.
phdr = struct.pack('<IIIIIIII', 1, 0x1000, dest, dest, len(dst), size + bss + 1, 7, 0x10)
out = ehdr + phdr
out += b'\0' * (0x1000 - len(out)) + bytes(dst)
open(out_path, 'wb').write(out)
