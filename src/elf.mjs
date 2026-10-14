// Minimal ELF parser: return the p_align of each PT_LOAD program header.
// 64-bit only (arm64 / x86_64) — which is all that matters for Android's 16 KB rule.

export function elfLoadAligns(buf) {
  if (buf.length < 64) {
    throw new Error('ELF too small');
  }
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) {
    throw new Error('not an ELF file');
  }
  const eiClass = buf[4]; // 1 = 32-bit, 2 = 64-bit
  const eiData = buf[5]; // 1 = little-endian, 2 = big-endian
  if (eiClass !== 2) {
    throw new Error('only 64-bit ELF supported');
  }
  const le = eiData === 1;
  const u16 = (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const u64 = (o) => Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));

  const phoff = u64(0x20);
  const phentsize = u16(0x36);
  const phnum = u16(0x38);

  const aligns = [];
  for (let i = 0; i < phnum; i += 1) {
    const off = phoff + i * phentsize;
    if (off + 56 > buf.length) break;
    const pType = u32(off); // PT_LOAD = 1
    if (pType === 1) {
      aligns.push(u64(off + 48)); // p_align
    }
  }
  return aligns;
}

export const SIXTEEN_KB = 0x4000;

export function is16kAligned(aligns) {
  return aligns.length > 0 && aligns.every((a) => a >= SIXTEEN_KB);
}
