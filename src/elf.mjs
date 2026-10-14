// Minimal ELF parser: read the program headers we care about for Android's 16 KB rule.
// 64-bit only (arm64 / x86_64) — which is all that matters here.
//
// Two things matter for 16 KB compliance:
//   1. every PT_LOAD `p_align` must be >= 16 KB, and
//   2. the end of PT_GNU_RELRO (p_vaddr + p_memsz) must be congruent to 0 mod 16 KB.
// A library can pass (1) and still fail (2) — which is why the official scripts can say
// "ELF Verification Successful" while Google Play still rejects the upload.

export const SIXTEEN_KB = 0x4000;
export const PT_LOAD = 1;
export const PT_GNU_RELRO = 0x6474e552;

function readHeaders(buf) {
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
  return { buf, u16, u32, u64, phoff: u64(0x20), phentsize: u16(0x36), phnum: u16(0x38) };
}

/** { loadAligns: number[], relro: [{ end, aligned }] } for a 64-bit ELF. */
export function elfPageInfo(buf) {
  const { u16, u32, u64, phoff, phentsize, phnum } = readHeaders(buf);
  void u16;
  const loadAligns = [];
  const relro = [];
  for (let i = 0; i < phnum; i += 1) {
    const off = phoff + i * phentsize;
    if (off + 56 > buf.length) break;
    const pType = u32(off);
    if (pType === PT_LOAD) {
      loadAligns.push(u64(off + 48)); // p_align
    } else if (pType === PT_GNU_RELRO) {
      const end = u64(off + 16) + u64(off + 40); // p_vaddr + p_memsz
      relro.push({ end, aligned: end % SIXTEEN_KB === 0 });
    }
  }
  return { loadAligns, relro };
}

/** Back-compat: just the PT_LOAD alignments. */
export function elfLoadAligns(buf) {
  return elfPageInfo(buf).loadAligns;
}

export function is16kAligned(aligns) {
  return aligns.length > 0 && aligns.every((a) => a >= SIXTEEN_KB);
}
