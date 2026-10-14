// Minimal, dependency-free ZIP reader (enough to pull entries out of an AAB/APK).
// Handles stored (0) and deflate (8) entries, plus ZIP64 EOCD/sizes.
import { inflateRawSync } from 'node:zlib';

const EOCD = 0x06054b50;
const CDH = 0x02014b50;
const LFH = 0x04034b50;
const Z64_LOC = 0x07064b50;
const Z64_EOCD = 0x06064b50;

export function readZip(buf) {
  // locate End Of Central Directory (scan backwards over the comment window)
  let eocd = -1;
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip file (no EOCD)');

  let total = buf.readUInt16LE(eocd + 10);
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  // ZIP64 EOCD locator sits right before the EOCD
  const loc = eocd - 20;
  if (loc >= 0 && buf.readUInt32LE(loc) === Z64_LOC) {
    const z64 = Number(buf.readBigUInt64LE(loc + 8));
    if (buf.readUInt32LE(z64) === Z64_EOCD) {
      total = Number(buf.readBigUInt64LE(z64 + 32));
      cdSize = Number(buf.readBigUInt64LE(z64 + 40));
      cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
    }
  }

  const entries = [];
  let p = cdOffset;
  for (let n = 0; n < total; n += 1) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CDH) break;
    const method = buf.readUInt16LE(p + 10);
    let compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);

    if (compSize === 0xffffffff || localOff === 0xffffffff || uncompSize === 0xffffffff) {
      let e = p + 46 + nameLen;
      const end = e + extraLen;
      while (e + 4 <= end) {
        const tag = buf.readUInt16LE(e);
        const size = buf.readUInt16LE(e + 2);
        if (tag === 0x0001) {
          let q = e + 4;
          if (uncompSize === 0xffffffff) q += 8;
          if (compSize === 0xffffffff) {
            compSize = Number(buf.readBigUInt64LE(q));
            q += 8;
          }
          if (localOff === 0xffffffff) {
            localOff = Number(buf.readBigUInt64LE(q));
            q += 8;
          }
        }
        e += 4 + size;
      }
    }

    entries.push({ name, method, compSize, localOff });
    p += 46 + nameLen + extraLen + commentLen;
  }

  return { buf, entries };
}

/** Byte offset of an entry's stored data (past the local header + name + extra). */
export function entryDataOffset(zip, entry) {
  const lh = entry.localOff;
  if (zip.buf.readUInt32LE(lh) !== LFH) throw new Error('bad local file header');
  const nameLen = zip.buf.readUInt16LE(lh + 26);
  const extraLen = zip.buf.readUInt16LE(lh + 28);
  return lh + 30 + nameLen + extraLen;
}

export function readEntry(zip, name) {
  const e = zip.entries.find((x) => x.name === name);
  if (!e) return null;
  const { buf } = zip;
  const lh = e.localOff;
  if (buf.readUInt32LE(lh) !== LFH) throw new Error(`bad local header for ${name}`);
  const nameLen = buf.readUInt16LE(lh + 26);
  const extraLen = buf.readUInt16LE(lh + 28);
  const start = lh + 30 + nameLen + extraLen;
  const data = buf.subarray(start, start + e.compSize);
  if (e.method === 0) return Buffer.from(data);
  if (e.method === 8) return inflateRawSync(data);
  throw new Error(`unsupported compression method ${e.method} for ${name}`);
}
