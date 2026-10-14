import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc32 } from 'node:zlib';

import { checkArtifact, formatReport } from '../src/check.mjs';
import { readZip, entryDataOffset } from '../src/zip.mjs';
import { makeElf } from './elf.test.mjs';

/**
 * ZIP writer that can pad an entry's extra field so its *data* lands on a 16 KB boundary —
 * i.e. what `zipalign -P 16` produces. Stored (uncompressed) entries only.
 */
function makeZip(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const crc = crc32(f.data) >>> 0;
    let extraLen = 0;
    if (f.align16k) {
      const base = offset + 30 + nameBuf.length;
      let need = (0x4000 - (base % 0x4000)) % 0x4000;
      if (need < 4) need += 0x4000;
      extraLen = need;
    }
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(f.data.length, 18);
    lfh.writeUInt32LE(f.data.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(extraLen, 28);
    parts.push(lfh, nameBuf, Buffer.alloc(extraLen), f.data);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(f.data.length, 20);
    cd.writeUInt32LE(f.data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42); // extra length (central) stays 0
    central.push(cd, nameBuf);

    offset += lfh.length + nameBuf.length + extraLen + f.data.length;
  }
  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, centralBuf, eocd]);
}

const manifest = { name: 'AndroidManifest.xml', data: Buffer.from('<manifest/>') };
const ELF16K = makeElf(0x4000);

test('a stored, 16 KB-aligned .so in an APK passes', () => {
  const apk = makeZip([manifest, { name: 'lib/arm64-v8a/libx.so', data: ELF16K, align16k: true }]);
  const report = checkArtifact(apk);
  assert.equal(report.isApk, true);
  assert.equal(report.zipFailures.length, 0);
  assert.equal(report.ok, true);
});

test('a stored but unaligned .so in an APK fails the zip check', () => {
  const apk = makeZip([manifest, { name: 'lib/arm64-v8a/libx.so', data: ELF16K }]);
  const report = checkArtifact(apk);
  assert.equal(report.isApk, true);
  assert.equal(report.zipFailures.length, 1);
  assert.equal(report.ok, false);
  assert.match(formatReport(report), /ZIP ALIGNMENT/);
});

test('the zip check does not apply to an AAB', () => {
  const aab = makeZip([{ name: 'base/lib/arm64-v8a/libx.so', data: ELF16K }]);
  const report = checkArtifact(aab);
  assert.equal(report.isApk, false);
  assert.equal(report.zipFailures.length, 0);
  assert.equal(report.ok, true);
});

test('data offsets are computed from the local header (validation)', () => {
  const apk = makeZip([manifest, { name: 'lib/arm64-v8a/libx.so', data: ELF16K, align16k: true }]);
  const zip = readZip(apk);
  const entry = zip.entries.find((e) => e.name === 'lib/arm64-v8a/libx.so');
  const off = entryDataOffset(zip, entry);
  assert.equal(off % 0x4000, 0, 'padded entry should land on a 16 KB boundary');
  // and the ELF really is at that offset
  assert.equal(apk.readUInt32LE(off), 0x464c457f);
});
