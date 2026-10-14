import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc32 } from 'node:zlib';

import { checkArtifact, formatReport } from '../src/check.mjs';
import { makeElf } from './elf.test.mjs';

/** Minimal ZIP writer (stored, no compression) — just enough for tests. */
function makeZip(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const crc = crc32(f.data) >>> 0;
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(f.data.length, 18);
    lfh.writeUInt32LE(f.data.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    parts.push(lfh, nameBuf, f.data);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(f.data.length, 20);
    cd.writeUInt32LE(f.data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBuf);

    offset += lfh.length + nameBuf.length + f.data.length;
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

test('flags an unaligned arm64 lib', () => {
  const zip = makeZip([
    { name: 'base/lib/arm64-v8a/libgood.so', data: makeElf(0x4000) },
    { name: 'base/lib/arm64-v8a/libbad.so', data: makeElf(0x1000) },
  ]);
  const report = checkArtifact(zip);
  assert.equal(report.ok, false);
  assert.equal(report.totalLibs, 2);
  assert.equal(report.failures.length, 1);
  assert.equal(report.failures[0].abi, 'arm64-v8a');
  assert.match(formatReport(report), /FAIL/);
});

test('passes when all gating libs are 16 KB aligned', () => {
  const zip = makeZip([
    { name: 'base/lib/arm64-v8a/libgood.so', data: makeElf(0x4000) },
    { name: 'base/lib/arm64-v8a/libalso.so', data: makeElf(0x4000) },
  ]);
  const report = checkArtifact(zip);
  assert.equal(report.ok, true);
  assert.match(formatReport(report), /PASS/);
});

test('non-gating ABI (armeabi-v7a) unaligned does not fail the audit', () => {
  const zip = makeZip([
    { name: 'base/lib/armeabi-v7a/libv7.so', data: makeElf(0x1000) },
  ]);
  const report = checkArtifact(zip);
  assert.equal(report.failures.length, 0);
});
