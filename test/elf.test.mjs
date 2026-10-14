import { test } from 'node:test';
import assert from 'node:assert/strict';

import { elfLoadAligns, is16kAligned, SIXTEEN_KB } from '../src/elf.mjs';

/** Build a minimal 64-bit little-endian ELF with one PT_LOAD header at `align`. */
export function makeElf(align) {
  const buf = Buffer.alloc(64 + 56);
  buf[0] = 0x7f;
  buf[1] = 0x45; // E
  buf[2] = 0x4c; // L
  buf[3] = 0x46; // F
  buf[4] = 2; // 64-bit
  buf[5] = 1; // little-endian
  buf.writeUInt16LE(2, 16); // e_type = EXEC
  buf.writeUInt16LE(0xb7, 18); // e_machine = AARCH64
  buf.writeBigUInt64LE(64n, 0x20); // e_phoff
  buf.writeUInt16LE(56, 0x36); // e_phentsize
  buf.writeUInt16LE(1, 0x38); // e_phnum
  buf.writeUInt32LE(1, 64); // PT_LOAD
  buf.writeBigUInt64LE(BigInt(align), 64 + 48); // p_align
  return buf;
}

test('reads p_align = 0x4000 as 16 KB aligned', () => {
  const aligns = elfLoadAligns(makeElf(0x4000));
  assert.deepEqual(aligns, [0x4000]);
  assert.equal(is16kAligned(aligns), true);
});

test('reads p_align = 0x1000 as NOT aligned', () => {
  const aligns = elfLoadAligns(makeElf(0x1000));
  assert.deepEqual(aligns, [0x1000]);
  assert.equal(is16kAligned(aligns), false);
  assert.equal(SIXTEEN_KB, 0x4000);
});

test('rejects non-ELF input', () => {
  assert.throws(() => elfLoadAligns(Buffer.from('not an elf file, definitely not')));
});
