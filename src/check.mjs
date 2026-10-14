import { elfPageInfo, is16kAligned } from './elf.mjs';
import { readZip, readEntry, entryDataOffset } from './zip.mjs';

const LIB_RE = /(?:^|\/)lib\/([^/]+)\/([^/]+\.so)$/;
const GATING_ABIS = new Set(['arm64-v8a', 'x86_64']);
const ZIP_ALIGN = 0x4000;

/** Audit a .aab/.apk buffer for the Android 15+ 16 KB page-size requirement. */
export function checkArtifact(buf, opts = {}) {
  const zip = readZip(buf);

  // An APK carries lib/<abi>/*.so with the manifest at the zip root; an AAB nests everything
  // under base/. The distinction matters: an APK's stored .so entries must ALSO be zip-aligned
  // (`zipalign -P 16`), because the loader mmaps them straight out of the file.
  const isApk = zip.entries.some((e) => e.name === 'AndroidManifest.xml');

  const libs = zip.entries
    .map((e) => ({ entry: e, path: e.name, m: LIB_RE.exec(e.name) }))
    .filter((x) => x.m)
    .map((x) => ({ abi: x.m[1], name: x.m[2], path: x.path, entry: x.entry }));

  const byAbi = new Map();
  for (const lib of libs) {
    let aligns = [];
    let relro = [];
    let error = null;
    try {
      const info = elfPageInfo(readEntry(zip, lib.path));
      aligns = info.loadAligns;
      relro = info.relro;
    } catch (e) {
      error = e.message;
    }

    let zipInfo = null;
    if (isApk) {
      try {
        const offset = entryDataOffset(zip, lib.entry);
        zipInfo = {
          stored: lib.entry.method === 0,
          offset,
          aligned: offset % ZIP_ALIGN === 0,
        };
      } catch {
        zipInfo = null;
      }
    }

    // The hard requirement (and what Google Play checks) is PT_LOAD alignment.
    const aligned = error ? false : is16kAligned(aligns);
    const list = byAbi.get(lib.abi) ?? [];
    list.push({ name: lib.name, aligns, relro, aligned, error, zip: zipInfo });
    byAbi.set(lib.abi, list);
  }

  const abis = [...byAbi.entries()].map(([abi, ls]) => ({
    abi,
    libs: ls,
    gating: GATING_ABIS.has(abi),
    ok: ls.every((l) => l.aligned),
  }));

  const failures = abis.filter((a) => a.gating && !a.ok);

  // APK only: a stored (uncompressed) .so whose data isn't 16 KB-aligned can't be mapped on a
  // 16 KB-page device — that's what `zipalign -P 16` exists to guarantee.
  const zipFailures = [];
  const zipCompressed = [];
  if (isApk) {
    for (const abi of abis) {
      for (const l of abi.libs) {
        if (!l.zip) continue;
        if (!l.zip.stored) zipCompressed.push({ abi: abi.abi, name: l.name });
        else if (!l.zip.aligned) zipFailures.push({ abi: abi.abi, name: l.name, offset: l.zip.offset });
      }
    }
  }

  // Informational, opt-in: LOAD is fine but the PT_GNU_RELRO end isn't 16 KB aligned.
  // Deliberately OFF by default — in practice nearly every real-world lib has an unaligned
  // RELRO end (including libc++_shared.so in Play-approved apps), so it is not a useful
  // default signal. It's here for the case where Play rejects despite aligned LOAD segments.
  const relroNotes = [];
  if (opts.relro) {
    for (const abi of abis) {
      for (const l of abi.libs) {
        if (l.error || !l.aligned) continue;
        const bad = (l.relro ?? []).filter((r) => !r.aligned);
        if (bad.length) relroNotes.push({ abi: abi.abi, name: l.name, end: bad[0].end });
      }
    }
  }

  return {
    ok: failures.length === 0 && zipFailures.length === 0 && abis.length > 0,
    isApk,
    abis,
    totalLibs: libs.length,
    failures,
    zipFailures,
    zipCompressed,
    relroNotes,
  };
}

export function formatReport(report, label = '') {
  const out = [];
  out.push(`store-check — 16 KB page-size audit${report.isApk ? ' (APK)' : ''}`);
  if (label) out.push(`artifact: ${label}`);
  out.push('');

  if (report.totalLibs === 0) {
    out.push('No native libraries found — nothing to check.');
    return out.join('\n');
  }

  for (const abi of report.abis) {
    out.push(`${abi.abi}${abi.gating ? '' : ' (not gating)'}`);
    for (const l of abi.libs) {
      const mark = !abi.gating ? '·' : l.aligned ? '✓' : '✗';
      const hex = l.aligns.map((a) => `0x${a.toString(16)}`).join(', ');
      const zipNote = l.zip && !l.zip.stored ? ', compressed' : '';
      if (l.error) {
        out.push(`  ${mark} ${l.name}  (${l.error})`);
      } else if (l.aligned) {
        out.push(`  ${mark} ${l.name}  (p_align ${hex}${zipNote})`);
      } else {
        out.push(`  ${mark} ${l.name}  NOT 16 KB aligned (p_align ${hex})`);
      }
    }
    out.push('');
  }

  if (report.zipFailures.length) {
    out.push(`ZIP ALIGNMENT — ${report.zipFailures.length} stored .so entr${report.zipFailures.length === 1 ? 'y' : 'ies'} not 16 KB aligned:`);
    for (const z of report.zipFailures.slice(0, 8)) {
      out.push(`  ${z.abi}/${z.name}  (data offset 0x${z.offset.toString(16)})`);
    }
    if (report.zipFailures.length > 8) out.push(`  …and ${report.zipFailures.length - 8} more`);
    out.push('  Fix: run `zipalign -P 16` on the APK (or build with useLegacyPackaging=false).', '');
  } else if (report.zipCompressed.length) {
    out.push(
      `NOTE — ${report.zipCompressed.length} .so entr${report.zipCompressed.length === 1 ? 'y is' : 'ies are'} compressed in the APK.`,
      '  The loader has to extract those; for 16 KB devices the recommended packaging is',
      '  uncompressed + aligned (useLegacyPackaging=false, then `zipalign -P 16`).',
      '',
    );
  }

  if (report.relroNotes?.length) {
    out.push(
      `NOTE — ${report.relroNotes.length} lib(s) have a PT_GNU_RELRO end that is not 16 KB aligned:`,
    );
    for (const n of report.relroNotes.slice(0, 8)) {
      out.push(`  ${n.abi}/${n.name}  (end 0x${n.end.toString(16)})`);
    }
    if (report.relroNotes.length > 8) out.push(`  …and ${report.relroNotes.length - 8} more`);
    out.push(
      '  LOAD segments are aligned, which is the documented requirement and what Play checks.',
      '  If Play still rejects, ask the vendor to rebuild with -Wl,-z,max-page-size=16384.',
      '',
    );
  }

  out.push(
    report.ok
      ? 'PASS — every 64-bit native lib is 16 KB aligned.'
      : 'FAIL — a 64-bit native lib is not 16 KB aligned. Google Play will reject this on Android 15+.',
  );
  return out.join('\n');
}
