import { elfLoadAligns, is16kAligned } from './elf.mjs';
import { readZip, readEntry } from './zip.mjs';

const LIB_RE = /(?:^|\/)lib\/([^/]+)\/([^/]+\.so)$/;
const GATING_ABIS = new Set(['arm64-v8a', 'x86_64']);

/** Audit a .aab/.apk buffer for the Android 15+ 16 KB page-size requirement. */
export function checkArtifact(buf) {
  const zip = readZip(buf);
  const libs = zip.entries
    .map((e) => ({ path: e.name, m: LIB_RE.exec(e.name) }))
    .filter((x) => x.m)
    .map((x) => ({ abi: x.m[1], name: x.m[2], path: x.path }));

  const byAbi = new Map();
  for (const lib of libs) {
    let aligns = [];
    let error = null;
    try {
      aligns = elfLoadAligns(readEntry(zip, lib.path));
    } catch (e) {
      error = e.message;
    }
    const aligned = error ? false : is16kAligned(aligns);
    const list = byAbi.get(lib.abi) ?? [];
    list.push({ name: lib.name, aligns, aligned, error });
    byAbi.set(lib.abi, list);
  }

  const abis = [...byAbi.entries()].map(([abi, ls]) => ({
    abi,
    libs: ls,
    gating: GATING_ABIS.has(abi),
    ok: ls.every((l) => l.aligned),
  }));

  const failures = abis.filter((a) => a.gating && !a.ok);
  return {
    ok: failures.length === 0 && abis.length > 0,
    abis,
    totalLibs: libs.length,
    failures,
  };
}

export function formatReport(report, label = '') {
  const out = [];
  out.push('store-check — 16 KB page-size audit');
  if (label) out.push(`artifact: ${label}`);
  out.push('');

  if (report.totalLibs === 0) {
    out.push('No native libraries found — nothing to check.');
    return out.join('\n');
  }

  for (const abi of report.abis) {
    out.push(`${abi.abi}${abi.gating ? '' : ' (not gating)'}`);
    for (const l of abi.libs) {
      if (l.error) {
        out.push(`  ✗ ${l.name}  (${l.error})`);
      } else if (l.aligned) {
        const hex = l.aligns.map((a) => `0x${a.toString(16)}`).join(', ');
        out.push(`  ✓ ${l.name}  (p_align ${hex})`);
      } else {
        const hex = l.aligns.map((a) => `0x${a.toString(16)}`).join(', ');
        out.push(`  ✗ ${l.name}  NOT 16 KB aligned (p_align ${hex})`);
      }
    }
    out.push('');
  }

  out.push(
    report.ok
      ? 'PASS — every 64-bit native lib is 16 KB aligned.'
      : 'FAIL — a 64-bit native lib is not 16 KB aligned. Google Play will reject this on Android 15+.',
  );
  return out.join('\n');
}
