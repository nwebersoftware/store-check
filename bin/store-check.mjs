#!/usr/bin/env node
import { readFileSync } from 'node:fs';

import { checkArtifact, formatReport } from '../src/check.mjs';

const path = process.argv[2];
if (!path || path === '-h' || path === '--help') {
  console.log('usage: store-check <app.aab|app.apk>');
  process.exit(path ? 0 : 2);
}

try {
  const report = checkArtifact(readFileSync(path));
  console.log(formatReport(report, path));
  process.exit(report.ok ? 0 : 1);
} catch (e) {
  console.error(`store-check: ${e.message}`);
  process.exit(2);
}
