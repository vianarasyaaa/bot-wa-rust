#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const bundled = path.resolve(__dirname, '../vendor/wa-rs');
const cargo = path.join(
  os.homedir(),
  '.cargo',
  'bin',
  process.platform === 'win32' ? 'wa-rs.exe' : 'wa-rs'
);

const binary = fs.existsSync(bundled) ? bundled : cargo;

if (!fs.existsSync(binary)) {
  console.error('[wa-rs] Binary tidak ditemukan. Coba instal ulang package.');
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), {
  stdio: 'inherit'
});

if (result.error) {
  console.error('[wa-rs] Gagal menjalankan: ' + result.error.message);
  process.exit(1);
}

process.exit(result.status === null ? 1 : result.status);
