#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const binaryPath = path.join(root, 'vendor', 'wa-rs');
const repo = 'vianarasyaaa/bot-wa-rust';

function isTermux() {
  return process.platform === 'android' ||
    Boolean(process.env.PREFIX &&
      process.env.PREFIX.includes('/com.termux/')) ||
    Boolean(process.env.ANDROID_ROOT);
}

function installWithCargo() {
  const check = spawnSync('cargo', ['--version'], { stdio: 'ignore' });

  if (check.error) {
    console.error('[wa-rs] Cargo belum tersedia.');
    console.error('[wa-rs] Jalankan: pkg install rust');
    process.exit(1);
  }

  const result = spawnSync('cargo', [
    'install',
    '--git',
    'https://github.com/' + repo,
    '--locked',
    '--force'
  ], { stdio: 'inherit' });

  if (result.error || result.status !== 0) {
    console.error('[wa-rs] Instalasi melalui Cargo gagal.');
    process.exit(result.status || 1);
  }
}

function download(url, destination, redirects = 6) {
  return new Promise((resolve, reject) => {
    https.get(url, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) &&
          response.headers.location) {
        response.resume();
        if (redirects <= 0) {
          return reject(new Error('Terlalu banyak redirect'));
        }
        return resolve(download(
          response.headers.location,
          destination,
          redirects - 1
        ));
      }

      if (response.statusCode !== 200) {
        response.resume();
        return reject(new Error('HTTP ' + response.statusCode));
      }

      fs.mkdirSync(path.dirname(destination), { recursive: true });
      const output = fs.createWriteStream(destination, { mode: 0o755 });
      response.pipe(output);
      output.on('finish', () => output.close(resolve));
      output.on('error', reject);
    }).on('error', reject);
  });
}

async function main() {
  if (isTermux()) {
    console.log('[wa-rs] Termux terdeteksi. Build native dengan Cargo...');
    installWithCargo();
    return;
  }

  if (process.platform !== 'linux' ||
      !['x64', 'arm64'].includes(process.arch)) {
    console.error('[wa-rs] Platform belum didukung: ' +
      process.platform + '/' + process.arch);
    process.exit(1);
  }

  const asset = 'wa-rs-linux-' + process.arch;

  try {
    console.log('[wa-rs] Mengunduh binary ' + asset + '...');
    await download(
      'https://github.com/' + repo +
      '/releases/latest/download/' + asset,
      binaryPath
    );
    fs.chmodSync(binaryPath, 0o755);
    console.log('[wa-rs] Instalasi selesai.');
  } catch (error) {
    console.error('[wa-rs] Download gagal: ' + error.message);
    console.error('[wa-rs] Pastikan GitHub Release sudah tersedia.');
    process.exit(1);
  }
}

main();
