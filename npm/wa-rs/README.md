# WA-RS npm installer

Install globally:

```bash
npm install -g @rasya6162/wa-rs
```

Run:

```bash
wa-rs
```

Linux x64 and ARM64 download the native executable from GitHub Releases.

Android/Termux builds the native executable using Cargo:

```bash
pkg install nodejs rust -y
npm install -g @rasya6162/wa-rs
```

Keep the local `auth/` directory private. It contains account credentials
and session data. Never publish credentials or Signal session data.

WA-RS is experimental and does not claim complete WhatsApp protocol coverage.

Project: https://github.com/vianarasyaaa/bot-wa-rust
