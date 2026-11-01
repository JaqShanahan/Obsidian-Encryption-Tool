# Obsidian Vault Crypto Tool

A menu-driven command line tool that encrypts an Obsidian vault (your "Brain folder")
at rest, so your notes are unreadable if the vault is synced, backed up, or stolen.

File contents, file names, folder names, and the manifest that ties them together are
all encrypted. Obsidian sees nothing but garbage — open the vault while it is locked
and every note is an opaque blob.

## Features

- **Post-quantum hybrid encryption** — file contents are encrypted with AES-256-GCM,
  with the AES key wrapped by **ML-KEM-768** (NIST FIPS 203). Safe against harvest-now,
  decrypt-later attacks.
- **Filename and folder obfuscation** — every path component is XOR-encrypted with your
  32-byte key and encoded URL-safe, so note titles and folder structure leak nothing.
- **Encrypted manifest** — a `.vault_manifest` file (itself encrypted) maps the
  obfuscated names back to the originals. Nothing readable is left on disk.
- **Password-protected private key** — the ML-KEM private key can be locked with a
  password (Scrypt KDF + AES-256-GCM).
- **Auto-encrypt watchdog** — while the tool is running, it watches your vault and
  automatically encrypts it after 30 minutes of inactivity, but only when your key
  drive is plugged in.
- **Legacy support** — vaults encrypted with the older RSA-4096 format still decrypt;
  re-encrypt to convert them to ML-KEM-768.
- Touches only `.md` and image files (`.png .jpg .jpeg .gif .svg .webp .bmp`);
  the `.obsidian` folder is left alone.

## How it works

| Layer | Protection |
|---|---|
| File contents | AES-256-GCM, key encapsulated with ML-KEM-768 |
| File and folder names | XOR (32-byte key) + URL-safe base64 |
| Manifest (`.vault_manifest`) | Same hybrid encryption as file contents |
| Private key at rest | Optional password → Scrypt (N=2¹⁴, r=8, p=1) + AES-256-GCM |
| Legacy vaults | RSA-4096 + AES-256-GCM (decrypt only) |

## Installation

Requires Python 3.10+.

```bat
pip install -r requirements.txt
python obsidian_crypto.py
```

## First run

1. **Config → Set Brain folder path** — the Obsidian vault to protect.
2. **Config → Set Keys folder path** — where your key files live (any folder, ideally
   on a USB drive that is not always connected).
3. **Config → Generate new ML-KEM-768 keys** — creates `mlkem_private_key.bin`
   (secret, back it up) and `mlkem_public_key.bin`.
4. **Config → Generate new XOR key** — creates the 32-byte `xor_key.bin` used to
   obfuscate names. **Losing this file means losing your file names.**
5. **Encrypt** — locks the vault. **Decrypt** unlocks it.

The watchdog then keeps the vault locked automatically while the tool runs: if the
vault sits idle for 30 minutes and the key drive is present, it is re-encrypted.

## Configuration

The tool reads `config.json` next to the script (created automatically on first save).
Copy `config.example.json` to `config.json` to start from scratch:

```json
{
  "brain_folder": "",
  "private_key": "",
  "public_key": "",
  "xor_key": "",
  "mlkem_private_key": "",
  "mlkem_public_key": ""
}
```

All paths may be left empty to use the defaults (app folder). Keys are created for you
by the Config menu — you never have to edit this file by hand.

## Building the standalone executable

```bat
build.bat
```

This runs PyInstaller in onefile mode and produces `dist\obsidian_crypto.exe`.
The exe keeps `config.json` and key files next to itself, so the folder it lives in
is the tool's home directory. Rebuild any time after changing `obsidian_crypto.py`.

## Security notes

- **Never commit** `config.json`, `*.pem`, `mlkem_*.bin`, `xor_key.bin`, or
  `.vault_manifest` — `.gitignore` already excludes them.
- **Back up `mlkem_private_key.bin` and `xor_key.bin`.** Without both you cannot
  decrypt your vault. Without the private key the content is gone; without the XOR
  key the file names are gone.
- The ML-KEM-768 layer protects key exchange only; actual confidentiality comes from
  AES-256-GCM, which remains safe against quantum computers at 256-bit strength.
- This tool protects data **at rest**. It does nothing about malware or keyloggers on
  a machine where the vault is unlocked.

## License

MIT — see [LICENSE](LICENSE).
