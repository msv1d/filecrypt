# FileCrypt

Interactive file encryption with **Argon2id** (key derivation) and **ChaCha20-Poly1305** (authenticated encryption).

Drag a file into the terminal: the tool auto-detects encrypt/decrypt. Password input is hidden and never touches shell history.

License: **GNU AGPL v3 or later** — see `LICENSE`.

## Features

- Drag & drop, no flags to remember.
- Auto mode detection via file header.
- Streaming in 8 MiB chunks, low memory on multi-GB files.
- Colored output, progress bar with percent, sizes and speed.
- CLI mode: batch files, `--encrypt` / `--decrypt`, `-o`, `-y`, `-k`.
- Detects wrong passwords, tampering, truncation and chunk reordering.
- Atomic output, never overwrites without asking.

## Install

```bash
pip install filecrypt-argon2id
filecrypt --help
```

Or from source:

```bash
git clone https://github.com/msv1d/filecrypt.git
cd filecrypt
pip install -r requirements.txt
python filecrypt.py
```

## Usage

Interactive (simplest):

```bash
python filecrypt.py
```

Encrypted files get `.obf2id`: `photo.jpg` -> `photo.jpg.obf2id` and back.

With arguments:

```bash
# auto mode, one or more files
python filecrypt.py report.pdf backup.zip

# forced modes
python filecrypt.py -e secret.docx
python filecrypt.py -d secret.docx.obf2id

# custom output, overwrite without asking, keep source
python filecrypt.py -e input.bin -o output.obf2id -y -k

python filecrypt.py --help
python filecrypt.py --version
```

Exit code: `0` on success, `1` if any file failed.

## Format

| Parameter | Value |
|---|---|
| KDF | Argon2id, 3 iterations, 64 MiB, 4 lanes |
| Cipher | ChaCha20-Poly1305, 256-bit key |
| Chunk | 8 MiB plaintext + 16-byte tag |
| Header | 58 bytes, used as AAD for every chunk |
| Nonce | prefix(7) + counter(4) + last(1), STREAM construction |

Header stores Argon2 parameters, so they can be raised later. Untrusted headers are capped: time <= 10, memory <= 256 MiB, parallelism <= 8, chunk <= 64 MiB. See the docstring in `filecrypt.py`.

## Security notes

- Strength depends on the password. Use a long passphrase (20+ chars).
- Wrong password fails on the first chunk; later failures mean modification.
- Deleting the original is a plain delete, not a secure wipe.
- Python cannot reliably erase secrets from memory.
- Not independently audited.

## License

Copyright (C) 2026 FileCrypt contributors.

Free software under **GNU Affero General Public License v3 or later**. Full text in `LICENSE`: you may use, modify and share it; modifications stay under AGPL, and network use of a modified version requires offering the source to users.
