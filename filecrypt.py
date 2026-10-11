#!/usr/bin/env python3
"""FileCrypt - file encryption with Argon2id + ChaCha20-Poly1305.

Usage:
    python filecrypt.py [FILE ...] [options]
    python filecrypt.py              # interactive drag & drop mode

File format (big-endian):
    magic 25B | version 1B | time 1B | memory 4B | parallelism 1B |
    chunk size 4B | salt 16B | nonce prefix 7B (= 59B header) |
    chunks: ciphertext + 16B tag. Header is AAD for every chunk.

License: GNU AGPL v3 or later, see LICENSE.
"""
import argparse
import getpass
import os
import shlex
import struct
import sys
import tempfile
import time
from typing import BinaryIO, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__version__ = "1.0"

# Constants
MAGIC = b"msv1dArgon2idObfuscation"
FORMAT_VERSION = 1
EXT = ".obf2id"

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MiB in KiB
ARGON2_PARALLELISM = 4
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 7
KEY_LEN = 32
TAG_SIZE = 16
CHUNK_SIZE = 8 * 1024 * 1024  # plaintext per chunk
PROGRESS_MIN_SIZE = 8 * 1024 * 1024  # show progress above this size
MIN_PASSWORD_LEN = 8

HEADER_FMT = ">%dsBBIBI%ds%ds" % (len(MAGIC), SALT_SIZE, NONCE_PREFIX_SIZE)
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Header sanity limits (DoS protection for untrusted files)
MAX_TIME_COST = 10
MAX_MEMORY_COST = 262144  # 256 MiB in KiB
MAX_PARALLELISM = 8
MAX_CHUNK_SIZE = 64 * 1024 * 1024


class CryptoError(Exception):
    pass


class WrongPassword(CryptoError):
    def __init__(self) -> None:
        super().__init__("Wrong password (or the file is corrupted).")


# Terminal colors
def _enable_windows_ansi() -> None:
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 4)
        except Exception:
            pass


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_enable_windows_ansi()
_USE_COLOR = _colors_enabled()


class C:
    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""
    RED = "\033[91m" if _USE_COLOR else ""
    GREEN = "\033[92m" if _USE_COLOR else ""
    YELLOW = "\033[93m" if _USE_COLOR else ""
    CYAN = "\033[96m" if _USE_COLOR else ""


def ok(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.RED}[-]{C.RESET} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def info(msg: str) -> None:
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def dim(msg: str) -> None:
    print(f"{C.DIM}{msg}{C.RESET}")


def banner() -> None:
    line = "=" * 58
    print(f"{C.CYAN}{line}{C.RESET}")
    print(f"  {C.BOLD}FileCrypt {__version__}{C.RESET}{C.DIM}  -  Argon2id + ChaCha20-Poly1305{C.RESET}")
    print(f"  {C.DIM}Licensed under GNU AGPL v3 (see LICENSE){C.RESET}")
    print(f"{C.CYAN}{line}{C.RESET}")


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024.0:
            return f"{n:.1f} {unit}" if n < 100 else f"{n:.0f} {unit}"
    return f"{n:.0f} PB"


class Progress:
    WIDTH = 28

    def __init__(self, total: int) -> None:
        self.total = total
        self.active = total >= PROGRESS_MIN_SIZE
        self._t0 = time.monotonic()
        self._last = ""

    def update(self, done: int) -> None:
        if not self.active:
            return
        total = max(self.total, 1)
        frac = min(1.0, done / total)
        filled = int(frac * self.WIDTH)
        bar = "#" * filled + "-" * (self.WIDTH - filled)
        elapsed = max(time.monotonic() - self._t0, 1e-6)
        speed = done / elapsed
        line = (f"\r    {C.CYAN}{bar}{C.RESET} {frac * 100:5.1f}%  "
                f"{human_size(done)}/{human_size(total)}  {human_size(int(speed))}/s")
        key = f"{filled}-{int(frac * 100)}"
        if key != self._last:
            print(line, end="", flush=True)
            self._last = key

    def finish(self) -> None:
        if self.active:
            print()


# Crypto
def derive_key(password: str, salt: bytes, time_cost: int,
               memory_cost: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def make_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def is_encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _open_temp(dst: str) -> Tuple[BinaryIO, str]:
    parent = os.path.dirname(os.path.abspath(dst)) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, suffix=".tmp")
    return os.fdopen(fd, "wb"), tmp


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def encrypt_file(src: str, dst: str, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    prefix = os.urandom(NONCE_PREFIX_SIZE)
    header = struct.pack(HEADER_FMT, MAGIC, FORMAT_VERSION, ARGON2_TIME_COST,
                         ARGON2_MEMORY_COST, ARGON2_PARALLELISM, CHUNK_SIZE,
                         salt, prefix)
    aead = ChaCha20Poly1305(derive_key(password, salt, ARGON2_TIME_COST,
                                       ARGON2_MEMORY_COST, ARGON2_PARALLELISM))
    total = os.path.getsize(src)
    progress = Progress(total)

    out, tmp = _open_temp(dst)
    try:
        with open(src, "rb") as fin, out:
            out.write(header)
            buf, counter, done = fin.read(CHUNK_SIZE), 0, 0
            while True:
                nxt = fin.read(CHUNK_SIZE)  # lookahead for last flag
                last = not nxt
                out.write(aead.encrypt(make_nonce(prefix, counter, last), buf, header))
                done += len(buf)
                progress.update(done)
                if last:
                    break
                buf, counter = nxt, counter + 1
        progress.finish()
        os.replace(tmp, dst)
    except (Exception, KeyboardInterrupt):
        _remove_quietly(tmp)
        progress.finish()
        raise


def decrypt_file(src: str, dst: str, password: str) -> None:
    total = os.path.getsize(src)
    with open(src, "rb") as fin:
        header = fin.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise CryptoError("File is corrupted (truncated header).")
        magic, version, time_cost, memory_cost, parallelism, chunk, salt, prefix = \
            struct.unpack(HEADER_FMT, header)
        if magic != MAGIC:
            raise CryptoError("Not a FileCrypt file.")
        if version != FORMAT_VERSION:
            raise CryptoError(f"Unsupported format version: {version}.")
        if not (1 <= time_cost <= MAX_TIME_COST
                and 8 <= memory_cost <= MAX_MEMORY_COST
                and 1 <= parallelism <= MAX_PARALLELISM
                and 1 <= chunk <= MAX_CHUNK_SIZE):
            raise CryptoError("Invalid header parameters.")

        aead = ChaCha20Poly1305(derive_key(password, salt, time_cost,
                                           memory_cost, parallelism))
        enc_chunk = chunk + TAG_SIZE
        progress = Progress(total)

        out, tmp = _open_temp(dst)
        try:
            with out:
                buf, counter, done = fin.read(enc_chunk), 0, HEADER_SIZE
                while True:
                    if len(buf) < TAG_SIZE:
                        raise CryptoError("File is corrupted or truncated.")
                    nxt = fin.read(enc_chunk)  # lookahead for last flag
                    last = not nxt
                    try:
                        out.write(aead.decrypt(make_nonce(prefix, counter, last), buf, header))
                    except InvalidTag:
                        if counter == 0:
                            raise WrongPassword()
                        raise CryptoError("File was modified, corrupted or truncated.")
                    done += len(buf)
                    progress.update(done)
                    if last:
                        break
                    buf, counter = nxt, counter + 1
            progress.finish()
            os.replace(tmp, dst)
        except (Exception, KeyboardInterrupt):
            _remove_quietly(tmp)
            progress.finish()
            raise


# UI
def parse_dropped_path(raw: str) -> str:
    # Handles quotes, file:// URIs and the "& " PowerShell prefix.
    s = raw.strip()
    if s.startswith("& "):
        s = s[2:].strip()
    if s.lower().startswith("file://"):
        s = unquote(urlparse(s).path)
        if os.name == "nt" and len(s) > 2 and s[0] == "/" and s[2] == ":":
            s = s[1:]
    elif os.name == "nt":
        s = s.strip("\"'")
    else:
        try:
            parts = shlex.split(s)
            if len(parts) == 1:
                s = parts[0]
        except ValueError:
            s = s.strip("\"'")
    return os.path.expanduser(s)


def ask_yes_no(question: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"{C.YELLOW}[?]{C.RESET} {question} [{hint}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def free_name(path: str) -> str:
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{base} ({i}){ext}"):
        i += 1
    return f"{base} ({i}){ext}"


def choose_output(path: str, auto_yes: bool = False) -> str:
    if os.path.exists(path):
        warn(f"File already exists: {path}")
        if auto_yes or ask_yes_no("Overwrite it?", default=False):
            return path
        path = free_name(path)
        info(f"Saving as: {path}")
    return path


def password_strength(password: str) -> str:
    n = len(password)
    if n < 12:
        return f"{C.YELLOW}medium{C.RESET}"
    if n < 20:
        return f"{C.GREEN}strong{C.RESET}"
    return f"{C.GREEN}excellent{C.RESET}"


def ask_new_password() -> str:
    while True:
        password = getpass.getpass("Choose a password (hidden): ")
        if not password:
            err("Password cannot be empty.")
            continue
        if len(password) < MIN_PASSWORD_LEN:
            warn(f"Password is shorter than {MIN_PASSWORD_LEN} chars.")
            if not ask_yes_no("Use it anyway?"):
                continue
        else:
            dim(f"    Strength: {password_strength(password)}")
        if password != getpass.getpass("Repeat the password: "):
            err("Passwords do not match, try again.")
            continue
        return password


class Options:
    def __init__(self, output: Optional[str] = None, force_mode: Optional[str] = None,
                 yes: bool = False, keep: bool = False, quiet: bool = False) -> None:
        self.output = output
        self.force_mode = force_mode
        self.yes = yes
        self.keep = keep
        self.quiet = quiet


def default_decrypt_name(path: str) -> str:
    if path.lower().endswith(EXT):
        return path[:-len(EXT)]
    return path + ".dec"


def do_encrypt(path: str, opts: Options) -> bool:
    info(f"Plain file -> ENCRYPT mode ({human_size(os.path.getsize(path))})")
    password = ask_new_password()
    dst = opts.output or choose_output(path + EXT, auto_yes=opts.yes)
    if opts.output and os.path.exists(dst) and not opts.yes:
        dst = choose_output(dst)
    print("Encrypting (Argon2id is deriving the key)...")
    encrypt_file(path, dst, password)
    ok(f"Done: {dst} ({human_size(os.path.getsize(dst))})")
    if not opts.keep:
        if ask_yes_no("Delete the original file? (plain delete, not secure wipe)"):
            os.remove(path)
            dim("Original file deleted.")
    return True


def do_decrypt(path: str, opts: Options) -> bool:
    info(f"Encrypted file -> DECRYPT mode ({human_size(os.path.getsize(path))})")
    out = opts.output or choose_output(default_decrypt_name(path), auto_yes=opts.yes)
    if opts.output and os.path.exists(out) and not opts.yes:
        out = choose_output(out)
    while True:
        try:
            password = getpass.getpass("Enter the password (hidden): ")
        except (KeyboardInterrupt, EOFError):
            print()
            err("Cancelled.")
            return False
        print("Decrypting...")
        try:
            decrypt_file(path, out, password)
        except WrongPassword:
            err("Wrong password, try again (Ctrl+C to cancel).")
            continue
        ok(f"Done: {out} ({human_size(os.path.getsize(out))})")
        return True


def process(path: str, opts: Options) -> bool:
    if not os.path.isfile(path):
        err(f"File not found (or is a directory): {path}")
        return False
    try:
        if opts.force_mode == "encrypt":
            return do_encrypt(path, opts)
        if opts.force_mode == "decrypt":
            return do_decrypt(path, opts)
        if is_encrypted(path):
            return do_decrypt(path, opts)
        return do_encrypt(path, opts)
    except CryptoError as e:
        err(f"Error: {e}")
    except MemoryError:
        err("Not enough memory for Argon2id.")
    except PermissionError as e:
        err(f"Permission denied: {e}")
    except OSError as e:
        err(f"Filesystem error: {e}")
    return False


def interactive_loop(opts: Options) -> int:
    print()
    dim("Drag a file into this window and press Enter.")
    dim("Empty line, q or Ctrl+C to quit.")
    failures = 0
    while True:
        try:
            raw = input(f"\n{C.BOLD}File{C.RESET} > ")
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if raw.strip().lower() in ("", "q", "quit", "exit"):
            break
        if process(parse_dropped_path(raw), opts):
            failures = 0
        else:
            failures += 1
    print(f"{C.CYAN}Bye!{C.RESET}")
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="filecrypt",
        description="FileCrypt: file encryption (Argon2id + ChaCha20-Poly1305). "
                    "No arguments starts interactive drag & drop mode.",
    )
    p.add_argument("files", nargs="*", metavar="FILE",
                   help="files to process (mode is auto-detected)")
    p.add_argument("-o", "--output", default=None,
                   help="output file (single input only)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("-e", "--encrypt", action="store_true", help="force encrypt")
    mode.add_argument("-d", "--decrypt", action="store_true", help="force decrypt")
    p.add_argument("-y", "--yes", action="store_true", help="overwrite without asking")
    p.add_argument("-k", "--keep", action="store_true",
                   help="do not offer to delete the source after encrypt")
    p.add_argument("-q", "--quiet", action="store_true", help="less output")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    opts = Options(
        output=args.output,
        force_mode="encrypt" if args.encrypt else ("decrypt" if args.decrypt else None),
        yes=args.yes,
        keep=args.keep,
        quiet=args.quiet,
    )

    if not args.quiet:
        banner()

    if args.output and len(args.files) > 1:
        parser.error("--output works with a single input file only")

    if not args.files:
        return interactive_loop(opts)

    code = 0
    for path in args.files:
        cleaned = parse_dropped_path(path)
        size = human_size(os.path.getsize(cleaned)) if os.path.isfile(cleaned) else "?"
        print(f"\n- {cleaned} ({size})")
        if not process(cleaned, opts):
            code = 1
    return code


if __name__ == "__main__":
    sys.exit(main())
