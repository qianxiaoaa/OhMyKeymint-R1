#!/usr/bin/env python3
"""Build soter-svc, the A-side software Soter TA daemon.

The daemon is the parcel half of the software TA: C for the binder service (the
process that owns a service name is the only one that can read its request
parcels and write its replies) and Rust for the ledger, the blobs and the
answers, linked in from the soter-ta staticlib. The ABI between the two halves
lives in soter-ta/src/ffi.rs and is mirrored in soterta-svc/soter-svc.c.

    python scripts/build_soterta_svc.py [--abi arm64-v8a|x86_64] [--debug]
                                    [--ndk-root PATH] [--api-level N]

Output: target/soterta-svc/<abi>/{debug,release}/soterta-svc
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from setup_cargo_config import detect_ndk_root, resolve_host_tag  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CARGO_CONFIG = REPO_ROOT / ".cargo" / "config.toml"
ABI_TO_TARGET = {
    "arm64-v8a": ("aarch64-linux-android", "aarch64-linux-android"),
    "x86_64": ("x86_64-linux-android", "x86_64-linux-android"),
}
DEFAULT_API_LEVEL = 29
SOURCE = REPO_ROOT / "soterta-svc" / "soter-svc.c"
TARGET_DIR = REPO_ROOT / "target"
OUTPUT_ROOT = TARGET_DIR / "soterta-svc"

# binder_ndk for the C API, log for the daemon log lines and the Rust panic
# path, dl for the platform symbol lookup.
PLATFORM_LIBS = ("binder_ndk", "log", "dl", "m")


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    result = subprocess.run(command, cwd=REPO_ROOT)
    if result.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(command)}")


def cargo_config_ndk_root() -> str | None:
    """The NDK the Rust side is built with, so both halves use one toolchain."""
    if not CARGO_CONFIG.is_file():
        return None
    for line in CARGO_CONFIG.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("ANDROID_NDK_ROOT"):
            _, _, value = stripped.partition("=")
            value = value.strip()
            # Cargo accepts both a plain string and an inline table such as
            # `{ value = "...", force = true }` in [env].
            inline = re.search(r"value\s*=\s*(['\"])(.*?)\1", value)
            return (inline.group(2) if inline else value.strip("'\"")) or None
    return None


def build_staticlib(abi: str, debug: bool) -> Path:
    target = ABI_TO_TARGET[abi][0]
    profile_dir = "debug" if debug else "release"
    command = ["cargo", "build", "--locked", "--target", target, "-p", "soter-ta"]
    if not debug:
        command.append("--release")
    run(command)
    library = TARGET_DIR / target / profile_dir / "libsoter_ta.a"
    if not library.is_file():
        raise SystemExit(f"staticlib not found: {library}")
    return library


def compile_daemon(
    *,
    abi: str,
    ndk_root: Path,
    host_tag: str,
    api_level: int,
    library: Path,
    output: Path,
) -> None:
    bin_dir = ndk_root / "toolchains" / "llvm" / "prebuilt" / host_tag / "bin"
    sysroot = ndk_root / "toolchains" / "llvm" / "prebuilt" / host_tag / "sysroot"
    triple = ABI_TO_TARGET[abi][1]
    clang = bin_dir / "clang.exe"
    if not clang.is_file():
        clang = bin_dir / "clang"
    if not clang.is_file():
        raise SystemExit(f"clang not found under {bin_dir}")

    output.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            str(clang),
            f"--target={triple}{api_level}",
            f"--sysroot={sysroot.as_posix()}",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror=implicit-function-declaration",
            "-o",
            str(output),
            str(SOURCE),
            str(library),
            *(f"-l{name}" for name in PLATFORM_LIBS),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the soter-svc daemon.")
    parser.add_argument(
        "--abi",
        choices=sorted(ABI_TO_TARGET),
        default="arm64-v8a",
        help="Target ABI (default: arm64-v8a).",
    )
    parser.add_argument("--debug", action="store_true", help="Build soter-ta in debug mode.")
    parser.add_argument("--ndk-root", help="Path to the Android NDK root.")
    parser.add_argument("--host-tag", help="NDK host tag, for example windows-x86_64.")
    parser.add_argument(
        "--api-level",
        type=int,
        default=DEFAULT_API_LEVEL,
        help=f"Android API level for the linker (default: {DEFAULT_API_LEVEL}).",
    )
    args = parser.parse_args()

    try:
        ndk_root = detect_ndk_root(args.ndk_root or cargo_config_ndk_root())
        host_tag = resolve_host_tag(ndk_root, args.host_tag)
    except (FileNotFoundError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    library = build_staticlib(args.abi, args.debug)
    # Same file name the module packages, so one name is valid everywhere.
    output = OUTPUT_ROOT / args.abi / ("debug" if args.debug else "release") / "soterta-svc"
    compile_daemon(
        abi=args.abi,
        ndk_root=ndk_root,
        host_tag=host_tag,
        api_level=args.api_level,
        library=library,
        output=output,
    )
    print(f"wrote {output} ({output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
