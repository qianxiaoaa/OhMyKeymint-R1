#!/usr/bin/env python3

import argparse
import os
import platform
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / ".cargo" / "config.toml"


def detect_ndk_root(cli_value: str | None) -> Path:
    candidates = []
    if cli_value:
        candidates.append(Path(cli_value).expanduser())

    for env_name in ("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"):
        env_value = os.environ.get(env_name)
        if env_value:
            candidates.append(Path(env_value).expanduser())

    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        sdk_root = Path(android_home).expanduser()
        candidates.append(sdk_root / "ndk-bundle")
        ndk_dir = sdk_root / "ndk"
        if ndk_dir.is_dir():
            versions = sorted((path for path in ndk_dir.iterdir() if path.is_dir()), reverse=True)
            candidates.extend(versions)

    for candidate in candidates:
        if (candidate / "toolchains" / "llvm" / "prebuilt").is_dir():
            return candidate.resolve()

    raise FileNotFoundError(
        "Android NDK not found. Set ANDROID_NDK_ROOT/ANDROID_NDK_HOME or pass --ndk-root."
    )


def guess_host_tags() -> list[str]:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        return ["linux-x86_64"]

    if system == "darwin":
        tags = []
        if machine in ("arm64", "aarch64"):
            tags.append("darwin-arm64")
        tags.append("darwin-x86_64")
        return tags

    if system == "windows":
        return ["windows-x86_64"]

    raise RuntimeError(f"Unsupported host platform: {platform.system()} {platform.machine()}")


def resolve_host_tag(ndk_root: Path, cli_value: str | None) -> str:
    prebuilt_dir = ndk_root / "toolchains" / "llvm" / "prebuilt"
    if cli_value:
        candidate = prebuilt_dir / cli_value
        if candidate.is_dir():
            return cli_value
        raise FileNotFoundError(f"NDK host tag does not exist: {candidate}")

    for tag in guess_host_tags():
        if (prebuilt_dir / tag).is_dir():
            return tag

    available = sorted(path.name for path in prebuilt_dir.iterdir() if path.is_dir())
    raise FileNotFoundError(
        "Unable to detect a matching NDK host tag. "
        f"Available tags: {', '.join(available) or '(none)'}"
    )


def toml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\") + '"'


def find_clang_resource_include(prebuilt_lib_dir: Path) -> Path | None:
    """Return <prebuilt>/lib/clang/<ver>/include if it exists.

    bindgen needs the clang builtin headers (stddef.h and friends) when it goes
    through libclang; without this include path any C++ header that pulls in
    <stddef.h> fails with "stddef.h file not found".
    """
    clang_root = prebuilt_lib_dir / "clang"
    if not clang_root.is_dir():
        return None
    versions = sorted((path for path in clang_root.iterdir() if path.is_dir()), reverse=True)
    for version in versions:
        include_dir = version / "include"
        if include_dir.is_dir():
            return include_dir
    return None


def find_bssl_sys_patch() -> Path:
    """Path to the local bssl-sys used to override the crates.io placeholder.

    Mirrors build.py: BORINGSSL_BUILD_DIR or ~/.cargo/boringssl/build.
    """
    configured = os.environ.get("BORINGSSL_BUILD_DIR")
    build_dir = Path(configured).expanduser() if configured else Path.home() / ".cargo" / "boringssl" / "build"
    return build_dir.resolve().parent / "rust" / "bssl-sys"


def render_config(ndk_root: Path, host_tag: str, api_level: int) -> str:
    bin_dir = ndk_root / "toolchains" / "llvm" / "prebuilt" / host_tag / "bin"
    sysroot = ndk_root / "toolchains" / "llvm" / "prebuilt" / host_tag / "sysroot"
    prebuilt_lib_dir = ndk_root / "toolchains" / "llvm" / "prebuilt" / host_tag / "lib"

    exe_suffix = ".cmd" if host_tag.startswith("windows-") else ""
    ar_name = "llvm-ar.exe" if host_tag.startswith("windows-") else "llvm-ar"

    aarch64_clang = bin_dir / f"aarch64-linux-android{api_level}-clang{exe_suffix}"
    aarch64_clangxx = bin_dir / f"aarch64-linux-android{api_level}-clang++{exe_suffix}"
    x86_64_clang = bin_dir / f"x86_64-linux-android{api_level}-clang{exe_suffix}"
    x86_64_clangxx = bin_dir / f"x86_64-linux-android{api_level}-clang++{exe_suffix}"
    llvm_ar = bin_dir / ar_name

    for path in (aarch64_clang, aarch64_clangxx, x86_64_clang, x86_64_clangxx, llvm_ar):
        if not path.is_file():
            raise FileNotFoundError(f"Required NDK tool not found: {path}")
    
    # sysroot should use slash, not backslash
    sysroot_with_slashes = str(sysroot).replace('\\', '/')

    clang_include = find_clang_resource_include(prebuilt_lib_dir)
    if clang_include is None:
        raise FileNotFoundError(
            "Unable to locate the NDK clang resource headers under "
            f"{prebuilt_lib_dir / 'clang'}; bindgen would miss stddef.h."
        )
    clang_include_flags = f"-isystem {str(clang_include).replace(chr(92), '/')}"

    aarch64_bindgen = f"--sysroot={sysroot_with_slashes} -I{sysroot / 'usr' / 'include' / 'aarch64-linux-android'} {clang_include_flags}"
    x86_64_bindgen = f"--sysroot={sysroot_with_slashes} -I{sysroot / 'usr' / 'include' / 'x86_64-linux-android'} {clang_include_flags}"

    return "\n".join(
        [
            "# This file is auto-generated by scripts/setup_cargo_config.py.",
            f"# NDK root: {ndk_root}",
            f"# Host tag: {host_tag}",
            f"# API level: {api_level}",
            "",
            "[target.aarch64-linux-android]",
            f"linker = {toml_string(str(aarch64_clang))}",
            'rustflags = ["-C", "link-arg=-lc++abi"]',
            "",
            "[target.x86_64-linux-android]",
            f"linker = {toml_string(str(x86_64_clang))}",
            'rustflags = ["-C", "link-arg=-lc++abi"]',
            "",
            "[env]",
            f"ANDROID_NDK_ROOT = {{ value = {toml_string(str(ndk_root))}, force = true }}",
            'BORINGSSL_RUST_CPPLIB = { value = "c++_static", force = true }',
            f'LIBCLANG_PATH = {{ value = {toml_string(str(prebuilt_lib_dir)) }, force = true }}',
            f"CC_aarch64_linux_android = {toml_string(str(aarch64_clang))}",
            f"CXX_aarch64_linux_android = {toml_string(str(aarch64_clangxx))}",
            f"AR_aarch64_linux_android = {toml_string(str(llvm_ar))}",
            f'BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android = {toml_string(aarch64_bindgen)}',
            "",
            f"CC_x86_64_linux_android = {toml_string(str(x86_64_clang))}",
            f"CXX_x86_64_linux_android = {toml_string(str(x86_64_clangxx))}",
            f"AR_x86_64_linux_android = {toml_string(str(llvm_ar))}",
            f'BINDGEN_EXTRA_CLANG_ARGS_x86_64_linux_android = {toml_string(x86_64_bindgen)}',
            "",
            "[patch.crates-io]",
            f"bssl-sys = {{ path = {toml_string(str(find_bssl_sys_patch()))} }}",
            "",
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate .cargo/config.toml for Android NDK builds."
    )
    parser.add_argument("--ndk-root", help="Path to the Android NDK root.")
    parser.add_argument(
        "--host-tag",
        help="NDK host tag, for example linux-x86_64 or darwin-x86_64.",
    )
    parser.add_argument(
        "--api-level",
        type=int,
        default=26,
        help="Android API level embedded in clang wrapper names. Default: 26.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output file path. Default: .cargo/config.toml",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the generated config instead of writing a file.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        ndk_root = detect_ndk_root(args.ndk_root)
        host_tag = resolve_host_tag(ndk_root, args.host_tag)
        rendered = render_config(ndk_root, host_tag, args.api_level)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.stdout:
        sys.stdout.write(rendered)
        return 0

    output_path = args.output.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists() and not args.force:
        print(
            f"error: {output_path} already exists. Use --force to overwrite it.",
            file=sys.stderr,
        )
        return 1

    output_path.write_text(rendered, encoding="utf-8")
    print(f"wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
