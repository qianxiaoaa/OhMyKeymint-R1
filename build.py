#!/usr/bin/env python3
"""
Build script for OhMyKeymint Android targets.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

try:
    import tomllib as toml
except ModuleNotFoundError:
    import toml


REPO_ROOT = Path(__file__).resolve().parent
TARGET_ROOT = REPO_ROOT / "target"
DEFAULT_PLATFORM = 24

# R1 identity: the KSU manager, the installer and the WebUI show
# `${MODULE_DISPLAY_PREFIX}-<version>-<hash>`; zip and GitHub release files keep the space-free
# `${MODULE_NAME_PREFIX}`. versionCode is a release number rather than a commit count so a
# rebuilt tree cannot silently downgrade an installed module.
MODULE_NAME_PREFIX = "OhMyKeymint-R1"
MODULE_DISPLAY_PREFIX = "Oh My Keymint-R1"
SHORT_HASH_LENGTH = 7
DEFAULT_VERSION_CODE = 106
VERSION_CODE_ENV = "OMK_VERSION_CODE"

ABI_TO_TARGET = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}

ABI_TO_MODULE_ARCHES = {
    "arm64-v8a": "arm64 arm64-v8a",
    "x86_64": "x64 x86_64",
}

BORINGSSL_BUILD_DIRS = {
    "aarch64-linux-android": Path.home() / ".cargo" / "boringssl" / "build",
    "x86_64-linux-android": Path.home() / ".cargo" / "boringssl" / "build-x86_64",
}

BINARY_SPECS = (
    {"package": None, "bin": "keymint", "output_name": "keymint"},
    {"package": "injector", "bin": "inject", "output_name": "inject"},
)
SOTERTA_SERVICE_NAME = "soterta-svc"
PIF_SPOOF_PACKAGE = "pif-spoof"
PIF_SPOOF_LIBRARY = "libpif_spoof.so"

REQUIRED_TEMPLATE_FILES = (
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "module.prop",
    "uninstall.sh",
    "post-fs-data.sh",
    "service.sh",
    "soterta.sh",
    "verify.sh",
    "webroot",
)

MODULE_TEXT_FILES = (
    "AOSP.Apache-license-2.0.txt",
    "LICENSE-2",
    "LICENSE.md",
    "README.md",
    "THIRD_PARTY_LICENSES/Tricky-Addon-Update-Target-List.txt",
    "THIRD_PARTY_LICENSES/zygisk-api-0BSD.txt",
    "THIRD_PARTY_LICENSES/D-soter.txt",
    "THIRD_PARTY_LICENSES/ommega-soter-ta.txt",
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "keybox.xml",
    "google_attestation_status.json",
    "module.prop",
    "uninstall.sh",
    "post-fs-data.sh",
    "sepolicy.rule",
    "service.sh",
    "soterta.sh",
    "verify.sh",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
)


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def get_version_from_cargo_toml() -> str:
    with (REPO_ROOT / "Cargo.toml").open("r", encoding="utf-8") as fh:
        cargo_toml = toml.loads(fh.read())
    return cargo_toml["package"]["version"]


def get_version_code() -> str:
    raw = os.environ.get(VERSION_CODE_ENV, "").strip() or str(DEFAULT_VERSION_CODE)
    if not raw.isdigit():
        raise ValueError(f"{VERSION_CODE_ENV} must be numeric only, got: {raw}")
    return raw


def get_git_commit_hash() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Failed to get git commit hash")
    git_hash = result.stdout.strip()[:7]
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if status.returncode != 0:
        raise RuntimeError("Failed to inspect git worktree state")
    return f"{git_hash}-dirty" if status.stdout.strip() else git_hash


def cargo_context_for_target(target: str) -> tuple[dict[str, str], str]:
    env = os.environ.copy()
    configured_dir = env.get("BORINGSSL_BUILD_DIR")
    if configured_dir:
        build_dir = Path(configured_dir).expanduser()
        if not build_dir.is_absolute():
            build_dir = REPO_ROOT / build_dir
    else:
        build_dir = BORINGSSL_BUILD_DIRS.get(target)
        if build_dir is None:
            raise ValueError(f"No default BoringSSL build directory for target {target}")

    build_dir = build_dir.resolve()
    source_dir = build_dir.parent
    bssl_sys_dir = source_dir / "rust" / "bssl-sys"
    required_paths = (
        bssl_sys_dir / "Cargo.toml",
        build_dir / "libcrypto.a",
        build_dir / "libssl.a",
        build_dir / "rust" / "bssl-sys" / "librust_wrapper.a",
        build_dir / "rust" / "bssl-sys" / f"wrapper_{target}.rs",
    )
    missing = [path for path in required_paths if not path.is_file()]
    if missing:
        missing_text = ", ".join(os.fspath(path) for path in missing)
        raise FileNotFoundError(
            f"BoringSSL is not built for {target}; missing: {missing_text}. "
            f"Build it with -DRUST_BINDINGS={target}, or set BORINGSSL_BUILD_DIR "
            "to the matching build directory."
        )

    env["BORINGSSL_BUILD_DIR"] = os.fspath(build_dir)
    bssl_sys_path = json.dumps(bssl_sys_dir.as_posix())
    cargo_patch = f"patch.crates-io.bssl-sys.path={bssl_sys_path}"
    return env, cargo_patch


def build_binary(
    *,
    abi: str,
    target: str,
    release: bool,
    package: str | None,
    bin_name: str,
) -> Path:
    build_type = "release" if release else "debug"
    print(f"Building {bin_name} for {abi} ({target}, {build_type})...")

    env, cargo_patch = cargo_context_for_target(target)
    cmd = ["cargo", "--config", cargo_patch, "build", "--target", target]
    if package:
        cmd.extend(["-p", package, "--bin", bin_name])
    else:
        cmd.extend(["--bin", bin_name])
    if release:
        cmd.append("--release")

    run(cmd, env=env)

    binary_path = TARGET_ROOT / target / build_type / bin_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Built binary not found at {binary_path}")
    return binary_path


def copy_binary(binary: Path, output_name: str, abi: str, stage_dir: Path) -> None:
    dest_dir = stage_dir / "libs" / abi
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / output_name
    shutil.copy2(binary, dest_path)
    print(f"Copied {binary} to {dest_path}")


def build_soterta_service(*, abi: str, release: bool) -> Path:
    """Build the C Binder shim linked with the Rust software Soter TA.

    The shim is intentionally built by its dedicated script: it needs the NDK
    Binder C API in addition to Cargo's staticlib, while the normal package
    binaries are pure Rust.
    """
    profile = "release" if release else "debug"
    command = [
        os.fspath(Path(__file__).resolve().parent / "scripts" / "build_soterta_svc.py"),
        "--abi",
        abi,
    ]
    if not release:
        command.append("--debug")
    run([os.fspath(Path(sys.executable)), *command])
    output = TARGET_ROOT / "soterta-svc" / abi / profile / SOTERTA_SERVICE_NAME
    if not output.is_file():
        raise FileNotFoundError(f"Built Soter service not found at {output}")
    return output


def build_cdylib(
    *,
    abi: str,
    target: str,
    release: bool,
    package: str,
    library_name: str,
) -> Path:
    build_type = "release" if release else "debug"
    print(f"Building {package} cdylib for {abi} ({target}, {build_type})...")

    env, cargo_patch = cargo_context_for_target(target)
    cmd = ["cargo", "--config", cargo_patch, "build", "--target", target, "-p", package, "--lib"]
    if release:
        cmd.append("--release")
    run(cmd, env=env)

    library_path = TARGET_ROOT / target / build_type / library_name
    if not library_path.exists():
        raise FileNotFoundError(f"Built cdylib not found at {library_path}")
    return library_path


def copy_zygisk_payload(library: Path, abi: str, stage_dir: Path) -> None:
    payload_dir = stage_dir / "zygisk"
    payload_dir.mkdir(parents=True, exist_ok=True)
    destination = payload_dir / f"{abi}.so"
    shutil.copy2(library, destination)
    print(f"Copied {library} to {destination}")


def copy_template_files(stage_dir: Path) -> None:
    template_dir = REPO_ROOT / "template"
    if not template_dir.exists():
        raise FileNotFoundError("Template directory not found")

    missing = [name for name in REQUIRED_TEMPLATE_FILES if not (template_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"Template is missing required file(s): {', '.join(missing)}")

    print(f"Copying template files into {stage_dir}...")
    for item in template_dir.iterdir():
        dst = stage_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dst)


def copy_project_documents(stage_dir: Path) -> None:
    documents = (
        (REPO_ROOT / "README.md", stage_dir / "README.md"),
        (REPO_ROOT / "LICENSE.md", stage_dir / "LICENSE.md"),
        (REPO_ROOT / "LICENSE-2", stage_dir / "LICENSE-2"),
        (
            REPO_ROOT / "webui" / "LICENSE.upstream",
            stage_dir / "THIRD_PARTY_LICENSES" / "Tricky-Addon-Update-Target-List.txt",
        ),
        (
            REPO_ROOT / "third_party" / "zygisk-api" / "LICENSE",
            stage_dir / "THIRD_PARTY_LICENSES" / "zygisk-api-0BSD.txt",
        ),
        (
            REPO_ROOT / "pif-spoof" / "D-soter.NOTICE",
            stage_dir / "THIRD_PARTY_LICENSES" / "D-soter.txt",
        ),
        (
            REPO_ROOT / "template" / "THIRD_PARTY_LICENSES" / "ommega-soter-ta.txt",
            stage_dir / "THIRD_PARTY_LICENSES" / "ommega-soter-ta.txt",
        ),
    )
    for source, destination in documents:
        if not source.is_file():
            raise FileNotFoundError(f"Required license file not found: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def write_text_lf(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def normalize_module_text_files(stage_dir: Path) -> None:
    for relative_path in MODULE_TEXT_FILES:
        path = stage_dir / relative_path
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        content = content.replace("\r\n", "\n").replace("\r", "\n")
        write_text_lf(path, content)


def configure_template_for_abi(stage_dir: Path, abi: str) -> None:
    customize_path = stage_dir / "customize.sh"
    if not customize_path.exists():
        raise FileNotFoundError(f"customize.sh not found at {customize_path}")

    supported_arch = ABI_TO_MODULE_ARCHES[abi]
    content = customize_path.read_text(encoding="utf-8")
    content = content.replace('SUPPORTED_ABIS="arm64 x64"', f'SUPPORTED_ABIS="{supported_arch}"')
    write_text_lf(customize_path, content)
    print(f"Updated customize.sh supported ABI to {supported_arch}")


def release_display_name(version: str, git_hash: str) -> str:
    return f"{MODULE_DISPLAY_PREFIX}-{version}-{git_hash[:SHORT_HASH_LENGTH]}"


def modify_module_prop(
    stage_dir: Path,
    version: str,
    version_code: str,
    git_hash: str,
    release: bool,
) -> None:
    module_prop_path = stage_dir / "module.prop"
    if not module_prop_path.exists():
        raise FileNotFoundError(f"module.prop not found at {module_prop_path}")

    build_type = "release" if release else "debug"
    release_id = release_display_name(version, git_hash)
    version_name = f"{version} ({version_code}-{git_hash}-{build_type})"
    content = module_prop_path.read_text(encoding="utf-8")
    content = content.replace("${versionName}", version_name)
    content = content.replace("${versionCode}", version_code)
    content = content.replace("${moduleName}", release_id)
    # service.sh asks the daemon to overwrite this line once the boot self-check passes,
    # so the placeholder has to stay recognisable in the manager before that happens.
    content = content.replace("${moduleDescription}", f"{release_id} 等待开机自检")
    write_text_lf(module_prop_path, content)
    print(
        f"Updated module.prop: versionName={version_name}, versionCode={version_code}, "
        f"name={release_id}"
    )


def stamp_webroot_title(stage_dir: Path, title: str) -> None:
    # Only the staged copy: the committed webroot must stay identical to a fresh WebUI build.
    config_path = stage_dir / "webroot" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["title"] = title
    write_text_lf(config_path, json.dumps(config, ensure_ascii=False, indent=4) + "\n")
    print(f"Updated webroot/config.json: title={title}")


def generate_hash_for_file(file_path: Path) -> None:
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)

    hash_path = file_path.with_name(f"{file_path.name}.sha256")
    hash_path.write_text(digest.hexdigest(), encoding="utf-8")
    print(f"Created hash file: {hash_path}")


def generate_hash_files(stage_dir: Path) -> None:
    print(f"Generating SHA256 hash files under {stage_dir}...")
    for item in stage_dir.rglob("*"):
        if item.is_file() and not item.name.endswith(".sha256"):
            generate_hash_for_file(item)


def generate_webroot_manifest(stage_dir: Path) -> None:
    webroot = stage_dir / "webroot"
    required = (webroot / "index.html", webroot / "config.json")
    missing = [path.relative_to(stage_dir).as_posix() for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"WebUI build is incomplete; missing: {', '.join(missing)}")

    assets = sorted(
        path.relative_to(stage_dir).as_posix()
        for path in webroot.rglob("*")
        if path.is_file() and not path.name.endswith(".sha256")
    )
    if not assets:
        raise FileNotFoundError("WebUI build did not produce any files")
    write_text_lf(stage_dir / "webroot.manifest", "\n".join(assets) + "\n")
    print(f"Created WebUI manifest with {len(assets)} asset(s)")


def delete_old_zips(
    release: bool,
    selected_abis: list[str],
    version: str,
    version_code: str,
) -> None:
    build_type = "release" if release else "debug"
    old_zips: set[str] = set()
    for abi in selected_abis:
        # Remove packages produced by the previous naming scheme as well as
        # packages for this version produced by an earlier build.  The latter
        # is useful when the working tree hash changes between builds.
        for pattern in (
            f"OhMyKeymint-{build_type}-{abi}-*.zip",
            f"OhMyKeymint-{version}-*-{build_type}.zip",
            f"{MODULE_NAME_PREFIX}-{version}-*-{build_type}.zip",
            f"{MODULE_NAME_PREFIX}-{version}-{version_code}-*-{abi}-{build_type}.zip",
        ):
            old_zips.update(glob.glob(os.fspath(TARGET_ROOT / pattern)))

        if abi != "arm64-v8a":
            continue
        # The arm64 package intentionally omits its ABI in the filename; retain a
        # separately built x86_64 package with the same version and version code.
        # Restrict the glob to the current version code so older releases are
        # never removed just because this build is arm64.
        old_zips.update(
            path
            for path in glob.glob(
                os.fspath(
                    TARGET_ROOT
                    / f"{MODULE_NAME_PREFIX}-{version}-{version_code}-*-{build_type}.zip"
                )
            )
            if not path.endswith(f"-x86_64-{build_type}.zip")
        )
    if not old_zips:
        print(f"No old zip files found for build type {build_type} and ABIs {selected_abis}")
        return

    print(f"Found {len(old_zips)} old zip file(s) to delete:")
    for old_zip in old_zips:
        print(f"  Deleting: {old_zip}")
        os.remove(old_zip)


def create_zip_package(
    *,
    stage_dir: Path,
    version: str,
    version_code: str,
    git_hash: str,
    abi: str,
    release: bool,
) -> Path:
    build_type = "release" if release else "debug"
    # R1 package identity: prefix, version, release number, short commit hash, and
    # build type.  An explicit x86_64 build gets an ABI discriminator so separate ABI
    # builds cannot overwrite one another.
    abi_suffix = f"-{abi}" if abi != "arm64-v8a" else ""
    zip_name = (
        f"{MODULE_NAME_PREFIX}-{version}-{version_code}-{git_hash}"
        f"{abi_suffix}-{build_type}.zip"
    )
    zip_path = TARGET_ROOT / zip_name
    print(f"Creating zip package: {zip_path}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for root, _, files in os.walk(stage_dir):
            for file_name in files:
                file_path = Path(root) / file_name
                arcname = file_path.relative_to(stage_dir)
                zipf.write(file_path, arcname)

    return zip_path


def build_package_for_abi(
    *,
    abi: str,
    release: bool,
    platform: int,
    version: str,
    version_code: str,
    git_hash: str,
) -> Path:
    target = ABI_TO_TARGET[abi]
    stage_dir = TARGET_ROOT / "temp" / abi
    # Kept for compatibility with old invocations; plain Cargo uses .cargo/config.toml.
    _ = platform
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        built_binaries: dict[str, Path] = {}
        for spec in BINARY_SPECS:
            built_binaries[spec["output_name"]] = build_binary(
                abi=abi,
                target=target,
                release=release,
                package=spec["package"],
                bin_name=spec["bin"],
            )
        soterta_service = build_soterta_service(abi=abi, release=release)
        pif_payload = build_cdylib(
            abi=abi,
            target=target,
            release=release,
            package=PIF_SPOOF_PACKAGE,
            library_name=PIF_SPOOF_LIBRARY,
        )

        copy_template_files(stage_dir)
        copy_project_documents(stage_dir)
        normalize_module_text_files(stage_dir)
        configure_template_for_abi(stage_dir, abi)
        for spec in BINARY_SPECS:
            copy_binary(
                built_binaries[spec["output_name"]],
                spec["output_name"],
                abi,
                stage_dir,
            )
        copy_binary(soterta_service, SOTERTA_SERVICE_NAME, abi, stage_dir)
        copy_zygisk_payload(pif_payload, abi, stage_dir)

        modify_module_prop(stage_dir, version, version_code, git_hash, release)
        normalize_module_text_files(stage_dir)
        generate_webroot_manifest(stage_dir)
        stamp_webroot_title(stage_dir, release_display_name(version, git_hash))
        generate_hash_files(stage_dir)
        return create_zip_package(
            stage_dir=stage_dir,
            version=version,
            version_code=version_code,
            git_hash=git_hash,
            abi=abi,
            release=release,
        )
    finally:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build OhMyKeymint Magisk packages for Android")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--debug", action="store_true", help="Build in debug mode (default)")
    parser.add_argument(
        "--abi",
        dest="abis",
        action="append",
        choices=sorted(ABI_TO_TARGET),
        help="Build only the selected Android ABI(s). Defaults to arm64-v8a.",
    )
    parser.add_argument(
        "--platform",
        type=int,
        default=DEFAULT_PLATFORM,
        help=(
            "Compatibility option; ordinary cargo builds use .cargo/config.toml "
            f"for the Android API/linker (default: {DEFAULT_PLATFORM})"
        ),
    )
    args = parser.parse_args()

    version = get_version_from_cargo_toml()
    version_code = get_version_code()
    git_hash = get_git_commit_hash()
    selected_abis = args.abis or ["arm64-v8a"]

    print(f"Building {MODULE_NAME_PREFIX} version {version} (code {version_code}, commit {git_hash})")
    print(f"Build mode: {'Release' if args.release else 'Debug'}")
    print(f"Target ABIs: {', '.join(selected_abis)}")

    delete_old_zips(args.release, selected_abis, version, version_code)
    built_packages = []
    for abi in selected_abis:
        built_packages.append(
            build_package_for_abi(
                abi=abi,
                release=args.release,
                platform=args.platform,
                version=version,
                version_code=version_code,
                git_hash=git_hash,
            )
        )

    print("Build completed successfully!")
    for zip_path in built_packages:
        print(f"Output: {zip_path}")


if __name__ == "__main__":
    main()
