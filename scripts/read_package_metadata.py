#!/usr/bin/env python3
"""Read a module.prop key out of a packaged module zip.

The update workflow publishes the release's versionCode into update.json. Recomputing it from
git history would disagree with the number baked into the package by build.py, so the package
itself is the authority and this helper is the only reader.
"""

import argparse
import re
import sys
import zipfile

MODULE_PROP = "module.prop"
NUMERIC_KEYS = ("versionCode",)


def read_module_prop(zip_path: str) -> str:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            raw = archive.read(MODULE_PROP)
    except KeyError:
        raise SystemExit(f"{zip_path} does not contain {MODULE_PROP}")
    except zipfile.BadZipFile:
        raise SystemExit(f"{zip_path} is not a readable zip package")
    return raw.decode("utf-8")


def read_key(contents: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}=(.*)$", contents, re.M)
    if match is None:
        raise SystemExit(f"{MODULE_PROP} has no {key} line")
    value = match.group(1).strip()
    if not value:
        raise SystemExit(f"{MODULE_PROP} has an empty {key}")
    if key in NUMERIC_KEYS and not value.isdigit():
        raise SystemExit(f"{MODULE_PROP} {key} must be numeric, got: {value}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", help="packaged module zip")
    parser.add_argument("--key", default="versionCode", help="module.prop key to print")
    arguments = parser.parse_args()

    sys.stdout.write(read_key(read_module_prop(arguments.zip_path), arguments.key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
