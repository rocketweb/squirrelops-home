"""Retain exact Alpine recipes and their checksum-listed source inputs locally.

No APKBUILD is executed. No data is uploaded. Failed origins remain explicit.
"""

import argparse
import concurrent.futures
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path()
SOURCES = Path()
MAX_FILE = 512 * 1024 * 1024


def fetch(url, destination, maximum=MAX_FILE):
    if destination.exists():
        return
    temporary = destination.with_name(destination.name + ".partial")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=45) as response, temporary.open("wb") as output:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise ValueError("Non-HTTPS source redirect")
        count = 0
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > maximum:
                raise ValueError("Source file exceeds download budget")
            output.write(chunk)
    temporary.rename(destination)


def tree(path, commit, destination, depth=0):
    if depth > 5:
        raise ValueError("Recipe tree exceeds depth budget")
    response = subprocess.run(
        ["gh", "api", f"repos/alpinelinux/aports/contents/{path}?ref={commit}"],
        text=True, capture_output=True, timeout=45,
    )
    if response.returncode:
        raise ValueError("Recipe API unavailable: " + path)
    entries = json.loads(response.stdout)
    if not isinstance(entries, list) or len(entries) > 200:
        raise ValueError("Unexpected recipe tree")
    for entry in entries:
        name = entry["name"]
        if not re.fullmatch(r"[A-Za-z0-9._+@-]+", name) or name in {".", ".."}:
            raise ValueError("Unsafe recipe filename")
        target = destination / name
        if entry["type"] == "dir":
            tree(path + "/" + name, commit, target, depth + 1)
        elif entry["type"] == "file":
            expected_url = f"https://raw.githubusercontent.com/alpinelinux/aports/{commit}/{path}/{name}"
            if urllib.parse.unquote(entry["download_url"]) != expected_url or entry["size"] > 8 * 1024 * 1024:
                raise ValueError("Unexpected recipe origin or size")
            fetch(expected_url, target, 8 * 1024 * 1024)
            data = target.read_bytes()
            blob = b"blob " + str(len(data)).encode() + b"\0" + data
            if len(data) != entry["size"] or hashlib.sha1(blob).hexdigest() != entry["sha"]:
                raise ValueError("Recipe blob mismatch")
        else:
            raise ValueError("Recipe contains non-regular entry")


def retain(origin):
    name, commit = origin["origin"], origin["commit"]
    folder = SOURCES / f"{name}-{commit}"
    recipe = folder / "recipe"
    metadata = folder / "source-record.json"
    try:
        selected = None
        for section in ("main", "community"):
            url = f"https://raw.githubusercontent.com/alpinelinux/aports/{commit}/{section}/{name}/APKBUILD"
            try:
                fetch(url, recipe / "APKBUILD", 1024 * 1024)
                selected = section
                break
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise
        if not selected:
            raise ValueError("Exact origin recipe missing")
        recipe_path = f"{selected}/{name}"
        tree(recipe_path, commit, recipe)
        checksums = re.findall(
            r"^([0-9a-f]{128})[ \t]+([^\s]+)[ \t]*$",
            (recipe / "APKBUILD").read_text(), re.MULTILINE,
        )
        if not checksums and not origin.get("recipe_only"):
            raise ValueError("No literal source checksums; manual review required")
        source_files = {}
        for digest, filename in checksums:
            if not re.fullmatch(r"[A-Za-z0-9._+@-]+", filename) or filename in {".", ".."}:
                raise ValueError("Non-flat source filename; manual review required")
            if filename in source_files and source_files[filename]["sha512"] != digest:
                raise ValueError("Conflicting per-architecture source checksums")
            local = recipe / filename
            url = f"https://raw.githubusercontent.com/alpinelinux/aports/{commit}/{recipe_path}/{filename}"
            if not local.exists():
                local = folder / "distfiles" / filename
                url = "https://distfiles.alpinelinux.org/distfiles/v3.24/" + urllib.parse.quote(filename)
                fetch(url, local)
            with local.open("rb") as handle:
                actual = hashlib.file_digest(handle, "sha512").hexdigest()
            if actual != digest:
                raise ValueError("Source checksum mismatch: " + filename)
            source_files[filename] = {
                "path": str(local.relative_to(ROOT)), "sha512": digest,
                "size": local.stat().st_size, "url": url,
            }
        record = {
            **origin, "status": "all literal recipe checksums verified",
            "recipe_url": f"https://github.com/alpinelinux/aports/tree/{commit}/{recipe_path}",
            "source_files": list(source_files.values()),
        }
        metadata.write_text(json.dumps(record, indent=2) + "\n")
        print(f"VERIFIED {name}: {len(source_files)} source inputs", flush=True)
        return record
    except Exception as exc:
        result = {**origin, "status": "blocked", "error": str(exc)}
        print(f"BLOCKED {name}: {exc}", flush=True)
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ROOT = args.output
    SOURCES = ROOT / "sources"
    inventory = json.loads(args.inventory.read_text())
    for origin in inventory["origins"]:
        if not re.fullmatch(r"[a-zA-Z0-9_+-]+", origin["origin"]) or not re.fullmatch(
            r"[0-9a-f]{40}", origin["commit"]
        ):
            raise SystemExit("Unsafe origin or commit")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(retain, inventory["origins"]))
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "source-retention-status.json").write_text(json.dumps(results, indent=2) + "\n")
    failed = [r for r in results if r["status"] == "blocked"]
    print(f"Retained {len(results) - len(failed)}/{len(results)} origins. Nothing published.")
    raise SystemExit(bool(failed))
