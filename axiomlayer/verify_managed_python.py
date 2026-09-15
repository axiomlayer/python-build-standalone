#!/usr/bin/env python3
"""Verify the exact CPython provider contract consumed by AxiomLayer/pyr."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
CONTRACT_PATH = ROOT / "managed-python.json"
REPOSITORY_ROOT = ROOT.parent
UPSTREAM_WORKFLOWS = (
    "check.yml",
    "linux.yml",
    "macos.yml",
    "release.yml",
    "windows.yml",
    "zizmor.yml",
)
UPSTREAM_GUARD = "github.repository == 'astral-sh/python-build-standalone'"


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sri_from_hex(value: str) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(value)).decode("ascii")


def canonical_json_sha256(value: Any) -> str:
    encoded = (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fetch(url: str, destination: Path) -> None:
    headers = {"User-Agent": "AxiomLayer-python-provider-integration/1"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=120) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def materialize(source: str | None, spec: dict[str, Any], directory: Path) -> Path:
    if source is None:
        source = str(ROOT / spec["snapshotPath"])
    if source.startswith(("https://", "http://")):
        destination = directory / Path(str(spec["path"])).name
        fetch(source, destination)
    else:
        destination = Path(source).resolve()
    require(destination.is_file(), f"missing contract input: {destination}")
    actual = sha256_path(destination)
    require(
        actual == spec["rawSha256"],
        f"{spec['path']}: raw SHA-256 mismatch: expected {spec['rawSha256']}, got {actual}",
    )
    require(
        sri_from_hex(actual) == spec["nixHash"],
        f"{spec['path']}: Nix SRI does not encode the raw SHA-256",
    )
    return destination


def exact_source(contract: dict[str, Any]) -> dict[str, Any]:
    source = contract["source"]
    return {
        "id": "python",
        "role": "runtime",
        "acquisition": "fork",
        "upstream": source["upstream"],
        "repository": source["fork"],
        "version": f"{source['version']}+{source['build']}",
        "commit": source["commit"],
    }


def workflow_job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines()
    try:
        jobs_line = lines.index("jobs:")
    except ValueError as error:
        raise VerificationError("workflow has no jobs mapping") from error
    starts = [
        (index, match.group(1))
        for index, line in enumerate(lines[jobs_line + 1 :], jobs_line + 1)
        if (match := re.fullmatch(r"  ([A-Za-z0-9_-]+):", line))
    ]
    blocks: dict[str, str] = {}
    for offset, (start, name) in enumerate(starts):
        end = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        blocks[name] = "\n".join(lines[start:end])
    return blocks


def verify_workflow_policy(repository_root: Path) -> None:
    workflow_directory = repository_root / ".github" / "workflows"
    for name in UPSTREAM_WORKFLOWS:
        path = workflow_directory / name
        blocks = workflow_job_blocks(path.read_text(encoding="utf-8"))
        require(blocks, f"{name}: expected at least one job")
        for job, block in blocks.items():
            require(
                UPSTREAM_GUARD in block,
                f"{name}:{job}: inherited job is not inert in AxiomLayer",
            )

    action_pattern = re.compile(r"^[0-9a-f]{40}$")
    for path in sorted(workflow_directory.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        require(
            "codex_security_gate" not in text, f"{path.name}: retired gate returned"
        )
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("uses:"):
                continue
            action = stripped.removeprefix("uses:").split("#", 1)[0].strip()
            if action.startswith("./"):
                continue
            require("@" in action, f"{path.name}:{number}: action ref is absent")
            reference = action.rsplit("@", 1)[1]
            require(
                bool(action_pattern.fullmatch(reference)),
                f"{path.name}:{number}: action is not pinned to a full SHA",
            )

    integration = (workflow_directory / "axiomlayer-integration.yml").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "environment:",
        "secrets.",
        "contents: write",
        "packages: write",
        "id-token: write",
        "attestations: write",
        "deployments: write",
    ):
        require(
            forbidden not in integration, f"integration workflow contains {forbidden}"
        )
    require(
        "permissions:\n  contents: read" in integration,
        "integration workflow must remain read-only",
    )


def verify_git_lineage(contract: dict[str, Any]) -> None:
    source = contract["source"]
    expected_commit = source["commit"]
    tag_commit = subprocess.run(
        ["git", "rev-parse", f"refs/tags/{source['tag']}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    require(
        tag_commit == expected_commit,
        f"tag {source['tag']} resolves to {tag_commit}, expected {expected_commit}",
    )
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", expected_commit, "HEAD"],
        check=True,
    )


def verify_contract(args: argparse.Namespace) -> None:
    repository_root = Path(args.repository_root).resolve()
    verify_workflow_policy(repository_root)
    contract = load_json(CONTRACT_PATH)
    require(contract.get("schema") == "axiom-python-build-provider-v1", "bad schema")
    require(contract.get("revision") == 1, "unsupported contract revision")
    require(
        contract["nix"]["nixpkgsCommit"] == "c3eea5b2156db11c7eeeada3dc737711255b253e",
        "Nixpkgs pin diverges from dotfiles PR #49",
    )
    flake_lock = load_json(repository_root / "flake.lock")
    locked_nixpkgs = flake_lock["nodes"]["nixpkgs"]["locked"]
    original_nixpkgs = flake_lock["nodes"]["nixpkgs"]["original"]
    require(
        locked_nixpkgs["rev"] == contract["nix"]["nixpkgsCommit"]
        and original_nixpkgs["rev"] == contract["nix"]["nixpkgsCommit"],
        "flake.lock Nixpkgs revision diverges",
    )
    require(
        locked_nixpkgs["narHash"] == contract["nix"]["nixpkgsNarHash"],
        "flake.lock Nixpkgs narHash diverges",
    )
    require(
        locked_nixpkgs["lastModified"] == contract["nix"]["nixpkgsLastModified"],
        "flake.lock Nixpkgs timestamp diverges",
    )

    consumer = contract["consumer"]
    with tempfile.TemporaryDirectory(prefix="axiom-python-contract-") as raw_temp:
        temp = Path(raw_temp)
        policy_path = materialize(args.policy, consumer["policy"], temp)
        runtime_path = materialize(
            args.runtime_manifest, consumer["runtimeManifest"], temp
        )
        candidate_path = materialize(args.candidate, consumer["candidate"], temp)

        policy = load_json(policy_path)
        runtime_manifest = load_json(runtime_path)
        candidate = load_json(candidate_path)

    source = exact_source(contract)
    matching_sources = [
        item for item in policy["sources"] if item.get("id") == "python"
    ]
    require(matching_sources == [source], "promotion policy Python source diverges")

    policy_digest = canonical_json_sha256(policy)
    require(
        policy_digest == consumer["policy"]["canonicalSha256"],
        "promotion policy canonical digest diverges",
    )
    require(
        candidate["policySha256"] == policy_digest,
        "candidate does not bind the canonical promotion policy",
    )
    require(
        candidate["deviceGraph"]["runtimeManifest"]
        == {
            "path": consumer["runtimeManifest"]["path"],
            "sha256": consumer["runtimeManifest"]["rawSha256"],
        },
        "candidate does not bind the exact runtime manifest",
    )
    snapshots = [
        item for item in candidate["sourceSnapshots"] if item.get("id") == "python"
    ]
    require(
        snapshots
        == [
            {
                "commit": source["commit"],
                "id": "python",
                "repository": source["repository"],
                "version": source["version"],
            }
        ],
        "candidate Python source snapshot diverges",
    )

    runtime = runtime_manifest["runtimes"]["python"]
    require(runtime["version"] == contract["source"]["version"], "version diverges")
    require(runtime["build"] == contract["source"]["build"], "build diverges")
    require(
        runtime_manifest["installOrder"].index("pyr")
        < runtime_manifest["installOrder"].index("python"),
        "Python must remain managed behind Pyr",
    )
    require(
        set(runtime["assets"]) == set(contract["artifacts"]),
        "managed Python platform set diverges",
    )
    for platform_key, expected in contract["artifacts"].items():
        asset = runtime["assets"][platform_key]
        require(asset["format"] == "tar.gz", f"{platform_key}: format diverges")
        require(
            asset["strip"] == consumer["installRoot"],
            f"{platform_key}: install root diverges",
        )
        require(
            asset["url"] == expected["deliveryUrl"],
            f"{platform_key}: delivery URL diverges",
        )
        require(
            asset["sha256"] == expected["sha256"],
            f"{platform_key}: archive digest diverges",
        )
        require(
            asset["binarySha256"] == expected["binarySha256"],
            f"{platform_key}: binary digest diverges",
        )
        require(
            sri_from_hex(expected["sha256"]) == expected["nixHash"],
            f"{platform_key}: Nix SRI does not encode archive digest",
        )

    require(
        consumer["requiredCapabilities"] == ["tomllib", "sqlite-fts5"],
        "required Pyr capabilities diverge",
    )
    if args.verify_git:
        verify_git_lineage(contract)

    print(
        json.dumps(
            {
                "schema": "axiom-python-provider-contract-receipt-v1",
                "sourceCommit": source["commit"],
                "release": contract["source"]["tag"],
                "python": source["version"],
                "artifacts": len(contract["artifacts"]),
                "policySha256": policy_digest,
                "runtimeManifestSha256": consumer["runtimeManifest"]["rawSha256"],
            },
            sort_keys=True,
        )
    )


PROBE = r"""
import json
import platform
import sqlite3
import sys
import tomllib

assert tuple(sys.version_info[:3]) == (3, 14, 7), sys.version
assert tomllib.loads('fleet = "ready"')["fleet"] == "ready"
connection = sqlite3.connect(":memory:")
compile_options = {row[0] for row in connection.execute("PRAGMA compile_options")}
assert "ENABLE_FTS5" in compile_options, sorted(compile_options)
connection.execute("CREATE VIRTUAL TABLE fleet_search USING fts5(body)")
connection.execute("INSERT INTO fleet_search(body) VALUES ('managed by pyr')")
assert connection.execute(
    "SELECT body FROM fleet_search WHERE fleet_search MATCH 'managed'"
).fetchone() == ("managed by pyr",)
print(json.dumps({
    "machine": platform.machine().lower(),
    "python": platform.python_version(),
    "sqlite": sqlite3.sqlite_version,
    "tomllib": True,
    "fts5": True,
}, sort_keys=True))
"""


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            require(
                target == root or root in target.parents,
                f"archive path escapes extraction root: {member.name}",
            )
            if member.issym() or member.islnk():
                link = (target.parent / member.linkname).resolve()
                require(
                    link == root or root in link.parents,
                    f"archive link escapes extraction root: {member.name}",
                )
        tar.extractall(destination)


def verify_artifact(args: argparse.Namespace) -> None:
    contract = load_json(CONTRACT_PATH)
    require(
        args.platform in contract["artifacts"], f"unknown platform: {args.platform}"
    )
    spec = contract["artifacts"][args.platform]

    with tempfile.TemporaryDirectory(
        prefix=f"axiom-python-{args.platform}-"
    ) as raw_temp:
        temp = Path(raw_temp)
        if args.archive:
            archive = Path(args.archive).resolve()
        else:
            archive = temp / spec["upstreamAsset"]
            fetch(spec["upstreamUrl"], archive)
        require(archive.is_file(), f"missing archive: {archive}")
        require(
            archive.stat().st_size == spec["size"],
            f"{args.platform}: size mismatch: expected {spec['size']}, got {archive.stat().st_size}",
        )
        archive_digest = sha256_path(archive)
        require(
            archive_digest == spec["sha256"],
            f"{args.platform}: archive SHA-256 mismatch: expected {spec['sha256']}, got {archive_digest}",
        )

        extracted = temp / "extracted"
        extracted.mkdir()
        safe_extract(archive, extracted)
        executable = extracted / spec["binaryPath"]
        require(executable.is_file(), f"missing managed interpreter: {executable}")
        binary_digest = sha256_path(executable)
        require(
            binary_digest == spec["binarySha256"],
            f"{args.platform}: binary SHA-256 mismatch: expected {spec['binarySha256']}, got {binary_digest}",
        )
        if os.name != "nt":
            executable.chmod(executable.stat().st_mode | 0o111)

        completed = subprocess.run(
            [str(executable), "-I", "-c", PROBE],
            check=True,
            capture_output=True,
            text=True,
        )
        probe = json.loads(completed.stdout.strip().splitlines()[-1])
        require(
            probe["machine"] in spec["machines"],
            f"{args.platform}: ran on unexpected machine {probe['machine']}",
        )
        receipt = {
            "schema": "axiom-managed-python-artifact-receipt-v1",
            "platform": args.platform,
            "asset": spec["upstreamAsset"],
            "archiveSha256": archive_digest,
            "binarySha256": binary_digest,
            **probe,
        }
        print(json.dumps(receipt, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    contract = commands.add_parser("contract")
    contract.add_argument("--policy")
    contract.add_argument("--runtime-manifest")
    contract.add_argument("--candidate")
    contract.add_argument("--repository-root", default=str(REPOSITORY_ROOT))
    contract.add_argument("--verify-git", action="store_true")
    contract.set_defaults(handler=verify_contract)

    artifact = commands.add_parser("artifact")
    artifact.add_argument("--platform", required=True)
    artifact.add_argument("--archive")
    artifact.set_defaults(handler=verify_artifact)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (
        VerificationError,
        OSError,
        subprocess.CalledProcessError,
        tarfile.TarError,
    ) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
