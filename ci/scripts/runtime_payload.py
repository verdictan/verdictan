#!/usr/bin/env python3
"""Pack and verify the canonical cargo-dist CLI runtime payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
PACKAGE = "verdictan"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


def payload_files(root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"payload contains a symbolic link: {relative}")
        if not path.is_file() or relative == "payload-manifest.json":
            continue
        files.append(
            {
                "path": relative,
                "sha256": sha256(path),
                "size": path.stat().st_size,
                "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
            }
        )
    return files


def tree_digest(files: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for item in files:
        digest.update(
            (
                f"{item['path']}\0{item['size']}\0{item['mode']}\0"
                f"{item['sha256']}\n"
            ).encode()
        )
    return digest.hexdigest()


def copy_file(source: Path, target: Path, mode: int) -> None:
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"required regular file is missing: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def pack(args: argparse.Namespace) -> None:
    repo = args.repo_root.resolve()
    binary = args.binary.resolve()
    output = args.output.resolve()
    if not binary.is_file() or binary.is_symlink():
        raise ValueError(f"canonical cargo-dist binary is missing: {binary}")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError("source SHA must contain 40 lowercase hexadecimal characters")
    if not re.fullmatch(r"[0-9a-f]{64}", args.build_input_digest):
        raise ValueError("build input digest must contain 64 lowercase hexadecimal characters")
    if args.source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    epoch = args.source_date_epoch
    created = datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        copy_file(binary, stage / "rootfs/usr/local/bin/verdictan", 0o755)
        copy_file(repo / "LICENSE", stage / "rootfs/licenses/LICENSE", 0o644)
        copy_file(
            repo / "THIRD_PARTY_NOTICES.md",
            stage / "rootfs/licenses/THIRD_PARTY_NOTICES.md",
            0o644,
        )
        copy_file(
            repo / "schema/policy-configuration.schema.json",
            stage / "rootfs/usr/share/verdictan/policy-configuration.schema.json",
            0o644,
        )

        initial = payload_files(stage)
        rootfs_digest = tree_digest(initial)
        write_json(
            stage / "provenance.json",
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": "rootfs", "digest": {"sha256": rootfs_digest}}],
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://verdictan.com/build/cargo-dist-runtime-payload/v1",
                        "externalParameters": {
                            "target": args.target,
                            "buildInputDigest": args.build_input_digest,
                        },
                        "resolvedDependencies": [
                            {
                                "uri": "pkg:cargo/verdictan",
                                "digest": {"gitCommit": args.source_sha},
                            }
                        ],
                    },
                    "runDetails": {
                        "builder": {"id": args.builder_id},
                        "metadata": {"invocationId": args.invocation_id},
                    },
                },
            },
        )
        write_json(
            stage / "sbom.spdx.json",
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": f"verdictan-runtime-{args.target}",
                "documentNamespace": f"https://verdictan.com/spdx/{rootfs_digest}",
                "creationInfo": {
                    "created": created,
                    "creators": ["Tool: verdictan-runtime-payload/1"],
                },
                "packages": [
                    {
                        "name": "verdictan",
                        "SPDXID": "SPDXRef-Package-verdictan",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "versionInfo": args.source_sha,
                        "checksums": [
                            {
                                "algorithm": "SHA256",
                                "checksumValue": sha256(
                                    stage / "rootfs/usr/local/bin/verdictan"
                                ),
                            }
                        ],
                    }
                ],
            },
        )
        files = payload_files(stage)
        manifest = {
            "schemaVersion": SCHEMA_VERSION,
            "package": PACKAGE,
            "source": {"commit": args.source_sha, "sourceDateEpoch": epoch},
            "build": {
                "target": args.target,
                "profile": "dist",
                "features": ["distributed", "embedding-external", "otlp"],
                "toolchain": args.toolchain,
                "dependencyLockSha256": sha256(repo / "Cargo.lock"),
                "buildInputDigest": args.build_input_digest,
                "canonicalProducer": "cargo-dist",
            },
            "runtime": {"baseImage": args.runtime_base},
            "payload": {"treeSha256": tree_digest(files), "files": files},
            "artifacts": {
                "executable": "rootfs/usr/local/bin/verdictan",
                "policySchema": "rootfs/usr/share/verdictan/policy-configuration.schema.json",
                "sbom": "sbom.spdx.json",
                "provenance": "provenance.json",
            },
        }
        write_json(stage / "payload-manifest.json", manifest)
        for path in stage.rglob("*"):
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        verify_path(stage)
        if output.exists():
            shutil.rmtree(output)
        os.replace(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def verify_path(root: Path) -> None:
    manifest_path = root / "payload-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != SCHEMA_VERSION or manifest.get("package") != PACKAGE:
        raise ValueError("payload manifest identity is invalid")
    declared = manifest.get("payload", {}).get("files")
    if not isinstance(declared, list) or not declared:
        raise ValueError("payload manifest has no files")
    actual = payload_files(root)
    if actual != declared:
        raise ValueError("payload file inventory or hash does not match the manifest")
    if tree_digest(actual) != manifest["payload"].get("treeSha256"):
        raise ValueError("payload tree digest does not match the manifest")
    executable = root / manifest["artifacts"]["executable"]
    if stat.S_IMODE(executable.stat().st_mode) != 0o755:
        raise ValueError("payload executable mode is not 0755")
    schema = root / manifest["artifacts"]["policySchema"]
    if not schema.is_file():
        raise ValueError("payload policy schema is missing")


def verify_image(root: Path, image: str) -> None:
    verify_path(root)
    manifest = json.loads((root / "payload-manifest.json").read_text(encoding="utf-8"))
    expected = {
        "/" + item["path"].removeprefix("rootfs/"): item["sha256"]
        for item in manifest["payload"]["files"]
        if item["path"].startswith("rootfs/")
    }
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sha256sum",
            image,
            *sorted(expected),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    actual = {}
    for line in result.stdout.splitlines():
        digest, path = line.split(maxsplit=1)
        actual[path.lstrip("*")] = digest
    if actual != expected:
        raise ValueError("final image rootfs hashes do not match the payload manifest")
    smoke = subprocess.run(
        ["docker", "run", "--rm", image, "--version"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if not smoke.stdout.startswith("verdictan "):
        raise ValueError("final image did not report the Verdictan version")


def self_test() -> None:
    repo = Path(__file__).resolve().parents[2]
    dockerfile = (repo / "Dockerfile.hosted").read_text(encoding="utf-8")
    if re.search(r"FROM\s+rust:|RUN[^\n]*cargo|COPY\s+\.\s", dockerfile):
        raise AssertionError("hosted image definition contains a source build")
    for package_script in ("release_extra_deb.sh", "release_extra_rpm.sh"):
        content = (repo / "ci/scripts" / package_script).read_text(encoding="utf-8")
        if 'release_bin="${target_base}/release/verdictan"' in content:
            raise AssertionError(f"{package_script} accepts a non-dist executable")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        binary = root / "verdictan"
        binary.write_bytes(b"canonical-dist-binary\n")
        binary.chmod(0o755)
        common = argparse.Namespace(
            repo_root=repo,
            binary=binary,
            target="x86_64-unknown-linux-gnu",
            source_sha="1" * 40,
            source_date_epoch=0,
            build_input_digest="2" * 64,
            toolchain="rustc-test",
            runtime_base="debian@test",
            builder_id="test-builder",
            invocation_id="test-invocation",
        )
        first = root / "first"
        second = root / "second"
        common.output = first
        pack(common)
        common.output = second
        pack(common)
        if (first / "payload-manifest.json").read_bytes() != (
            second / "payload-manifest.json"
        ).read_bytes():
            raise AssertionError("identical inputs produced different manifests")
        verify_path(first)
        (first / "rootfs/usr/local/bin/verdictan").write_bytes(b"changed")
        try:
            verify_path(first)
        except ValueError:
            return
        raise AssertionError("verification accepted a modified executable")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subparsers = value.add_subparsers(dest="command", required=True)
    pack_parser = subparsers.add_parser("pack")
    pack_parser.add_argument("--repo-root", type=Path, required=True)
    pack_parser.add_argument("--binary", type=Path, required=True)
    pack_parser.add_argument("--output", type=Path, required=True)
    pack_parser.add_argument("--target", required=True)
    pack_parser.add_argument("--source-sha", required=True)
    pack_parser.add_argument("--source-date-epoch", type=int, required=True)
    pack_parser.add_argument("--build-input-digest", required=True)
    pack_parser.add_argument("--toolchain", required=True)
    pack_parser.add_argument("--runtime-base", required=True)
    pack_parser.add_argument("--builder-id", required=True)
    pack_parser.add_argument("--invocation-id", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("payload", type=Path)
    image_parser = subparsers.add_parser("verify-image")
    image_parser.add_argument("--image", required=True)
    image_parser.add_argument("payload", type=Path)
    subparsers.add_parser("self-test")
    return value


def main() -> None:
    args = parser().parse_args()
    if args.command == "pack":
        pack(args)
    elif args.command == "verify":
        verify_path(args.payload.resolve())
    elif args.command == "verify-image":
        verify_image(args.payload.resolve(), args.image)
    else:
        self_test()


if __name__ == "__main__":
    main()
