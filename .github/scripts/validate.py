"""Validate the public checkout, package, installed consumer, and local lab."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "Build"
SOURCE = ROOT
DOC = ROOT / "项目文档"
STAGE = BUILD / "stage"
DIST = BUILD / "dist"
VENV = BUILD / "venv"
CONSUMER = BUILD / "consumer"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label: str, argv: list[str], cwd: Path, env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
    log = BUILD / (label + ".log")
    log.write_text(result.stdout + result.stderr)
    return {"step": label, "exit_code": result.returncode, "argv": argv,
            "log": str(log), "log_sha256": digest(log)}


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    DIST.mkdir(exist_ok=True)
    CONSUMER.mkdir(exist_ok=True)
    config = tomllib.loads((SOURCE / "pyproject.toml").read_text())
    source_files = sorted(
        [SOURCE / "pyproject.toml", SOURCE / ".github/scripts/validate.py", SOURCE / ".github/workflows/verify.yml"]
        + [path for base in (SOURCE / "src", SOURCE / "tests") for path in base.rglob("*") if path.is_file()]
    )
    manifest = [{"path": str(path.relative_to(SOURCE)), "sha256": digest(path)} for path in source_files]
    receipt: dict[str, object] = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": "ProxyIdentityHeaderTrust",
        "version": config["project"]["version"],
        "author": config["project"]["authors"][0]["name"],
        "source_root": str(SOURCE),
        "documentation_root": str(DOC),
        "source_manifest": manifest,
        "source_manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        "readme_sha256": digest(DOC / "README.md"),
        "license_sha256": digest(DOC / "LICENSE"),
        "reference": {
            "repository": "oauth2-proxy/oauth2-proxy",
            "pinned_snapshot": "bea3f04bf87b93f5354f392fe2216a88e6031350",
            "pinned_snapshot_topic": "v7.15.5 release, not this lab's upstream defect fix",
            "license": "MIT",
            "code_copied": False,
        },
        "commands": [], "checks": {}, "status": "OPEN",
    }
    commands = receipt["commands"]
    checks = receipt["checks"]
    assert isinstance(commands, list) and isinstance(checks, dict)
    env = os.environ.copy()
    env["UV_CACHE_DIR"] = str(BUILD / "uv-cache")
    env["PYTHONPYCACHEPREFIX"] = str(BUILD / "pycache")
    source_env = env.copy()
    source_env["PYTHONPATH"] = str(SOURCE / "src")

    def step(label: str, argv: list[str], cwd: Path, step_env: dict[str, str]) -> bool:
        outcome = run(label, argv, cwd, step_env)
        commands.append(outcome)
        checks[label] = outcome["exit_code"] == 0
        return bool(checks[label])

    try:
        if not step("source-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], SOURCE, source_env):
            return 1
        if not step("source-lab", [sys.executable, str(SOURCE / "tests/run_local_experiment.py"), str(BUILD / "lab-source.json")], SOURCE, source_env):
            return 1
        if STAGE.exists():
            shutil.rmtree(STAGE)
        STAGE.mkdir(parents=True)
        shutil.copy2(SOURCE / "pyproject.toml", STAGE / "pyproject.toml")
        for directory in ("src", "tests"):
            shutil.copytree(
                SOURCE / directory, STAGE / directory,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
            )
        shutil.copy2(DOC / "LICENSE", STAGE / "LICENSE")
        checks["staged_own_license"] = digest(STAGE / "LICENSE") == digest(DOC / "LICENSE")
        for artifact in list(DIST.glob("*.whl")) + list(DIST.glob("*.tar.gz")):
            artifact.unlink()
        if not step("build", ["uv", "build", "--out-dir", str(DIST)], STAGE, env):
            return 1
        wheels = sorted(DIST.glob("*.whl"))
        sdists = sorted(DIST.glob("*.tar.gz"))
        checks["one_wheel_and_sdist"] = len(wheels) == len(sdists) == 1
        if not checks["one_wheel_and_sdist"]:
            return 1
        wheel, sdist = wheels[0], sdists[0]
        with zipfile.ZipFile(wheel) as archive:
            wheel_files = sorted(archive.namelist())
            metadata = archive.read(next(name for name in wheel_files if name.endswith(".dist-info/METADATA"))).decode()
        with tarfile.open(sdist, "r:gz") as archive:
            sdist_files = sorted(archive.getnames())
        checks["wheel_runtime_license_only"] = (
            all(name in wheel_files for name in (
                "proxy_identity_header_trust/__init__.py",
                "proxy_identity_header_trust/lab.py",
                "proxy_identity_header_trust/policy.py",
            ))
            and any(name.endswith(".dist-info/licenses/LICENSE") for name in wheel_files)
            and not any("/tests/" in name for name in wheel_files)
        )
        checks["sdist_source_tests_license"] = all(any(name.endswith(suffix) for name in sdist_files) for suffix in (
            "/src/proxy_identity_header_trust/lab.py", "/src/proxy_identity_header_trust/policy.py",
            "/tests/test_proxy_identity.py", "/tests/run_local_experiment.py", "/LICENSE", "/pyproject.toml",
        ))
        checks["metadata_author_version_license"] = all(line in metadata.splitlines() for line in (
            "Name: proxy-identity-header-trust", "Version: 0.1.0", "Author: dhtfish98", "License-Expression: MIT",
        ))
        receipt["artifacts"] = {
            "wheel": {"path": str(wheel), "sha256": digest(wheel), "files": wheel_files},
            "sdist": {"path": str(sdist), "sha256": digest(sdist), "files": sdist_files},
        }
        if not all((checks["wheel_runtime_license_only"], checks["sdist_source_tests_license"], checks["metadata_author_version_license"])):
            return 1
        if not step("venv", ["uv", "venv", "--clear", "--python", sys.executable, str(VENV)], CONSUMER, env):
            return 1
        python = str(VENV / "bin/python")
        if not step("install-wheel", ["uv", "pip", "install", "--python", python, "--no-deps", str(wheel)], CONSUMER, env):
            return 1
        installed_env = env.copy()
        installed_env.pop("PYTHONPATH", None)
        installed_check = (
            "import proxy_identity_header_trust as p; from pathlib import Path; "
            "assert p.__version__ == '0.1.0'; "
            f"assert str(Path(p.__file__).resolve()).startswith({str(VENV.resolve())!r}); "
            "print(p.__version__, p.__file__)"
        )
        if not step("installed-import", [python, "-c", installed_check], CONSUMER, installed_env):
            return 1
        if not step("installed-tests", [python, "-m", "unittest", "discover", "-s", str(SOURCE / "tests"), "-v"], CONSUMER, installed_env):
            return 1
        if not step("installed-lab", [python, str(SOURCE / "tests/run_local_experiment.py"), str(BUILD / "lab-installed.json")], CONSUMER, installed_env):
            return 1
        source_lab = json.loads((BUILD / "lab-source.json").read_text())
        installed_lab = json.loads((BUILD / "lab-installed.json").read_text())
        checks["source_and_installed_lab_pass"] = source_lab["result"] == installed_lab["result"] == "PASS"
        checks["lab_checks_match"] = source_lab["checks"] == installed_lab["checks"]
        checks["source_tree_only_source"] = all(
            not any(part in {"__pycache__", ".pytest_cache", "dist", "build", ".venv"} for part in path.parts)
            and path.suffix.lower() not in {".md", ".rst", ".txt", ".whl", ".gz", ".log", ".json"}
            and path.name != "LICENSE"
            for base in (SOURCE / "src", SOURCE / "tests") for path in base.rglob("*") if path.is_file()
        )
        checks["build_placeholder_and_ignore"] = (
            (BUILD / ".gitignore").read_text() == "*\n!.gitignore\n"
            and "/Build/*" in (ROOT / ".gitignore").read_text().splitlines()
            and "!/Build/.gitignore" in (ROOT / ".gitignore").read_text().splitlines()
        )
        checks["standalone_documentation"] = (
            "/Users/" not in (DOC / "README.md").read_text()
            and ".github/scripts/validate.py" in (DOC / "README.md").read_text()
            and (DOC / "LICENSE").is_file()
        )
        checks["author_version"] = receipt["author"] == "dhtfish98" and receipt["version"] == "0.1.0"
        return 0 if all(checks.values()) else 1
    finally:
        receipt["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        receipt["status"] = "PASS" if checks and all(checks.values()) else "FAIL"
        output = BUILD / "validation.json"
        output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "receipt": str(output), "checks": checks}, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
