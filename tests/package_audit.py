"""Offline package, source-safety, retained-input, and evidence integrity audit."""
from __future__ import annotations

import ast
import csv
import json
import re
import resource
import stat
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "results" / "package-audit.json"
ALLOWED_TOP_LEVEL = {
    "LICENSE", "README.md", "claim_evidence_ledger.csv", "data",
    "external_resources.csv", "licenses", "proofs", "reproduce.py",
    "results", "src", "tests", "upstream", "reviewer-evidence-ledger.csv",
}
EXPECTED_PYTHON_FILES = ['reproduce.py', 'src/builder_adapter.py', 'src/capsule.py', 'src/checker.py', 'src/corpus_adapter.py', 'src/cutcheck.py', 'src/cuts.py', 'src/diagnose.py', 'src/emitter.py', 'src/fixtures.py', 'src/freshness.py', 'src/ledger.py', 'src/merge.py', 'src/reviewer_hardening.py', 'tests/boundaries.py', 'tests/builder_bridge.py', 'tests/campaign.py', 'tests/context.py', 'tests/deployment.py', 'tests/emitter_worker.py', 'tests/finite.py', 'tests/freshness.py', 'tests/freshness_worker.py', 'tests/natural.py', 'tests/package_audit.py', 'tests/pilot.py', 'tests/reviewer_hardening.py', 'tests/runner_guards.py', 'tests/scaling.py']
FORBIDDEN_NETWORK_ROOTS = {
    "aiohttp", "ftplib", "http", "httplib", "requests", "socket", "telnetlib",
    "urllib", "urllib3", "webbrowser",
}
FORBIDDEN_CALL_NAMES = {"eval", "exec", "compile", "__import__", "os.system"}
UPSTREAM_COMMIT = "bebec929edd826f19b5fa3538f22d18d5b50da4b"
UPSTREAM_BLOB = "446313901df4de049a3cfc473152f438b542c799"
HUMANEVAL_COMMIT = "6d43fb980f9fee3c892a914eda09951f772ad10d"
HUMANEVAL_BLOB = "06236282a45e10e92233e2b8f84cea10ae25be46"
REFERENCE_UPSTREAM = '''
def benchmark_name_to_filter_reason(benchmark_name: str):
    return f"{benchmark_name}_match"


def find_substrings(data, filter_out, return_matched=False):
    content = data['content'].lower()
    for benchmark, substrings in filter_out.items():
        for substring in substrings:
            if substring.lower() in content:
                if return_matched:
                    return False, benchmark_name_to_filter_reason(benchmark), substring
                else:
                    return False, benchmark_name_to_filter_reason(benchmark)
    if return_matched:
        return True, None, None
    else:
        return True, None
'''
EXPECTED_HUMANEVAL = {
    "task_id": "test/0",
    "prompt": "def return1():\n",
    "canonical_solution": "    return 1",
    "test": "def check(candidate):\n    assert candidate() == 1",
    "entry_point": "return1",
}


class PackageAuditError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageAuditError(message)


def call_name(node: ast.Call) -> str:
    target = node.func
    parts = []
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    return ".".join(reversed(parts))


def public_input_audit() -> dict:
    selection = json.loads((ROOT / "data" / "selection.json").read_text(encoding="utf-8"))
    projects = selection.get("projects")
    files = selection.get("files")
    require(type(projects) is list and len(projects) == 6, "selection project count")
    require(type(files) is list and len(files) == 24, "selection file count")
    expected_paths = set()
    per_project = Counter()
    total_bytes = 0
    total_lines = 0
    for record in files:
        require(type(record) is dict, "selection file record")
        relative = record.get("file")
        require(type(relative) is str and relative and relative not in expected_paths,
                "duplicate or invalid selected path")
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                "unsafe selected path")
        expected_paths.add(relative)
        path = ROOT / "data" / "public" / relative
        require(path.is_file() and not path.is_symlink(), f"missing selected file {relative}")
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise PackageAuditError(f"non-UTF-8 selected file {relative}") from exc
        # Do not count the empty split segment after a terminal LF as a line.
        physical_lines = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
        require(len(raw) == record.get("bytes"), f"byte count mismatch for {relative}")
        require(physical_lines == record.get("lines"), f"line count mismatch for {relative}")
        license_path = ROOT / record.get("retained_license", "")
        require(license_path.is_file() and license_path.stat().st_size > 0,
                f"missing retained license for {relative}")
        require(type(record.get("source")) is str and record["source"].startswith("https://"),
                f"missing source locator for {relative}")
        total_bytes += len(raw)
        total_lines += physical_lines
        per_project[record.get("project")] += 1
    actual_paths = {
        str(path.relative_to(ROOT / "data" / "public"))
        for path in (ROOT / "data" / "public").rglob("*") if path.is_file()
    }
    require(actual_paths == expected_paths, "selected file inventory mismatch")
    require(set(per_project.values()) == {4} and len(per_project) == 6,
            "expected four files per project")
    for project in projects:
        require(project.get("files") == per_project[project.get("display")],
                f"project count mismatch for {project.get('display')}")
        license_path = ROOT / project.get("license_file", "")
        require(license_path.is_file() and license_path.stat().st_size > 0,
                f"project license missing for {project.get('display')}")
    require((total_bytes, total_lines) == (268614, 8191), "frozen input totals changed")
    return {
        "selection_projects": len(projects),
        "selection_files": len(files),
        "selection_bytes": total_bytes,
        "selection_physical_lines": total_lines,
        "all_selected_files_end_in_LF": all((ROOT / "data/public" / name).read_bytes().endswith(b"\n") for name in expected_paths),
        "files_per_project": dict(sorted(per_project.items())),
        "all_selected_files_utf8": True,
        "all_selected_files_have_retained_license": True,
    }


def source_audit() -> dict:
    python_files = sorted(
        [ROOT / "reproduce.py"]
        + list((ROOT / "src").glob("*.py"))
        + list((ROOT / "tests").glob("*.py"))
    )
    require([str(path.relative_to(ROOT)) for path in python_files] == EXPECTED_PYTHON_FILES,
            "maintained Python source inventory mismatch")
    for directory in ("src", "tests"):
        require({str(path.relative_to(ROOT)) for path in (ROOT / directory).iterdir() if path.is_file()}
                == {name for name in EXPECTED_PYTHON_FILES if name.startswith(directory + "/")},
                "unexpected source/test file")
    forbidden_imports = []
    forbidden_calls = []
    shell_calls = []
    dynamic_import_sites = []
    import_graph: dict[str, set[str]] = {}
    for path in python_files:
        relative = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=relative)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    imports.add(root)
                    if root in FORBIDDEN_NETWORK_ROOTS:
                        forbidden_imports.append([relative, node.lineno, alias.name])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root = node.module.split(".")[0]
                    imports.add(root)
                    if root in FORBIDDEN_NETWORK_ROOTS:
                        forbidden_imports.append([relative, node.lineno, node.module])
            elif isinstance(node, ast.Call):
                name = call_name(node)
                if name in FORBIDDEN_CALL_NAMES:
                    forbidden_calls.append([relative, node.lineno, name])
                if name.endswith("spec_from_file_location") or name.endswith("exec_module"):
                    dynamic_import_sites.append([relative, node.lineno, name])
                if name.endswith("subprocess.run") or name.endswith("subprocess.Popen") or name.endswith("subprocess.call"):
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            shell_calls.append([relative, node.lineno, name])
        import_graph[relative] = imports
    require(not forbidden_imports, f"network-capable imports found: {forbidden_imports}")
    require(not forbidden_calls, f"dynamic execution calls found: {forbidden_calls}")
    require(not shell_calls, f"shell=True subprocess call found: {shell_calls}")
    require([(site[0], site[2]) for site in dynamic_import_sites] == [
        ("src/builder_adapter.py", "importlib.util.spec_from_file_location"),
        ("src/builder_adapter.py", "spec.loader.exec_module"),
    ], f"unexpected dynamic import sites: {dynamic_import_sites}")
    hardening_tree = ast.parse((ROOT / "src/reviewer_hardening.py").read_text())
    require(any(isinstance(node, ast.Call) and call_name(node) == "builder_adapter.load_upstream"
                for node in ast.walk(hardening_tree)), "hardening must reuse the complete fixed-path loader")
    require("ledger" not in import_graph["src/checker.py"], "checker imports producer ledger")
    require("checker" not in import_graph["src/ledger.py"], "producer imports checker")
    require("cuts" not in import_graph["src/cutcheck.py"], "cut verifier imports generator")
    return {
        "python_files_ast_parsed": len(python_files),
        "forbidden_network_imports": 0,
        "forbidden_dynamic_execution_calls": 0,
        "shell_true_subprocess_calls": 0,
        "dynamic_import_sites": dynamic_import_sites,
        "producer_checker_cross_imports": 0,
        "cut_generator_verifier_cross_imports": 0,
    }


def retained_upstream_audit() -> dict:
    excerpt_path = ROOT / "upstream" / "bigcode-dataset" / "find_substrings_excerpt.py"
    excerpt = excerpt_path.read_text(encoding="utf-8")
    actual = ast.parse(excerpt)
    reference = ast.parse(REFERENCE_UPSTREAM)
    actual_functions = [node for node in actual.body if isinstance(node, ast.FunctionDef)]
    reference_functions = [node for node in reference.body if isinstance(node, ast.FunctionDef)]
    require([node.name for node in actual_functions] == [node.name for node in reference_functions],
            "retained BigCode function set changed")
    for actual_node, reference_node in zip(actual_functions, reference_functions):
        # Ignore docstrings in the retained upstream function; executable AST must match.
        if (actual_node.body and isinstance(actual_node.body[0], ast.Expr)
                and isinstance(actual_node.body[0].value, ast.Constant)
                and isinstance(actual_node.body[0].value.value, str)):
            actual_node.body = actual_node.body[1:]
        require(ast.dump(actual_node, include_attributes=False) == ast.dump(reference_node, include_attributes=False),
                f"retained upstream function AST changed: {actual_node.name}")
    adapter = (ROOT / "src" / "builder_adapter.py").read_text(encoding="utf-8")
    notice = (ROOT / "upstream" / "bigcode-dataset" / "NOTICE.md").read_text(encoding="utf-8")
    for token in (UPSTREAM_COMMIT, UPSTREAM_BLOB):
        require(token in adapter and token in notice and token in excerpt,
                f"BigCode source identity missing: {token}")
    human_path = ROOT / "upstream" / "human-eval" / "example_problem.jsonl"
    lines = human_path.read_text(encoding="utf-8").splitlines()
    require(len(lines) == 1 and json.loads(lines[0]) == EXPECTED_HUMANEVAL,
            "retained HumanEval example changed")
    human_notice = (ROOT / "upstream" / "human-eval" / "NOTICE.md").read_text(encoding="utf-8")
    for token in (HUMANEVAL_COMMIT, HUMANEVAL_BLOB):
        require(token in adapter and token in human_notice, f"HumanEval source identity missing: {token}")
    require("The MIT License" in (ROOT / "upstream" / "human-eval" / "LICENSE").read_text(encoding="utf-8"),
            "HumanEval MIT license missing")
    require("Apache License" in (ROOT / "upstream" / "bigcode-dataset" / "LICENSE").read_text(encoding="utf-8"),
            "BigCode Apache license missing")
    return {
        "retained_bigcode_functions_ast_matched": len(actual_functions),
        "bigcode_commit_and_blob_identifiers_present": True,
        "humaneval_example_exact_record_matched": True,
        "humaneval_commit_and_blob_identifiers_present": True,
        "upstream_license_files_present": 2,
    }



def emitter_publication_audit() -> dict:
    """Check the source-level invariants of the bounded POSIX publication path."""
    emitter_path = ROOT / "src" / "emitter.py"
    text = emitter_path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename="src/emitter.py")
    calls: list[tuple[str, ast.Call]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append((call_name(node), node))
    call_counts = Counter(name for name, _ in calls)
    require(call_counts["os.link"] == 1, "emitter must have exactly one atomic hard-link commit")
    require(call_counts["os.fsync"] >= 3, "emitter must synchronize the file and directory transitions")
    require(call_counts["os.open"] >= 2, "emitter must open both directory and exclusive temporary file")
    require(call_counts["os.unlink"] >= 1, "emitter must remove only its temporary name")
    for forbidden in ("os.replace", "os.rename", "Path.replace", "Path.rename"):
        require(call_counts[forbidden] == 0, f"emitter uses forbidden overwrite-capable publication call {forbidden}")
    require("os.O_EXCL" in text and "O_NOFOLLOW" in text,
            "emitter must use exclusive creation and no-follow flags")
    require("follow_symlinks=False" in text, "hard-link/stat operations must disable symlink following")
    for name, node in calls:
        if name == "os.unlink":
            require(node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == "temp_name",
                    "emitter may unlink only the private temporary name")
    require("os.unlink(basename" not in text and "destination.unlink" not in text,
            "emitter contains destination-removal logic")

    argument_text = (ROOT / "proofs" / "arguments.md").read_text(encoding="utf-8").lower()
    for phrase in (
        "same-directory temporary",
        "create-if-absent hard link",
        "never unlinks a committed destination",
        "power-loss",
    ):
        require(phrase in argument_text, f"publication argument omits required boundary phrase: {phrase}")
    return {
        "atomic_hard_link_commits": call_counts["os.link"],
        "fsync_calls": call_counts["os.fsync"],
        "overwrite_capable_publication_calls": 0,
        "destination_unlink_calls": 0,
        "exclusive_and_no_follow_flags_present": True,
        "proof_implementation_boundary_aligned": True,
    }

def evidence_table_audit() -> dict:
    with (ROOT / "external_resources.csv").open(newline="", encoding="utf-8") as handle:
        resources = list(csv.DictReader(handle))
    require(len(resources) == 118, "external resource inventory count changed")
    required_resource_fields = set(resources[0])
    require(required_resource_fields == {
        "name", "url", "license", "access_date", "resource_type", "acquisition_method",
        "integration_mode", "supported_claim", "internals_modified", "access_or_identity_limit",
    }, "external resource header changed")
    for row in resources:
        require(all(row[field].strip() for field in required_resource_fields),
                f"incomplete external resource row: {row.get('name')}")
        require(row["url"].startswith("https://"), f"non-HTTPS resource locator: {row['name']}")
        require(re.fullmatch(r"20\d{2}-\d{2}-\d{2}", row["access_date"]) is not None,
                f"invalid access date: {row['name']}")
        require(row["internals_modified"].startswith("No"), f"modified external internals: {row['name']}")
    scholarly = [row for row in resources if "scholarly" in row["resource_type"].lower() or "technical standard" in row["resource_type"].lower()]
    require(len(scholarly) == 85, "scholarly/standard resource count changed")

    with (ROOT / "claim_evidence_ledger.csv").open(newline="", encoding="utf-8") as handle:
        claims = list(csv.DictReader(handle))
    require(len(claims) >= 25, "claim-evidence ledger unexpectedly short")
    require(len({row["claim_id"] for row in claims}) == len(claims), "duplicate claim identifier")
    for row in claims:
        require(all(value.strip() for value in row.values()), f"incomplete claim row {row.get('claim_id')}")
    with (ROOT / "reviewer-evidence-ledger.csv").open(newline="", encoding="utf-8") as handle:
        reviewer_rows = list(csv.DictReader(handle))
    require(len(reviewer_rows) == 8, "additional-evidence ledger inventory")
    require(all(row.get("status") and row.get("evidence") for row in reviewer_rows),
            "additional-evidence status missing")
    return {
        "additional_evidence_rows": len(reviewer_rows),
        "unavailable_inherited_ancillary_records": sum(row["status"] == "unavailable-not-reconstructed" for row in reviewer_rows),
        "external_resource_rows": len(resources),
        "scholarly_or_standard_resource_rows": len(scholarly),
        "claim_evidence_rows": len(claims),
        "all_resource_locators_https": True,
        "external_internals_modified": 0,
    }


def package_shape_audit() -> dict:
    actual_top = {path.name for path in ROOT.iterdir()}
    require(actual_top == ALLOWED_TOP_LEVEL,
            f"artifact top-level mismatch: {sorted(actual_top ^ ALLOWED_TOP_LEVEL)}")
    symlinks = []
    nested_archives = []
    cache_artifacts = []
    forbidden_names = []
    for path in ROOT.rglob("*"):
        relative = str(path.relative_to(ROOT))
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            symlinks.append(relative)
        if path.is_file() and path.suffix.lower() in {".zip", ".tar", ".tgz", ".gz", ".7z"}:
            nested_archives.append(relative)
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}:
            cache_artifacts.append(relative)
        lower = relative.lower()
        if any(token in lower for token in ("prompt", "chat-history", "credentials", ".git/")):
            forbidden_names.append(relative)
    require(not symlinks, f"symlinks in artifact: {symlinks}")
    require(not nested_archives, f"nested archives in artifact: {nested_archives}")
    require(not cache_artifacts, f"cache artifacts in artifact: {cache_artifacts}")
    require(not forbidden_names, f"forbidden workflow/private names: {forbidden_names}")
    return {
        "top_level_entries": sorted(actual_top),
        "symlinks": 0,
        "nested_archives": 0,
        "python_cache_artifacts": 0,
        "forbidden_workflow_or_private_names": 0,
    }


def main() -> None:
    cpu = time.process_time()
    wall = time.perf_counter()
    result = {
        "status": "passed",
        "package_shape": package_shape_audit(),
        "public_inputs": public_input_audit(),
        "source_safety": source_audit(),
        "emitter_publication": emitter_publication_audit(),
        "retained_upstream": retained_upstream_audit(),
        "evidence_tables": evidence_table_audit(),
        "scope": (
            "Offline package-shape, retained-byte accounting, AST-level source-safety, publication-source invariants, "
            "upstream-excerpt identity, and evidence-table integrity checks. These checks do not prove semantic correctness, "
            "arbitrary-file-system durability, or remote source availability."
        ),
        "cpu_seconds": time.process_time() - cpu,
        "wall_seconds": time.perf_counter() - wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    RESULT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
