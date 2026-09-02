from __future__ import annotations

import ast
import tomllib
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src" / "qnty_authority_root"
FORBIDDEN_IMPORTS = {
    "requests",
    "httpx",
    "aiohttp",
    "socket",
    "urllib",
    "web3",
    "eth_account",
    "qntyspot",
}


def test_production_source_has_no_network_or_qntyspot_runtime_imports() -> None:
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
                assert not names & FORBIDDEN_IMPORTS, (path, names & FORBIDDEN_IMPORTS)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in FORBIDDEN_IMPORTS, (path, node.module)


def test_production_source_has_no_private_key_or_transaction_surfaces() -> None:
    source = "\n".join(path.read_text() for path in SRC.glob("*.py"))
    assert "Ed25519PrivateKey" not in source
    assert "os.environ" not in source
    assert "provision" not in source.lower()
    assert "wallet" not in source.lower()
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        names = {
            node.name.lower()
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        assert not any("transaction" in name for name in names), (path, names)


def test_dependency_boundary_has_no_qntyspot_runtime_dependency() -> None:
    document = tomllib.loads((SRC.parents[1] / "pyproject.toml").read_text())
    dependencies = document["project"]["dependencies"]
    assert not any("qntyspot" in dependency.lower() for dependency in dependencies)
    assert any("cryptography" in dependency for dependency in dependencies)
