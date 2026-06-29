"""Agente autônomo de revisão de PR para o Trust-Transpiler.

Roda no CI (GitHub Actions), escaneia os arquivos alterados de um PR,
posta um comentário consolidado com o Trust Score e as violações
encontradas, e decide se o PR deve ser bloqueado.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests

GITHUB_API = "https://api.github.com"
SUPPORTED_EXTENSIONS = (".tt",)
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}
MIN_TRUST_SCORE = 60.0


@dataclass
class FileReport:
    path: str
    trust_score: float
    grade: str
    violations: list = field(default_factory=list)
    patches: list = field(default_factory=list)
    error: Optional[str] = None


def get_changed_files(repo: str, pr_number: str, token: str) -> list:
    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    files = []
    page = 1
    while True:
        resp = requests.get(url, headers=headers, params={"per_page": 100, "page": page}, timeout=30)
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        files.extend(f["filename"] for f in batch if f["status"] != "removed")
        page += 1
    return [f for f in files if f.endswith(SUPPORTED_EXTENSIONS)]


def scan_file(file_path: str, racket_main: str) -> FileReport:
    try:
        result = subprocess.run(
            ["racket", racket_main, "--json-report", file_path],
            capture_output=True, text=True, timeout=60,
        )
        # main.rkt imprime outras linhas de debug; o JSON é a última linha válida.
        json_line = next(line for line in reversed(result.stdout.splitlines()) if line.strip().startswith("{"))
        payload = json.loads(json_line)
        trust = payload["trust_score"]
        return FileReport(
            path=file_path,
            trust_score=trust["score"],
            grade=trust["grade"],
            violations=payload["violations"],
            patches=payload["patches"],
        )
    except Exception as exc:  # noqa: BLE001 - relatamos qualquer falha de scan, não escondemos
        return FileReport(path=file_path, trust_score=0.0, grade="F", error=str(exc))


def format_comment(reports: list) -> str:
    if not reports:
        return "## 🤖 Trust-Transpiler — Revisão de PR\n\nNenhum arquivo suportado (`.tt`) foi alterado neste PR."

    lines = ["## 🤖 Trust-Transpiler — Revisão de PR\n"]
    for r in reports:
        if r.error:
            lines.append(f"### ⚠️ `{r.path}`\nErro ao escanear: `{r.error}`\n")
            continue

        lines.append(f"### `{r.path}` — Trust Score: **{r.trust_score:.1f} ({r.grade})**\n")
        if not r.violations:
            lines.append("Nenhuma violação encontrada.\n")
            continue

        lines.append("| Severidade | Sink | Origem | Caminho de Taint |")
        lines.append("|---|---|---|---|")
        for v in r.violations:
            path = " → ".join(v["taint_path"])
            lines.append(f"| {v['severity']} | `{v['sink']}` | `{v['source']}` | {path} |")
        lines.append("")

        if r.patches:
            lines.append("**Sugestões de correção:**")
            for p in r.patches:
                lines.append(f"- `{p['code_suggestion']}` _(sanitizer: {p['sanitizer_fn']}, confiança: {p['confidence']:.2f})_")
            lines.append("")

    return "\n".join(lines)


def decide_gate(reports: list) -> bool:
    """Retorna True se o PR deve ser BLOQUEADO."""
    for r in reports:
        if r.error:
            return True
        if r.trust_score < MIN_TRUST_SCORE:
            return True
        if any(v["severity"] in BLOCKING_SEVERITIES for v in r.violations):
            return True
    return False


def post_comment(repo: str, pr_number: str, token: str, body: str) -> None:
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    resp = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    resp.raise_for_status()


def main() -> int:
    repo = os.environ["GITHUB_REPOSITORY"]
    pr_number = os.environ["PR_NUMBER"]
    token = os.environ["GITHUB_TOKEN"]
    racket_main = os.environ.get("RACKET_MAIN_PATH", "main.rkt")

    changed = get_changed_files(repo, pr_number, token)
    reports = [scan_file(f, racket_main) for f in changed]

    comment = format_comment(reports)
    post_comment(repo, pr_number, token, comment)

    if decide_gate(reports):
        print("Trust-Transpiler: PR bloqueado — score abaixo do mínimo ou violação crítica.")
        return 1

    print("Trust-Transpiler: PR aprovado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())