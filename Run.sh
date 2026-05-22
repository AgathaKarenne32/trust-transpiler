#!/usr/bin/env bash
# =============================================================================
# trust-transpiler — Script de Execução
# =============================================================================
# Uso:
#   ./run.sh demo                    # Executa análise de demonstração
#   ./run.sh scan examples/vulnerable.tt  # Analisa arquivo específico
#   ./run.sh test                    # Roda suíte de testes unitários
#   ./run.sh scan --no-color <file>  # Saída sem ANSI (para CI/CD)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

check_racket() {
  if ! command -v racket &> /dev/null; then
    echo "❌ Racket não encontrado. Instale em: https://racket-lang.org/download/"
    exit 1
  fi
}

case "${1:-help}" in
  demo)
    check_racket
    echo "→ Executando análise de demonstração..."
    racket main.rkt --demo
    ;;

  scan)
    check_racket
    shift
    if [ -z "$1" ]; then
      echo "Uso: ./run.sh scan <arquivo.tt>"
      exit 1
    fi
    echo "→ Analisando: $*"
    racket main.rkt "$@"
    ;;

  test)
    check_racket
    echo "→ Executando suíte de testes unitários..."
    racket tests/taint-tests.rkt
    ;;

  help|--help|-h)
    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║  Trust-Transpiler SAST Framework     ║"
    echo "╚══════════════════════════════════════╝"
    echo ""
    echo "Comandos disponíveis:"
    echo "  ./run.sh demo                    — Análise de demonstração"
    echo "  ./run.sh scan <arquivo.tt>       — Analisa arquivo .tt"
    echo "  ./run.sh scan --no-color <file>  — Sem cores (CI/CD)"
    echo "  ./run.sh test                    — Executa testes unitários"
    echo ""
    ;;

  *)
    echo "Comando desconhecido: $1"
    echo "Execute ./run.sh help para ver os comandos disponíveis."
    exit 1
    ;;
esac