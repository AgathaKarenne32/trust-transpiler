#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

check_racket() {
  if ! command -v racket &> /dev/null; then
    echo "❌ Racket não encontrado."
    exit 1
  fi
}

# --- NOVA LÓGICA DE PRECEDÊNCIA ---
# Se o argumento começar com '--', enviamos TUDO diretamente para o main.rkt
# Isso resolve o erro no CI/CD pois o --diff será passado intacto
if [[ "$1" == --* ]]; then
    check_racket
    racket main.rkt "$@"
    exit $?
fi

# --- LÓGICA DE SUBCOMANDOS (Legado) ---
case "${1:-help}" in
  demo) 
    check_racket
    racket main.rkt --demo 
    ;;
  watch) 
    check_racket
    racket main.rkt --watch "$2" 
    ;;
  fix) 
    shift; 
    racket main.rkt fix "$@" 
    ;; 
  scan) 
    check_racket
    shift
    racket main.rkt "$@" 
    ;;
  test) 
    if [ -f "test/taint_test.rkt" ]; then racket test/taint_test.rkt; else exit 1; fi 
    ;;
  help|--help|-h)
    echo "Comandos: demo, scan <file>, test, watch <path>, fix <file>"
    ;;
  *)
    echo "Comando desconhecido: $1"
    exit 1
    ;;
esac