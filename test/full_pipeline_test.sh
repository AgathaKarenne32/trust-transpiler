#!/bin/bash
# test/full_pipeline_test.sh

# 1. Setup: Criar um código com vulnerabilidade HIGH
echo "let x = source; query(x);" > test/veto_test.tt

# 2. Executar scan no modo strict
./run.sh test/veto_test.tt --strict-mode > /dev/null 2>&1
EXIT_CODE=$?

# 3. Validar se o Gatekeeper bloqueou (espera-se exit 1)
if [ $EXIT_CODE -eq 1 ]; then
  echo "✅ SUCESSO: Gatekeeper bloqueou código inseguro (Exit 1)."
else
  echo "❌ FALHA: Gatekeeper não bloqueou código inseguro (Exit $EXIT_CODE)."
  exit 1
fi

# 4. Setup: Criar um código seguro (com sanitização)
echo "let x = source; sanitize(x); query(x);" > test/safe_test.tt

# 5. Executar scan novamente
./run.sh test/safe_test.tt --strict-mode > /dev/null 2>&1
EXIT_CODE_SAFE=$?

# 6. Validar se o pipeline permitiu (espera-se exit 0)
if [ $EXIT_CODE_SAFE -eq 0 ]; then
  echo "✅ SUCESSO: Pipeline permitiu código sanitizado (Exit 0)."
else
  echo "❌ FALHA: Pipeline bloqueou código seguro (Exit $EXIT_CODE_SAFE)."
  exit 1
fi