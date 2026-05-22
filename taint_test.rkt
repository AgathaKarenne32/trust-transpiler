#lang racket/base

;;; =============================================================================
;;; trust-transpiler/tests/taint-tests.rkt
;;; Suíte de Testes Unitários — rackunit
;;;
;;; Três casos de teste obrigatórios:
;;;   a) Propagação correta de um taint
;;;   b) Sanitização de um taint
;;;   c) Detecção de um fluxo inseguro (Source → Sink)
;;;
;;; Os testes constroem nós UIR diretamente (sem o parser) para isolar
;;; o motor de análise e garantir testes verdadeiramente unitários.
;;; =============================================================================

(require rackunit
         rackunit/text-ui
         "../src/uir.rkt"
         "../src/taint_engine.rkt")

;; Localização fictícia para os testes
(define test-loc (src-location "<test>" 1 0))

;; =============================================================================
;; TESTE A — Propagação Correta de Taint
;;
;; Cenário:
;;   let user_input = source()   ; SOURCE: user_input fica TAINTED
;;   let x = user_input          ; PROPAGAÇÃO: x herda o taint de user_input
;;   let y = x                   ; PROPAGAÇÃO: y herda o taint de x
;;
;; Expectativa: após a sequência, tanto x quanto y devem estar TAINTED.
;; Nenhuma violação deve ser emitida (não há sink neste teste).
;; =============================================================================
(define test-taint-propagation
  (test-case
    "Teste A: Propagação correta de taint através de atribuições"

    ;; Construção manual da UIR (sem parser — teste unitário puro)
    (let* ([stmt1  (uir:assign 'user_input "source()" taint:tainted test-loc)]
           [stmt2  (uir:assign 'x 'user_input taint:clean test-loc)]
           [stmt3  (uir:assign 'y 'x taint:clean test-loc)]
           [prog   (uir:sequence (list stmt1 stmt2 stmt3) test-loc)]
           [result (analyze-program prog)]
           [env    (analysis-result-final-env result)])

      ;; Sem violações (não há sink)
      (check-equal?
        (length (analysis-result-violations result))
        0
        "Não deve haver violações sem um sink")

      ;; user_input deve ser TAINTED (é o source)
      (check-equal?
        (env-lookup env 'user_input)
        taint:tainted
        "user_input deve estar TAINTED após ser marcado como source")

      ;; x deve herdar o taint de user_input
      (check-equal?
        (env-lookup env 'x)
        taint:tainted
        "x deve estar TAINTED por herança de user_input")

      ;; y deve herdar o taint de x (propagação transitiva)
      (check-equal?
        (env-lookup env 'y)
        taint:tainted
        "y deve estar TAINTED por herança transitiva de x"))))

;; =============================================================================
;; TESTE B — Sanitização de Taint
;;
;; Cenário:
;;   let raw = source()          ; SOURCE: raw fica TAINTED
;;   sanitize(raw)               ; SANITIZADOR: raw deve ficar SANITIZED
;;   let safe = raw              ; safe herda o estado SANITIZED de raw
;;
;; Expectativa: após sanitize(), raw e safe devem ser SANITIZED, não TAINTED.
;; Nenhuma violação deve ser emitida.
;; =============================================================================
(define test-taint-sanitization
  (test-case
    "Teste B: Sanitização quebra a propagação de taint"

    (let* ([stmt1  (uir:assign 'raw "source()" taint:tainted test-loc)]
           ;; sanitize() está em *sanitizer-functions* — marca 'raw como sanitized
           [stmt2  (uir:call 'sanitize (list 'raw) #f test-loc)]
           [stmt3  (uir:assign 'safe 'raw taint:clean test-loc)]
           [prog   (uir:sequence (list stmt1 stmt2 stmt3) test-loc)]
           [result (analyze-program prog)]
           [env    (analysis-result-final-env result)])

      ;; Sem violações
      (check-equal?
        (length (analysis-result-violations result))
        0
        "Sanitização não deve gerar violações")

      ;; raw deve ser SANITIZED após a chamada ao sanitizador
      (check-equal?
        (env-lookup env 'raw)
        taint:sanitized
        "raw deve estar SANITIZED após chamada a sanitize()")

      ;; safe não deve ser TAINTED (herdou SANITIZED, depois virou CLEAN via join)
      (check-not-equal?
        (env-lookup env 'safe)
        taint:tainted
        "safe NÃO deve estar TAINTED após sanitização"))))

;; =============================================================================
;; TESTE C — Detecção de Fluxo Inseguro (Source → Sink)
;;
;; Cenário:
;;   let query_param = source()  ; SOURCE: query_param fica TAINTED
;;   log(query_param)            ; SINK: log() recebe dado TAINTED → VIOLAÇÃO
;;
;; Expectativa: exatamente 1 violação do tipo 'unsanitized-sink,
;; com source-var = query_param e sink-func = log.
;; =============================================================================
(define test-unsafe-flow-detection
  (test-case
    "Teste C: Detecção de fluxo inseguro Source → Sink"

    (let* ([stmt1  (uir:assign 'query_param "source()" taint:tainted test-loc)]
           ;; log() está em *sink-functions* — deve gerar violação
           [stmt2  (uir:call 'log (list 'query_param) #t test-loc)]
           [prog   (uir:sequence (list stmt1 stmt2) test-loc)]
           [result (analyze-program prog)]
           [violations (analysis-result-violations result)])

      ;; Deve haver exatamente 1 violação
      (check-equal?
        (length violations)
        1
        "Deve haver exatamente 1 violação detectada")

      ;; A violação deve ser do tipo correto
      (check-equal?
        (violation-kind (car violations))
        'unsanitized-sink
        "A violação deve ser do tipo 'unsanitized-sink")

      ;; A variável de origem deve ser query_param
      (check-equal?
        (violation-source-var (car violations))
        'query_param
        "A variável de origem da violação deve ser 'query_param")

      ;; O sink deve ser a função log
      (check-equal?
        (violation-sink-func (car violations))
        'log
        "O sink da violação deve ser a função 'log"))))

;; =============================================================================
;; TESTE BÔNUS D — Branch: Taint em apenas um caminho
;;
;; Cenário:
;;   let a = source()            ; a é TAINTED
;;   if (flag)
;;     let b = a                 ; b herda taint APENAS no branch then
;;   (sem else)
;;   query(b)                    ; SINK — b pode ou não estar tainted
;;
;; Expectativa: análise conservadora → violação detectada.
;; =============================================================================
(define test-branch-taint
  (test-case
    "Teste D (Bônus): Análise conservadora em branches"

    (let* ([stmt1   (uir:assign 'a "source()" taint:tainted test-loc)]
           [then-b  (uir:assign 'b 'a taint:clean test-loc)]
           [stmt2   (uir:branch 'flag then-b (uir:noop test-loc) test-loc)]
           [stmt3   (uir:call 'query (list 'b) #t test-loc)]
           [prog    (uir:sequence (list stmt1 stmt2 stmt3) test-loc)]
           [result  (analyze-program prog)]
           [violations (analysis-result-violations result)])

      ;; Análise conservadora deve detectar o fluxo potencialmente inseguro
      (check-equal?
        (length violations)
        1
        "Análise conservadora deve detectar fluxo tainted em branch then"))))

;; =============================================================================
;; Runner — Executa toda a suíte
;; =============================================================================
(define (run-all-tests)
  (displayln "\n=== Trust-Transpiler — Suíte de Testes Unitários ===\n")
  (run-tests
    (test-suite
      "Trust-Transpiler Taint Analysis Tests"
      test-taint-propagation
      test-taint-sanitization
      test-unsafe-flow-detection
      test-branch-taint)))

;; Executa automaticamente quando o arquivo é rodado diretamente
(module+ main
  (exit (run-all-tests)))