#lang racket/base

(require rackunit
         rackunit/text-ui
         "../src/uir.rkt"
         "../src/taint_engine.rkt")

(define test-loc (src-location "<test>" 1 0))

(define test-taint-propagation
  (test-case "Teste A: Propagação"
    (let* ([stmt1 (uir:assign 'user_input "source()" taint:tainted test-loc)]
           [stmt2 (uir:assign 'x 'user_input taint:clean test-loc)]
           [stmt3 (uir:assign 'y 'x taint:clean test-loc)]
           [prog (uir:sequence (list stmt1 stmt2 stmt3) test-loc)]
           [result (analyze-program prog)]
           [env (analysis-result-final-env result)])
      (check-equal? (env-lookup env 'y) taint:tainted))))

(define test-taint-sanitization
  (test-case "Teste B: Sanitização"
    (let* ([stmt1 (uir:assign 'raw "source()" taint:tainted test-loc)]
           [stmt2 (uir:call 'sanitize (list 'raw) #f test-loc)]
           [stmt3 (uir:assign 'safe 'raw taint:clean test-loc)]
           [prog (uir:sequence (list stmt1 stmt2 stmt3) test-loc)]
           [result (analyze-program prog)]
           [env (analysis-result-final-env result)])
      (check-equal? (env-lookup env 'raw) taint:sanitized))))

(define test-unsafe-flow-detection
  (test-case "Teste C: Detecção Sink"
    (let* ([stmt1 (uir:assign 'query_param "source()" taint:tainted test-loc)]
           [stmt2 (uir:call 'log (list 'query_param) #t test-loc)]
           [prog (uir:sequence (list stmt1 stmt2) test-loc)]
           [result (analyze-program prog)])
      (check-equal? (length (analysis-result-violations result)) 1))))

;; O segredo: chamar explicitamente o runner aqui fora de qualquer módulo
(run-tests 
  (test-suite "Trust-Transpiler Taint Analysis Tests"
    test-taint-propagation
    test-taint-sanitization
    test-unsafe-flow-detection))