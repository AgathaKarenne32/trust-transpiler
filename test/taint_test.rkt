#lang racket/base

(require rackunit
         rackunit/text-ui
         "../src/uir.rkt"
         "../src/taint_engine.rkt")

(define test-loc (src-location "<test>" 1 0))

(define (run-my-tests)
  (run-tests 
    (test-suite "Trust-Transpiler Taint Analysis Tests"
      (test-case "Teste A: Propagação"
        (let* ([stmt1 (uir:assign 'user_input "source()" taint:tainted test-loc)]
               [stmt2 (uir:assign 'x 'user_input taint:clean test-loc)]
               [prog (uir:sequence (list stmt1 stmt2) test-loc)]
               [result (analyze-program prog)]
               [env (analysis-result-final-env result)])
          (check-equal? (env-lookup env 'x) taint:tainted)))
      
      (test-case "Teste C: Detecção Sink"
        (let* ([stmt1 (uir:assign 'query_param "source()" taint:tainted test-loc)]
               [stmt2 (uir:call 'log (list 'query_param) #t test-loc)]
               [prog (uir:sequence (list stmt1 stmt2) test-loc)]
               [result (analyze-program prog)])
          (check-equal? (length (analysis-result-violations result)) 1))))))

(run-my-tests)