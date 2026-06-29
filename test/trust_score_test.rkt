#lang racket/base

(require rackunit
         rackunit/text-ui
         "../src/uir.rkt"
         "../src/types.rkt"
         "../src/trust_score.rkt")

(define test-loc (src-location "<test>" 1 0))

(define (mk-violation kind)
  (violation kind 'x 'sink (list 'x) test-loc 0.9 'HIGH))

(define (run-my-tests)
  (run-tests
    (test-suite "Trust Score"

      (test-case "Código limpo gera score 100 e nota A"
        (let ([report (compute-trust-score '() 0)])
          (check-equal? (trust-report-score report) 100.0)
          (check-equal? (trust-report-grade report) 'A)))

      (test-case "Um unsanitized-sink reduz o score em 18 pontos"
        (let ([report (compute-trust-score (list (mk-violation 'unsanitized-sink)) 0)])
          (check-equal? (trust-report-score report) 82.0)
          (check-equal? (trust-report-grade report) 'B)))

      (test-case "unknown-api penaliza mesmo sem violações de taint (contador extra)"
        (let ([report (compute-trust-score '() 2)])
          (check-equal? (trust-report-score report) 76.0)
          (check-equal? (trust-report-grade report) 'B)))

      (test-case "unknown-api como violation? também penaliza"
        (let ([report (compute-trust-score (list (mk-violation 'unknown-api)) 0)])
          (check-equal? (trust-report-score report) 88.0)
          (check-equal? (trust-report-grade report) 'B)))

      (test-case "Muitas violações levam a score 0 e nota F"
        (let ([report (compute-trust-score
                        (list (mk-violation 'unsanitized-sink)
                              (mk-violation 'unsanitized-sink)
                              (mk-violation 'unsanitized-sink)
                              (mk-violation 'unsanitized-sink)
                              (mk-violation 'unsanitized-sink)
                              (mk-violation 'unsanitized-sink))
                        5)])
          (check-equal? (trust-report-score report) 0.0)
          (check-equal? (trust-report-grade report) 'F)))

      (test-case "Grade boundaries"
        (check-equal? (trust-score->grade 90) 'A)
        (check-equal? (trust-score->grade 89.9) 'B)
        (check-equal? (trust-score->grade 75) 'B)
        (check-equal? (trust-score->grade 60) 'C)
        (check-equal? (trust-score->grade 40) 'D)
        (check-equal? (trust-score->grade 39.9) 'F))

      (test-case "jsexpr contém os campos esperados"
        (let* ([report (compute-trust-score (list (mk-violation 'policy-violation)) 1)]
               [j (trust-report->jsexpr report)])
          (check-equal? (hash-ref j 'grade) "B")
          (check-equal? (hash-ref j 'unknown_api_count) 1)
          (check-equal? (hash-ref (hash-ref j 'breakdown) 'policy-violation) 1))))))

(run-my-tests)