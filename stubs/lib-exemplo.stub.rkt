#lang racket/base
(require "../src/stub-registry.rkt")

(register-stub! 'lib-exemplo
  '((sinks . (lib-exemplo.processar))
    (sources . ())
    (sanitizers . ())))

