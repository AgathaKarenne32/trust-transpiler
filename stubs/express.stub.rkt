#lang racket/base
(require "../src/stub-registry.rkt")

;; Definindo o comportamento de segurança do Express
;; Isso será consultado pelo seu taint_engine
(register-stub! 'express 
  '((sinks . (res.send res.json))
    (sources . (req.body req.query))
    (sanitizers . (express-validator))))