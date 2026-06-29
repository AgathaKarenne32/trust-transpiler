from oracle.pr_review_agent import FileReport, decide_gate, format_comment

def make_report(score=100.0, grade="A", violations=None, error=None):
    return FileReport(path="app.tt", trust_score=score, grade=grade,
                       violations=violations or [], error=error)


def test_decide_gate_passes_clean_report():
    assert decide_gate([make_report()]) is False


def test_decide_gate_blocks_low_score():
    assert decide_gate([make_report(score=40.0, grade="D")]) is True


def test_decide_gate_blocks_critical_severity():
    v = [{"severity": "HIGH", "sink": "query", "source": "x", "taint_path": ["x"]}]
    assert decide_gate([make_report(violations=v)]) is True


def test_decide_gate_blocks_on_scan_error():
    assert decide_gate([make_report(error="timeout")]) is True


def test_format_comment_no_files():
    assert "Nenhum arquivo suportado" in format_comment([])


def test_format_comment_includes_violation_table():
    v = [{"severity": "HIGH", "sink": "query", "source": "user_input", "taint_path": ["user_input", "query"]}]
    body = format_comment([make_report(score=82.0, grade="B", violations=v)])
    assert "query" in body
    assert "82.0 (B)" in body