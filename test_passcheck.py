"""Базові тести для passcheck. Запуск: pytest test_passcheck.py"""

from passcheck import analyze_password


def test_common_password_is_weak():
    report = analyze_password("123456", common_set={"123456"})
    assert report.score == 0
    assert report.is_common is True


def test_short_password_is_weak():
    report = analyze_password("aB1!", common_set=set())
    assert report.score == 0


def test_strong_password_scores_high():
    report = analyze_password("Kj8#mPx2qL!9vN", common_set=set())
    assert report.score == 4
    assert report.has_lower
    assert report.has_upper
    assert report.has_digit
    assert report.has_symbol


def test_entropy_increases_with_length():
    short_report = analyze_password("Abcdef1!", common_set=set())
    long_report = analyze_password("Abcdef1!Abcdef1!", common_set=set())
    assert long_report.entropy_bits > short_report.entropy_bits
