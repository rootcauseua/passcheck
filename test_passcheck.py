"""Тести для passcheck. Запуск: pytest test_passcheck.py -v"""

from passcheck import analyze_password, _normalize_variants

COMMON = {"123456", "password", "qwerty", "iloveyou", "1234567890", "qwerty123"}


# --- базова логіка ---

def test_common_password_is_weak():
    report = analyze_password("123456", common_set=COMMON)
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


# --- захист від мутацій (регресійні тести на баг, знайдений вручну) ---

def test_catches_trailing_digit_mutation():
    report = analyze_password("Password1", common_set=COMMON)
    assert report.is_common is True
    assert report.score == 0


def test_catches_leetspeak_mutation():
    report = analyze_password("P@ssw0rd!", common_set=COMMON)
    assert report.is_common is True
    assert report.score == 0


def test_catches_long_numeric_dictionary_suffix():
    # "qwerty" + "123456789..." — довгий цифровий словниковий хвіст,
    # не лише короткий суфікс з 1-4 символів
    report = analyze_password("qwerty1234567890", common_set=COMMON)
    assert report.is_common is True


def test_does_not_falsely_flag_strong_password_as_common():
    report = analyze_password("Kj8#mPx2qL!9vN", common_set=COMMON)
    assert report.is_common is False


def test_pure_numeric_long_password_not_overrated():
    # Раніше був баг: довгий цифровий рядок із символом в кінці
    # хибно отримував "Середній" через втрату збігу зі словником
    report = analyze_password("1234567890!", common_set=COMMON)
    assert report.is_common is True
    assert report.score == 0


# --- нормалізація варіантів (внутрішня функція) ---

def test_normalize_variants_includes_stripped_and_leet():
    variants = _normalize_variants("P@ssw0rd1")
    assert "p@ssw0rd1" in variants  # lower
    assert any(v.startswith("passw0rd") or v == "password" for v in variants)


def test_short_prefix_not_generated():
    # Хвіст не повинен "з'їдати" пароль до безглуздо короткого префіксу
    variants = _normalize_variants("ab1234")
    assert "a" not in variants
    assert "ab" not in variants
