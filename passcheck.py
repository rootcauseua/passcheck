#!/usr/bin/env python3
"""
passcheck — простий аналізатор надійності паролів.

Перевіряє пароль на довжину, різноманітність символів, наявність
у списку найпоширеніших паролів світу та оцінює приблизний час
на brute-force підбір.

Author: rootcause
License: MIT
"""

from __future__ import annotations

import argparse
import getpass
import math
import sys
from dataclasses import dataclass
from pathlib import Path

__version__ = "1.0.0"

COMMON_PASSWORDS_FILE = Path(__file__).parent / "data" / "common_passwords.txt"

# Приблизна швидкість перебору сучасним GPU-кластером (хешів/сек)
GUESSES_PER_SECOND = 10_000_000_000  # 10 млрд/с, орієнтир для швидких хешів (MD5/SHA1)


@dataclass
class PasswordReport:
    password: str
    length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    charset_size: int
    entropy_bits: float
    is_common: bool
    crack_time_seconds: float
    score: int  # 0-4
    verdict: str


def load_common_passwords() -> set[str]:
    if not COMMON_PASSWORDS_FILE.exists():
        return set()
    with open(COMMON_PASSWORDS_FILE, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def analyze_password(password: str, common_set: set[str] | None = None) -> PasswordReport:
    common_set = common_set if common_set is not None else load_common_passwords()

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 33  # приблизна кількість друкованих символів-спецсимволів

    length = len(password)
    entropy_bits = length * math.log2(charset_size) if charset_size and length else 0.0

    is_common = password.lower() in common_set

    crack_time_seconds = (2 ** entropy_bits) / GUESSES_PER_SECOND if entropy_bits else 0.0
    if is_common:
        crack_time_seconds = 0.0  # у словнику — підбирається миттєво

    score, verdict = _score_password(length, charset_size, entropy_bits, is_common)

    return PasswordReport(
        password=password,
        length=length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        charset_size=charset_size,
        entropy_bits=entropy_bits,
        is_common=is_common,
        crack_time_seconds=crack_time_seconds,
        score=score,
        verdict=verdict,
    )


def _score_password(length: int, charset_size: int, entropy_bits: float, is_common: bool) -> tuple[int, str]:
    if is_common:
        return 0, "Дуже слабкий (пароль у відкритих словниках)"
    if length < 8:
        return 0, "Дуже слабкий (занадто короткий)"

    if entropy_bits < 35:
        return 1, "Слабкий"
    elif entropy_bits < 60:
        return 2, "Середній"
    elif entropy_bits < 80:
        return 3, "Сильний"
    else:
        return 4, "Дуже сильний"


def format_duration(seconds: float) -> str:
    if seconds <= 0:
        return "миттєво"
    units = [
        ("століть", 60 * 60 * 24 * 365 * 100),
        ("років", 60 * 60 * 24 * 365),
        ("днів", 60 * 60 * 24),
        ("годин", 60 * 60),
        ("хвилин", 60),
        ("секунд", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if value > 1_000_000:
                return f">1 000 000 {name}"
            return f"~{value:,.0f} {name}"
    return "миттєво"


def print_report(report: PasswordReport) -> None:
    bar_filled = "█" * report.score
    bar_empty = "░" * (4 - report.score)

    print()
    print(f"  Довжина:         {report.length}")
    print(f"  Малі літери:     {'так' if report.has_lower else 'ні'}")
    print(f"  Великі літери:   {'так' if report.has_upper else 'ні'}")
    print(f"  Цифри:           {'так' if report.has_digit else 'ні'}")
    print(f"  Символи:         {'так' if report.has_symbol else 'ні'}")
    print(f"  У списку витоків:{'ТАК — замінити негайно' if report.is_common else ' ні'}")
    print(f"  Ентропія:        {report.entropy_bits:.1f} біт")
    print(f"  Час на злом:     {format_duration(report.crack_time_seconds)}")
    print(f"  Оцінка:          [{bar_filled}{bar_empty}] {report.verdict}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passcheck",
        description="Аналізатор надійності паролів (офлайн, нічого нікуди не надсилається).",
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Пароль для перевірки. Якщо не вказано — буде запропоновано ввести приховано.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    password = args.password or getpass.getpass("Введіть пароль для перевірки (нічого не зберігається): ")
    if not password:
        print("Порожній пароль.", file=sys.stderr)
        return 1

    report = analyze_password(password)
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
