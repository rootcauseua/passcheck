# passcheck

![version](https://img.shields.io/badge/version-1.1.0-red)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-11%20passing-brightgreen)

**Офлайн-аналізатор надійності паролів.** Перевіряє довжину,
різноманітність символів, збіги зі словником витоків (враховуючи
типові мутації — цифри в кінці, leetspeak) та оцінює приблизний час
на brute-force підбір. Нічого нікуди не надсилається — усі перевірки
виконуються локально.

**Offline password strength analyzer.** Checks length, character
variety, and dictionary/leaked-password matches — including common
mutations like trailing digits or leetspeak (`p@ssw0rd1` still gets
caught as `password`). Estimates a rough brute-force crack time.
Fully local, nothing is sent over the network.

## > demo

```
$ python passcheck.py "P@ssw0rd1"

  Довжина:         9
  Малі літери:     так
  Великі літери:   так
  Цифри:           так
  Символи:         так
  У списку витоків:ТАК (схоже на «password») — замінити негайно
  Ентропія:        59.1 біт
  Час на злом:     миттєво
  Оцінка:          [░░░░] Дуже слабкий (пароль у словнику витоків, навіть з мутацією)
```

```
$ python passcheck.py "Kj8#mPx2qL!9vN"

  Довжина:         14
  ...
  Оцінка:          [████] Дуже сильний
```

## > installation / встановлення

```bash
git clone https://github.com/rootcauseua/passcheck.git
cd passcheck
```

No dependencies needed — Python 3.10+ only.
Залежностей немає — потрібен лише Python 3.10+.

## > usage / використання

```bash
# pass as an argument / передати пароль аргументом
python passcheck.py "my_password"

# or enter hidden / або ввести приховано
python passcheck.py
```

| Flag / Прапорець | Description / Опис |
|-------------------|---------------------|
| `--version`        | Show version / Показати версію |
| `-h, --help`        | Show help / Показати довідку    |

## > how it works / як це рахується

- **Entropy / Ентропія** — `length × log2(charset_size)`, where the
  charset depends on which character types are used (lower/upper
  case, digits, symbols).
- **Crack time / Час на злом** — estimated at 10 billion guesses/sec,
  a rough benchmark for GPU attacks against fast, unsalted hashes
  (MD5/SHA1). Real time against bcrypt/argon2 is orders of magnitude
  longer.
- **Dictionary check / Перевірка зі словником** — not a plain exact
  match. The password is checked against the common-password list
  after normalization: lowercase, trailing digit/symbol suffixes of
  every length stripped, and leetspeak substitutions resolved
  (`@→a`, `0→o`, `1→i`, `3→e`, `5→s`, `7→t`). So `Password1`,
  `P@ssw0rd!`, `qwerty123456` are all caught, not just the exact
  literal strings in the wordlist.
  — Перевірка не просто на точний збіг. Пароль порівнюється зі
  словником після нормалізації: нижній регістр, відкидання хвостових
  цифр/символів будь-якої довжини, розкриття leetspeak. Тож
  `Password1`, `P@ssw0rd!`, `qwerty123456` теж ловляться.
- **Common password list / список паролів** — a curated ~265-entry
  sample (`data/common_passwords.txt`), not the full rockyou.txt
  (~14M entries, ~130MB) — kept small on purpose so the repo stays
  lightweight and the check stays instant. See Roadmap for a
  SecLists-based upgrade path.

## > known limitations / відомі обмеження

- The wordlist is a small curated sample, not an exhaustive leak
  database — a password can be weak in reality and still not match.
  / Словник — невелика вибірка, а не повна база витоків, тож деякі
  слабкі паролі можуть не збігтися.
- No keyboard-walk detection (e.g. `asdfgh`) beyond what's explicitly
  in the wordlist. / Немає детекції "ходьби по клавіатурі" поза тим,
  що явно є у словнику.
- Entropy is a standard approximation, not a substitute for
  battle-tested tools like `zxcvbn`. / Ентропія — стандартне
  наближення, не заміна перевіреним інструментам на кшталт `zxcvbn`.

## > tests / тести

```bash
pip install pytest
pytest test_passcheck.py -v
```

11 tests, including regression tests for the mutation-detection bug
fixed in v1.1.0. / 11 тестів, включно з регресійними на баг з
мутаціями, виправлений у v1.1.0.

## > roadmap

- [ ] Optional check against a larger list (SecLists top-100k) as an opt-in download
- [ ] Have I Been Pwned API check (opt-in, explicit network use)
- [ ] `zxcvbn`-style pattern scoring (keyboard walks, repeated sequences)
- [ ] Web demo (Flask)

## > author

[@rootcause_ua](https://www.tiktok.com/@rootcause_ua) — cybersecurity content in Ukrainian

## > license

MIT, see [LICENSE](LICENSE)
