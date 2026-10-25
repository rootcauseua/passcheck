# Changelog

## [1.1.0] — 2026-10-25

### Fixed
- **Mutation bypass bug:** passwords like `Password1`, `P@ssw0rd!`,
  `qwerty123456` were incorrectly scored as strong because the
  dictionary check only matched exact strings. Normalization now
  strips trailing digit/symbol suffixes of any length and resolves
  leetspeak before comparing against the wordlist.
- **Numeric overrate bug:** long all-digit passwords with a trailing
  symbol (e.g. `1234567890!`) were scored "Medium" instead of "Weak"
  because the old trailing-suffix regex consumed the entire string,
  losing the dictionary match. Fixed by trying all suffix lengths
  instead of one greedy match.

### Added
- Expanded common-password list from 48 to ~265 entries.
- 7 new regression tests covering the mutation-detection fixes.
- Bilingual (Ukrainian/English) README.
- `matched_base` field in the report showing which dictionary entry
  a mutated password matched against.

## [1.0.0] — 2026-10-14

Initial release: length/charset checks, entropy estimate, crack-time
estimate, exact-match dictionary check against a 48-entry wordlist.
