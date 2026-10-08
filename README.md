# Secure Password Analyzer

A Java CLI tool that evaluates password strength using configurable rules and checks whether a password has appeared in known data breaches, using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3) API's privacy-preserving k-anonymity model.

## Why this project

Weak and reused passwords remain one of the most common root causes of account compromise. This tool is built to demonstrate practical, defensible password security checks — the kind of logic that could sit inside a real signup/login flow — while keeping the implementation transparent and testable.

## Threat model

This tool addresses three common password-related risks:

1. **Weak passwords** — short, low-entropy, or dictionary-based passwords that are easy to brute-force or guess.
2. **Reused/breached passwords** — passwords that have already been exposed in a known data breach, making them unsafe even if they look "strong."
3. **Insecure storage** — a companion module demonstrates why passwords must be hashed (with salt) rather than stored in plaintext or with weak hashing.

It does **not** attempt to cover network-level attacks (e.g. credential stuffing infrastructure, rate limiting) — that's out of scope for this tool.

## Features

- [x] Project scaffold (Maven, package structure)
- [x] `PasswordRule` interface + concrete rules: `LengthRule`, `BlocklistRule`, `CharacterVarietyRule` (advisory)
- [ ] Further rules: dictionary/name check, entropy estimate
- [x] `PasswordAnalyzer` — aggregates rule results into a strength score/report
- [x] `BreachChecker` — integrates with the HIBP API using k-anonymity (only a 5-character SHA-1 hash prefix is ever sent, never the password itself)
- [x] `HashingDemo` — compares plaintext/weak hashing vs. bcrypt with salt, for educational purposes
- [x] Unit tests (JUnit 5) for the analyzer, rules, breach checker and hashing demo

## Design decisions

- **Rule-based architecture (`PasswordRule` interface)**: each check (length, entropy, dictionary match, etc.) is implemented as its own class behind a common interface. This makes it easy to add or remove checks without touching the core analyzer logic — an example of the Open/Closed Principle in practice.
- **No raw password logging**: at no point does the tool write a raw password to disk, logs, or console output beyond the immediate strength report. This is a deliberate design constraint, not an oversight.
- **k-anonymity for breach checking**: rather than sending a full password (or even its full hash) to a third-party API, only the first 5 characters of its SHA-1 hash are sent. HIBP returns all hash suffixes matching that prefix, and the match is confirmed locally. This means the actual password — or even a reversible representation of it — never leaves the machine.
- **Aligned with NIST SP 800-63B Rev 4 rather than classic complexity rules**: length and blocklist screening carry the score. `LengthRule` provides `nistSingleFactor()` (15 characters) and `nistWithMfa()` (8 characters), and counts Unicode code points. `BlocklistRule` rejects common passwords, look-alike substitutions (`P@ssw0rd`), repeated characters and keyboard/alphabet runs. `CharacterVarietyRule` is *advisory*: Rev 4 prohibits requiring particular character types, so it shows a tip but never lowers the score. A long all-lowercase passphrase can therefore score 100.
- **Advisory rules**: `PasswordRule.isAdvisory()` (default `false`) lets a rule give a hint without counting towards the score.
- **Password input**: `Main` reads the password from a hidden console prompt (or stdin when piped), never from command-line arguments, which would end up in shell history.
- **The breach check is a required rule, so it counts towards the score**: `BreachRule` wraps `BreachChecker` behind the same `PasswordRule` interface. A password found in a known breach is unsafe however long it looks, so it lowers the score like any other failed rule.
- **A failed lookup is skipped, never treated as safe**: `PasswordRule.evaluate()` can return `PASS`, `FAIL` or `UNAVAILABLE`. If the HIBP request cannot complete, the report shows `[SKIP]` and the rule is left out of the score, so an outage can neither raise nor lower it.
- **Built-in `HttpClient` instead of a library**: the breach check is a single GET request, so the JDK's `java.net.http.HttpClient` is enough and avoids an extra dependency to keep patched. The HTTP call sits behind a small `HibpClient` interface so the logic is unit tested without the network.
- **`HashingDemo` uses made-up passwords only**: it contrasts plaintext, unsalted SHA-256 (identical hashes for identical passwords, cracked by a wordlist) and bcrypt (random salt per password, deliberately slow) so the cost of each choice is visible.

## Tech stack

- Java 21
- Maven
- Java's built-in `java.net.http.HttpClient` — HTTP client for the HIBP API
- [jBCrypt](https://www.mindrot.org/projects/jBCrypt/) — password hashing demo
- JUnit 5 — testing

## Getting started

```bash
git clone https://github.com/noshaeec/secure-pass-analyzer.git
cd secure-pass-analyzer
```

Run the analyzer on macOS / Linux:

```bash
mvn compile
mvn exec:java -Dexec.mainClass="com.noxolo.passwordsecurity.Main"
```

Run the analyzer on Windows (PowerShell):

```powershell
mvn compile exec:java "-Dexec.mainClass=com.noxolo.passwordsecurity.Main"
```

## Running the tests and the hashing demo

```bash
mvn test
mvn compile exec:java -Dexec.mainClass="com.noxolo.passwordsecurity.hashing.HashingDemo"
```

On Windows (PowerShell), quote the whole argument:

```powershell
mvn compile exec:java "-Dexec.mainClass=com.noxolo.passwordsecurity.hashing.HashingDemo"
```

The demo prints how plaintext, unsalted SHA-256 and bcrypt behave for two made-up users who share a password, and compares how many guesses per second an attacker could make against each. Its speed figures vary by machine, and a real attacker with GPUs is orders of magnitude faster, so treat the ratio between the two as the lesson, not the absolute numbers.

The analyzer's breach check needs an internet connection. Without one, that rule is reported as `[SKIP]` and does not change the score.

## Project structure

```
src/main/java/com/noxolo/passwordsecurity/
├── Main.java
├── analyzer/   # Password strength rules and scoring
├── breach/     # HIBP breach-checking integration
└── hashing/    # Hashing demo (plaintext vs bcrypt)```

## Limitations

- This is a learning/portfolio project, not a production-hardened security library — it hasn't undergone external security review.
- The blocklist is a small local sample (`common-passwords.txt`), not a comprehensive breach corpus. It does not yet catch names or dictionary words, so a password built from a name (such as `J0n@than#81`) can pass the blocklist and is only caught by the length rule. The `BreachChecker` (HIBP) now catches such passwords when they appear in a known breach, but a name-based password that has not been breached can still pass; a dedicated dictionary/name rule is planned.

## License

See [LICENSE](LICENSE).