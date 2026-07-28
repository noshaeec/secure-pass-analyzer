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
- [ ] `PasswordRule` interface + concrete rules (length, character mix, dictionary check, entropy)
- [ ] `PasswordAnalyzer` — aggregates rule results into a strength score/report
- [ ] `BreachChecker` — integrates with the HIBP API using k-anonymity (only a 5-character SHA-1 hash prefix is ever sent, never the password itself)
- [ ] `HashingDemo` — compares plaintext/weak hashing vs. bcrypt with salt, for educational purposes
- [ ] Unit tests (JUnit 5)

## Design decisions

- **Rule-based architecture (`PasswordRule` interface)**: each check (length, entropy, dictionary match, etc.) is implemented as its own class behind a common interface. This makes it easy to add or remove checks without touching the core analyzer logic — an example of the Open/Closed Principle in practice.
- **No raw password logging**: at no point does the tool write a raw password to disk, logs, or console output beyond the immediate strength report. This is a deliberate design constraint, not an oversight.
- **k-anonymity for breach checking**: rather than sending a full password (or even its full hash) to a third-party API, only the first 5 characters of its SHA-1 hash are sent. HIBP returns all hash suffixes matching that prefix, and the match is confirmed locally. This means the actual password — or even a reversible representation of it — never leaves the machine.

## Tech stack

- Java 21
- Maven
- [OkHttp](https://square.github.io/okhttp/) — HTTP client for the HIBP API
- [jBCrypt](https://www.mindrot.org/projects/jBCrypt/) — password hashing demo
- JUnit 5 — testing

## Getting started

```bash
git clone git@github.com:noshaeec/secure-pass-analyzer.git
cd secure-pass-analyzer
mvn compile
mvn exec:java -Dexec.mainClass="com.noxolo.passwordsecurity.Main"
```

## Project structure

src/main/java/com/noxolo/passwordsecurity/
├── Main.java
├── analyzer/ # Password strength rules and scoring
├── breach/ # HIBP breach-checking integration
├── hashing/ # Hashing demo (plaintext vs bcrypt)
└── util/ # Report generation and shared helpers


## Limitations

- This is a learning/portfolio project, not a production-hardened security library — it hasn't undergone external security review.
- Dictionary checks currently rely on a limited local wordlist rather than a comprehensive breach corpus.

## License
