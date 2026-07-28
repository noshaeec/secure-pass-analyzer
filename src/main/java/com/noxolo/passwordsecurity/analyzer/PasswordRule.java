package com.noxolo.passwordsecurity.analyzer;

/**
 * Represents a single password validation check.
 * Each implementation encapsulates one rule (e.g. minimum length,
 * character variety, dictionary match) and reports whether the
 * password satisfies it, plus a human-readable explanation.
 */
public interface PasswordRule {

    /**
     * Evaluates the given password against this rule.
     *
     * @param password the password to check (never logged or stored)
     * @return true if the password satisfies this rule
     */
    boolean isSatisfiedBy(String password);

    /**
     * A short, human-readable description of what this rule checks,
     * used when generating the strength report.
     */
    String getDescription();
}
