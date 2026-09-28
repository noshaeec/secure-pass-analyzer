package com.noxolo.passwordsecurity.analyzer;

/**
 * Represents a single password validation check.
 * Each implementation encapsulates one rule (e.g. minimum length,
 * blocklist match, character variety) and reports whether the
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

    /**
     * Advisory rules give the user a hint but never count against the score.
     * NIST SP 800-63B Rev 4 prohibits requiring particular character types,
     * so composition checks should be advisory rather than mandatory.
     */
    default boolean isAdvisory() {
        return false;
    }
}
