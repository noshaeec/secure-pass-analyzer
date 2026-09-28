package com.noxolo.passwordsecurity.analyzer;

/**
 * Checks whether a password mixes uppercase, lowercase, digits and symbols.
 *
 * This rule is ADVISORY only. NIST SP 800-63B Rev 4 prohibits requiring
 * particular character types, because forced composition rules push people
 * towards predictable patterns (Password1!) and do not improve security.
 * A long all-lowercase passphrase is fine, so this rule never affects the
 * score. It is kept as a hint for users choosing short passwords.
 */
public class CharacterVarietyRule implements PasswordRule {

    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~";

    @Override
    public boolean isSatisfiedBy(String password) {
        if (password == null) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSymbol = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else if (SYMBOLS.indexOf(c) >= 0) hasSymbol = true;
        }

        return hasUpper && hasLower && hasDigit && hasSymbol;
    }

    @Override
    public String getDescription() {
        return "Tip: mixing uppercase, lowercase, digits and symbols can add strength (optional, not required)";
    }

    @Override
    public boolean isAdvisory() {
        return true;
    }
}
