package com.noxolo.passwordsecurity.analyzer;

/**
 * Requires a password to meet a minimum length.
 * Length is the single strongest predictor of password strength
 * against brute-force attacks.
 */
public class LengthRule implements PasswordRule {

    private final int minLength;

    public LengthRule(int minLength) {
        this.minLength = minLength;
    }

    @Override
    public boolean isSatisfiedBy(String password) {
        return password != null && password.length() >= minLength;
    }

    @Override
    public String getDescription() {
        return "Password must be at least " + minLength + " characters long";
    }
}
