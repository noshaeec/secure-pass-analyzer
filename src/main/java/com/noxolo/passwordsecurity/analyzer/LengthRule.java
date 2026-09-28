package com.noxolo.passwordsecurity.analyzer;

/**
 * Requires a password to meet a minimum length.
 * Length is the single strongest predictor of password strength
 * against brute-force attacks.
 *
 * Length is counted in Unicode code points (as NIST SP 800-63B asks),
 * so an emoji counts as one character, not two.
 */
public class LengthRule implements PasswordRule {

    /** NIST SP 800-63B Rev 4: minimum when the password is the only login factor. */
    public static final int NIST_SINGLE_FACTOR_MIN = 15;

    /** NIST SP 800-63B Rev 4: minimum when the password is used together with MFA. */
    public static final int NIST_WITH_MFA_MIN = 8;

    private final int minLength;

    public LengthRule(int minLength) {
        this.minLength = minLength;
    }

    public static LengthRule nistSingleFactor() {
        return new LengthRule(NIST_SINGLE_FACTOR_MIN);
    }

    public static LengthRule nistWithMfa() {
        return new LengthRule(NIST_WITH_MFA_MIN);
    }

    @Override
    public boolean isSatisfiedBy(String password) {
        return password != null
                && password.codePointCount(0, password.length()) >= minLength;
    }

    @Override
    public String getDescription() {
        return "Password must be at least " + minLength + " characters long";
    }
}
