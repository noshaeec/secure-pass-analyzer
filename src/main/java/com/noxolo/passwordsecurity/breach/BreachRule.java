package com.noxolo.passwordsecurity.breach;

import com.noxolo.passwordsecurity.analyzer.PasswordRule;

/**
 * Fails a password that appears in the Have I Been Pwned breach corpus.
 * A breached password is unsafe however long or complex it looks, so this
 * is a required rule and counts towards the score.
 *
 * If the lookup cannot be completed the outcome is UNAVAILABLE, which the
 * analyzer reports as skipped and leaves out of the score. The password is
 * never assumed safe just because the check did not run.
 */
public class BreachRule implements PasswordRule {

    private final BreachChecker checker;

    public BreachRule(BreachChecker checker) {
        this.checker = checker;
    }

    @Override
    public Outcome evaluate(String password) {
        if (password == null) {
            return Outcome.FAIL;
        }
        try {
            return checker.check(password).breached() ? Outcome.FAIL : Outcome.PASS;
        } catch (BreachCheckException e) {
            return Outcome.UNAVAILABLE;
        }
    }

    @Override
    public boolean isSatisfiedBy(String password) {
        return evaluate(password) == Outcome.PASS;
    }

    @Override
    public String getDescription() {
        return "Password must not appear in known data breaches";
    }
}
