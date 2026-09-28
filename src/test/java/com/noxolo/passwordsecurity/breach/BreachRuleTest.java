package com.noxolo.passwordsecurity.breach;

import com.noxolo.passwordsecurity.analyzer.PasswordRule;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BreachRuleTest {

    // SHA-1("password") suffix after the 5-character prefix 5BAA6
    private static final String SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static BreachRule ruleReturning(String body) {
        return new BreachRule(new BreachChecker(prefix -> body));
    }

    private static BreachRule ruleFailingWithNetworkError() {
        return new BreachRule(new BreachChecker(prefix -> {
            throw new IOException("network down");
        }));
    }

    @Test
    void breachedPasswordFails() {
        BreachRule rule = ruleReturning(SUFFIX + ":100\n");
        assertEquals(PasswordRule.Outcome.FAIL, rule.evaluate("password"));
        assertFalse(rule.isSatisfiedBy("password"));
    }

    @Test
    void cleanPasswordPasses() {
        BreachRule rule = ruleReturning("0018A45C4D1DEF81644B54AB7F969B88D65:1\n");
        assertEquals(PasswordRule.Outcome.PASS, rule.evaluate("password"));
        assertTrue(rule.isSatisfiedBy("password"));
    }

    @Test
    void networkFailureIsUnavailableNotPass() {
        BreachRule rule = ruleFailingWithNetworkError();
        assertEquals(PasswordRule.Outcome.UNAVAILABLE, rule.evaluate("password"));
        assertFalse(rule.isSatisfiedBy("password"));
    }

    @Test
    void nullPasswordFailsWithoutCallingTheNetwork() {
        assertEquals(PasswordRule.Outcome.FAIL, ruleFailingWithNetworkError().evaluate(null));
    }

    @Test
    void isARequiredRule() {
        assertFalse(ruleReturning("").isAdvisory());
    }
}
