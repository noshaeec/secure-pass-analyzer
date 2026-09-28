package com.noxolo.passwordsecurity.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LengthRuleTest {

    @Test
    void acceptsPasswordAtMinimumLength() {
        assertTrue(new LengthRule(8).isSatisfiedBy("12345678"));
    }

    @Test
    void rejectsPasswordBelowMinimumLength() {
        assertFalse(new LengthRule(8).isSatisfiedBy("1234567"));
    }

    @Test
    void rejectsNull() {
        assertFalse(new LengthRule(8).isSatisfiedBy(null));
    }

    @Test
    void nistSingleFactorNeedsFifteenCharacters() {
        LengthRule rule = LengthRule.nistSingleFactor();
        assertFalse(rule.isSatisfiedBy("a".repeat(14)));
        assertTrue(rule.isSatisfiedBy("a".repeat(15)));
    }

    @Test
    void nistWithMfaNeedsEightCharacters() {
        LengthRule rule = LengthRule.nistWithMfa();
        assertFalse(rule.isSatisfiedBy("a".repeat(7)));
        assertTrue(rule.isSatisfiedBy("a".repeat(8)));
    }

    @Test
    void countsUnicodeCodePointsNotUtf16Units() {
        String fourEmoji = "\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00"; // 4 characters, 8 UTF-16 units
        assertTrue(new LengthRule(4).isSatisfiedBy(fourEmoji));
        assertFalse(new LengthRule(5).isSatisfiedBy(fourEmoji));
    }

    @Test
    void acceptsSpacesAndVeryLongPassphrases() {
        assertTrue(LengthRule.nistSingleFactor().isSatisfiedBy("purple giraffe rides a bicycle"));
        assertTrue(LengthRule.nistSingleFactor().isSatisfiedBy("a".repeat(64)));
    }
}
