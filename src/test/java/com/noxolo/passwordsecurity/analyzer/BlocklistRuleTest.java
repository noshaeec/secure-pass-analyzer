package com.noxolo.passwordsecurity.analyzer;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BlocklistRuleTest {

    private final BlocklistRule rule = new BlocklistRule();

    @Test
    void blocksCommonPassword() {
        assertFalse(rule.isSatisfiedBy("password"));
    }

    @Test
    void blocksCommonPasswordIgnoringCase() {
        assertFalse(rule.isSatisfiedBy("PassWord"));
    }

    @Test
    void blocksCommonPasswordWithTrailingDigitsAndSymbols() {
        assertFalse(rule.isSatisfiedBy("Password123!"));
    }

    @Test
    void blocksLookAlikeSubstitutions() {
        assertFalse(rule.isSatisfiedBy("P@ssw0rd"));
        assertFalse(rule.isSatisfiedBy("P@ssw0rd1!"));
    }

    @Test
    void blocksRepeatedCharacter() {
        assertFalse(rule.isSatisfiedBy("aaaaaaaaaaaaaaaa"));
    }

    @Test
    void blocksAlphabetAndDigitRuns() {
        assertFalse(rule.isSatisfiedBy("abcdefghijkl"));
        assertFalse(rule.isSatisfiedBy("3456789"));
    }

    @Test
    void blocksReversedRuns() {
        assertFalse(rule.isSatisfiedBy("9876543210"));
    }

    @Test
    void blocksKeyboardRows() {
        assertFalse(rule.isSatisfiedBy("asdfghjkl"));
        assertFalse(rule.isSatisfiedBy("zxcvbnm"));
    }

    @Test
    void allowsLongUncommonPassphrase() {
        assertTrue(rule.isSatisfiedBy("purple giraffe rides a bicycle"));
    }

    @Test
    void rejectsNull() {
        assertFalse(rule.isSatisfiedBy(null));
    }

    @Test
    void customBlocklistIsUsedInsteadOfDefault() {
        BlocklistRule custom = new BlocklistRule(Set.of("Hunter2"));
        assertFalse(custom.isSatisfiedBy("hunter2"));
        assertTrue(custom.isSatisfiedBy("password"));
    }
}
