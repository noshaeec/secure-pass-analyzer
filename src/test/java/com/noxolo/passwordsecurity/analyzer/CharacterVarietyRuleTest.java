package com.noxolo.passwordsecurity.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CharacterVarietyRuleTest {

    private final CharacterVarietyRule rule = new CharacterVarietyRule();

    @Test
    void isAdvisoryBecauseNistProhibitsRequiringComposition() {
        assertTrue(rule.isAdvisory());
    }

    @Test
    void satisfiedWhenAllFourTypesPresent() {
        assertTrue(rule.isSatisfiedBy("Abcdef1!"));
    }

    @Test
    void notSatisfiedByLowercaseOnly() {
        assertFalse(rule.isSatisfiedBy("purple giraffe rides a bicycle"));
    }

    @Test
    void notSatisfiedByNull() {
        assertFalse(rule.isSatisfiedBy(null));
    }
}
