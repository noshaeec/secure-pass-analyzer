package com.noxolo.passwordsecurity.analyzer;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContextWordRuleTest {

    private static final String PASSPHRASE = "purple giraffe rides a bicycle";

    private final ContextWordRule withUsername = new ContextWordRule(List.of("Jonathan"));
    private final ContextWordRule noContext = new ContextWordRule(List.of());

    // --- context words (username, service name) ---

    @Test
    void rejectsUsernameWithSubstitutionsAndDecoration() {
        assertFalse(withUsername.isSatisfiedBy("J0n@than#81"));
    }

    @Test
    void rejectsUsernameWithDigitsAndSymbols() {
        assertFalse(withUsername.isSatisfiedBy("Jonathan2024!"));
        assertFalse(withUsername.isSatisfiedBy("JONATHAN"));
        assertFalse(withUsername.isSatisfiedBy("123Jonathan"));
    }

    @Test
    void rejectsUsernameWhenOnlyAFewLettersAreAdded() {
        assertFalse(withUsername.isSatisfiedBy("xxJonathanxx"));
    }

    @Test
    void splitsContextOnNonLettersSoEachPartIsChecked() {
        ContextWordRule rule = new ContextWordRule(List.of("noxolo.shabangu"));
        assertFalse(rule.isSatisfiedBy("Shabangu#99"));
        assertFalse(rule.isSatisfiedBy("NoxoloShabangu1"));
        assertFalse(rule.isSatisfiedBy("noxolo.shabangu"));
    }

    @Test
    void rejectsServiceName() {
        ContextWordRule rule = new ContextWordRule(List.of("jonathan", "MyBank"));
        assertFalse(rule.isSatisfiedBy("MyBank2024!"));
    }

    @Test
    void allowsLongPassphraseThatOnlyMentionsTheUsername() {
        assertTrue(withUsername.isSatisfiedBy("my jonathan loves purple giraffes riding bicycles"));
    }

    @Test
    void allowsPasswordUnrelatedToContext() {
        assertTrue(withUsername.isSatisfiedBy(PASSPHRASE));
    }

    @Test
    void ignoresContextWordsShorterThanThreeLetters() {
        ContextWordRule rule = new ContextWordRule(List.of("al"));
        assertTrue(rule.isSatisfiedBy("Alphabet-Orchard-Tractor-Violet"));
    }

    @Test
    void ignoresNullAndBlankContextEntries() {
        ContextWordRule rule = new ContextWordRule(java.util.Arrays.asList(null, "", "   ", "12"));
        assertTrue(rule.isSatisfiedBy(PASSPHRASE));
    }

    @Test
    void nullContextCollectionIsAllowed() {
        assertTrue(new ContextWordRule(null).isSatisfiedBy(PASSPHRASE));
    }

    // --- dictionary words and names ---

    @Test
    void rejectsCommonNameEvenWithoutContext() {
        assertFalse(noContext.isSatisfiedBy("Jonathan#81"));
        assertFalse(noContext.isSatisfiedBy("J0n@than#81"));
    }

    @Test
    void rejectsCommonWordWithDecoration() {
        assertFalse(noContext.isSatisfiedBy("Summer2024!"));
        assertFalse(noContext.isSatisfiedBy("5unsh1ne"));
    }

    @Test
    void allowsPassphraseMadeOfSeveralCommonWords() {
        assertTrue(noContext.isSatisfiedBy(PASSPHRASE));
    }

    @Test
    void allowsRandomLookingPasswordWithNoWords() {
        assertTrue(noContext.isSatisfiedBy("xK9#mQv2$Lp7"));
    }

    // --- general behaviour ---

    @Test
    void rejectsNullPassword() {
        assertFalse(noContext.isSatisfiedBy(null));
    }

    @Test
    void customDictionaryReplacesTheBundledOne() {
        ContextWordRule rule = new ContextWordRule(List.of(), Set.of("Hunter"), 8);
        assertFalse(rule.isSatisfiedBy("hunter99"));
        assertTrue(rule.isSatisfiedBy("Summer2024!"));
    }

    @Test
    void largerThresholdRejectsMorePasswords() {
        String password = "jonathan-purple-giraffe";
        assertTrue(new ContextWordRule(List.of("jonathan"), Set.of(), 8).isSatisfiedBy(password));
        assertFalse(new ContextWordRule(List.of("jonathan"), Set.of(), 20).isSatisfiedBy(password));
    }

    @Test
    void isARequiredRuleNotAdvisory() {
        assertFalse(withUsername.isAdvisory());
    }

    @Test
    void lowersTheScoreInTheAnalyzer() {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(List.of(
                new LengthRule(8), withUsername));

        assertEquals(50, analyzer.analyze("J0n@than#81").score());
        assertEquals(100, analyzer.analyze(PASSPHRASE).score());
    }
}