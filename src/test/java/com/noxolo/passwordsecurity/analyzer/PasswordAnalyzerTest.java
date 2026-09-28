package com.noxolo.passwordsecurity.analyzer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordAnalyzerTest {

    @Test
    void advisoryRulesDoNotAffectTheScore() {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(
                List.of(new LengthRule(8), new CharacterVarietyRule()));

        PasswordAnalyzer.AnalysisReport report = analyzer.analyze("longlowercasepassphrase");

        assertEquals(100, report.score());
        assertEquals(2, report.ruleResults().size());
        assertTrue(report.ruleResults().get(1).advisory());
        assertFalse(report.ruleResults().get(1).passed());
    }

    @Test
    void failedRequiredRuleLowersTheScore() {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(
                List.of(new LengthRule(8), new BlocklistRule()));

        // "password" is long enough but is a blocklisted password
        assertEquals(50, analyzer.analyze("password").score());
    }

    @Test
    void strongLongPassphrasePassesNistStyleRules() {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(
                List.of(LengthRule.nistSingleFactor(), new BlocklistRule(), new CharacterVarietyRule()));

        assertEquals(100, analyzer.analyze("purple giraffe rides a bicycle").score());
    }

    @Test
    void shortNamePasswordFailsLength() {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(
                List.of(LengthRule.nistSingleFactor(), new BlocklistRule()));

        // passes the blocklist but is far too short
        assertEquals(50, analyzer.analyze("Noxolo").score());
    }

    @Test
    void noRulesGivesZero() {
        assertEquals(0, new PasswordAnalyzer(List.of()).analyze("anything").score());
    }

    @Test
    void onlyAdvisoryRulesGivesZero() {
        assertEquals(0, new PasswordAnalyzer(List.of(new CharacterVarietyRule())).analyze("Abcdef1!").score());
    }

    @Test
    void nullPasswordIsHandledWithoutThrowing() {
        PasswordAnalyzer analyzer = new PasswordAnalyzer(List.of(new LengthRule(8)));
        assertEquals(0, analyzer.analyze(null).score());
    }
}
