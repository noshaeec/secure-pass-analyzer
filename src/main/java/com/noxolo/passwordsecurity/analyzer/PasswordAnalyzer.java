package com.noxolo.passwordsecurity.analyzer;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs a password against a configurable set of PasswordRules
 * and produces a strength report summarizing which rules passed
 * or failed.
 *
 * Advisory rules (see PasswordRule.isAdvisory) appear in the report as
 * tips but are left out of the score, in line with NIST SP 800-63B Rev 4.
 */
public class PasswordAnalyzer {

    private final List<PasswordRule> rules;

    public PasswordAnalyzer(List<PasswordRule> rules) {
        this.rules = rules;
    }

    /**
     * Evaluates the password against every rule.
     *
     * @param password the password to analyze (never logged)
     * @return a report summarizing rule pass/fail results and an overall score
     */
    public AnalysisReport analyze(String password) {
        List<RuleResult> results = new ArrayList<>();
        int required = 0;
        int requiredPassed = 0;

        for (PasswordRule rule : rules) {
            boolean passed = rule.isSatisfiedBy(password);
            boolean advisory = rule.isAdvisory();
            results.add(new RuleResult(rule.getDescription(), passed, advisory));

            if (!advisory) {
                required++;
                if (passed) {
                    requiredPassed++;
                }
            }
        }

        int score = required == 0 ? 0 : (requiredPassed * 100) / required;
        return new AnalysisReport(results, score);
    }

    /**
     * Result of a single rule check.
     */
    public record RuleResult(String description, boolean passed, boolean advisory) {}

    /**
     * Full analysis output: individual rule results plus an overall score (0-100)
     * calculated from the non-advisory rules only.
     */
    public record AnalysisReport(List<RuleResult> ruleResults, int score) {

        public void print() {
            for (RuleResult result : ruleResults) {
                String status;
                if (result.passed()) {
                    status = "PASS";
                } else if (result.advisory()) {
                    status = "TIP ";
                } else {
                    status = "FAIL";
                }
                System.out.println("[" + status + "] " + result.description());
            }
            System.out.println("Overall strength score: " + score + "/100");
        }
    }
}
