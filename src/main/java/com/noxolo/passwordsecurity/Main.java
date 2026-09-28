package com.noxolo.passwordsecurity;

import com.noxolo.passwordsecurity.analyzer.BlocklistRule;
import com.noxolo.passwordsecurity.analyzer.CharacterVarietyRule;
import com.noxolo.passwordsecurity.analyzer.LengthRule;
import com.noxolo.passwordsecurity.analyzer.PasswordAnalyzer;
import com.noxolo.passwordsecurity.analyzer.PasswordRule;
import com.noxolo.passwordsecurity.breach.BreachCheckException;
import com.noxolo.passwordsecurity.breach.BreachChecker;
import com.noxolo.passwordsecurity.breach.HttpHibpClient;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        List<PasswordRule> rules = List.of(
                LengthRule.nistSingleFactor(),
                new BlocklistRule(),
                new CharacterVarietyRule()
        );

        PasswordAnalyzer analyzer = new PasswordAnalyzer(rules);

        String password = readPassword();
        PasswordAnalyzer.AnalysisReport report = analyzer.analyze(password);
        report.print();

        printBreachStatus(password);
    }

    private static void printBreachStatus(String password) {
        BreachChecker checker = new BreachChecker(new HttpHibpClient());
        try {
            BreachChecker.BreachResult result = checker.check(password);
            if (result.breached()) {
                System.out.println("[FAIL] Found in known data breaches " + result.count()
                        + " times - do not use this password");
            } else {
                System.out.println("[PASS] Not found in known data breaches");
            }
        } catch (BreachCheckException e) {
            // Never report "safe" when the check didn't actually run.
            System.out.println("[SKIP] Breach check unavailable: " + e.getMessage());
        }
    }

    /**
     * Reads the password without echoing it where possible, and never takes it
     * from command-line arguments (those end up in shell history).
     */
    private static String readPassword() throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("Enter a password to analyze: ");
            String password = new String(chars);
            Arrays.fill(chars, ' ');
            return password;
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String line = reader.readLine();
        return line == null ? "" : line;
    }
}
