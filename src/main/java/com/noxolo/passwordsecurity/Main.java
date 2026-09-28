package com.noxolo.passwordsecurity;

import com.noxolo.passwordsecurity.analyzer.BlocklistRule;
import com.noxolo.passwordsecurity.analyzer.CharacterVarietyRule;
import com.noxolo.passwordsecurity.analyzer.LengthRule;
import com.noxolo.passwordsecurity.analyzer.PasswordAnalyzer;
import com.noxolo.passwordsecurity.analyzer.PasswordRule;

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
