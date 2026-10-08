package com.noxolo.passwordsecurity;

import com.noxolo.passwordsecurity.analyzer.BlocklistRule;
import com.noxolo.passwordsecurity.analyzer.CharacterVarietyRule;
import com.noxolo.passwordsecurity.analyzer.ContextWordRule;
import com.noxolo.passwordsecurity.analyzer.LengthRule;
import com.noxolo.passwordsecurity.analyzer.PasswordAnalyzer;
import com.noxolo.passwordsecurity.analyzer.PasswordRule;
import com.noxolo.passwordsecurity.breach.BreachChecker;
import com.noxolo.passwordsecurity.breach.BreachRule;
import com.noxolo.passwordsecurity.breach.HttpHibpClient;


import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class Main {


    /**
     * Any command-line arguments are treated as context words (for example a
     * username or the service name) that the password must not be built from.
     * The password itself is never taken from the arguments.
     */
    public static void main(String[] args) throws IOException {
        List<PasswordRule> rules = List.of(
                LengthRule.nistSingleFactor(),
                new BlocklistRule(),
                new ContextWordRule(Arrays.asList(args)),
                new BreachRule(new BreachChecker(new HttpHibpClient())),
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
