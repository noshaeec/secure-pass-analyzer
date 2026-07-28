package com.noxolo.passwordsecurity;

import com.noxolo.passwordsecurity.analyzer.LengthRule;
import com.noxolo.passwordsecurity.analyzer.PasswordRule;

public class Main {
    public static void main(String[] args) {
        PasswordRule lengthRule = new LengthRule(12);

        String testPassword = "short1!";

        System.out.println(lengthRule.getDescription());
        System.out.println("Password satisfies rule: " + lengthRule.isSatisfiedBy(testPassword));
    }
}
