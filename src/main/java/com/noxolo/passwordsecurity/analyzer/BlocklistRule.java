package com.noxolo.passwordsecurity.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Rejects passwords that are commonly used or trivially predictable.
 * NIST SP 800-63B Rev 4 requires this kind of screening.
 *
 * A password is blocked if, ignoring case, it:
 *   - is on the blocklist (also after undoing common substitutions such as
 *     @ for a, 0 for o, and after removing trailing digits/symbols, so
 *     "P@ssw0rd1!" is treated as "password"), or
 *   - is one repeated character (aaaaaaaa), or
 *   - is a run from the alphabet, digits or a keyboard row, forwards or
 *     backwards (abcdefgh, 987654321, qwertyuiop).
 *
 * The bundled list is a small local sample. For real use it should be
 * replaced or complemented by a breach corpus (see the planned BreachChecker).
 */
public class BlocklistRule implements PasswordRule {

    private static final String RESOURCE = "/common-passwords.txt";
    private static final int MIN_PATTERN_LENGTH = 4;
    private static final String[] SEQUENCES = {
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
    };

    private final Set<String> blocklist;

    public BlocklistRule() {
        this(loadDefaultBlocklist());
    }

    public BlocklistRule(Set<String> blocklist) {
        this.blocklist = new HashSet<>();
        for (String entry : blocklist) {
            this.blocklist.add(entry.toLowerCase(Locale.ROOT));
        }
    }

    @Override
    public boolean isSatisfiedBy(String password) {
        if (password == null) {
            return false;
        }
        String lower = password.toLowerCase(Locale.ROOT);
        for (String candidate : candidates(lower)) {
            if (blocklist.contains(candidate)
                    || isRepeatedCharacter(candidate)
                    || isSequence(candidate)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String getDescription() {
        return "Password must not be a common password or an obvious pattern";
    }

    // --- helpers ---

    private static Set<String> candidates(String lower) {
        Set<String> bases = new LinkedHashSet<>();
        bases.add(lower);
        bases.add(stripTrailingNonLetters(lower));

        Set<String> all = new LinkedHashSet<>();
        for (String base : bases) {
            all.add(base);
            all.add(decode(base, 'l'));
            all.add(decode(base, 'i'));
        }
        all.remove("");
        return all;
    }

    private static String stripTrailingNonLetters(String s) {
        int end = s.length();
        while (end > 0 && !Character.isLetter(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(0, end);
    }

    /** Undoes common look-alike substitutions. The digit 1 could mean l or i. */
    private static String decode(String s, char oneMeans) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '@', '4' -> sb.append('a');
                case '3' -> sb.append('e');
                case '0' -> sb.append('o');
                case '$', '5' -> sb.append('s');
                case '7' -> sb.append('t');
                case '!' -> sb.append('i');
                case '1' -> sb.append(oneMeans);
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isRepeatedCharacter(String s) {
        if (s.length() < MIN_PATTERN_LENGTH) {
            return false;
        }
        char first = s.charAt(0);
        for (int i = 1; i < s.length(); i++) {
            if (s.charAt(i) != first) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSequence(String s) {
        if (s.length() < MIN_PATTERN_LENGTH) {
            return false;
        }
        for (String seq : SEQUENCES) {
            String reversed = new StringBuilder(seq).reverse().toString();
            if (seq.contains(s) || reversed.contains(s)) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> loadDefaultBlocklist() {
        try (InputStream in = BlocklistRule.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Missing resource: " + RESOURCE);
            }
            Set<String> entries = new HashSet<>();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    entries.add(line);
                }
            }
            return entries;
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + RESOURCE, e);
        }
    }
}
