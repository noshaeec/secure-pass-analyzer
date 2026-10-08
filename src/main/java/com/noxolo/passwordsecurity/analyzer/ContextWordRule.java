package com.noxolo.passwordsecurity.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Rejects passwords built from context-specific or dictionary words.
 * NIST SP 800-63B Rev 4 asks for this: a password should not be (a trivial
 * variation of) the username, the service name, or a common word or name.
 *
 * Two checks are made, after lowercasing, undoing common look-alike
 * substitutions (@ for a, 0 for o, ...) and ignoring digits and symbols:
 *
 *   1. Dictionary: the password is exactly ONE entry from the bundled list of
 *      common names and words, plus decoration. "Summer2024!" and
 *      "J0n@than#81" fail. A passphrase made of several ordinary words
 *      ("purple giraffe rides a bicycle") passes, because NIST encourages those.
 *
 *   2. Context: the password contains a context word (for example the
 *      username) and has fewer than minExtraLetters letters left over once the
 *      context words are removed. "Jonathan2024!" fails for the username
 *      "Jonathan", but a long passphrase that merely mentions the name has
 *      plenty of other letters and passes.
 *
 * Context words are split on non-letters, so "noxolo.shabangu" contributes
 * "noxolo", "shabangu" and "noxoloshabangu". Words shorter than 3 letters
 * are ignored to avoid false positives.
 *
 * The bundled word list is a small local sample, not a full dictionary.
 */
public class ContextWordRule implements PasswordRule {

    /** How many letters beyond the context words a password needs to pass. */
    public static final int DEFAULT_MIN_EXTRA_LETTERS = 8;

    private static final String RESOURCE = "/common-words.txt";
    private static final int MIN_CONTEXT_WORD_LENGTH = 3;

    private final Set<String> contextWords;
    private final Set<String> dictionary;
    private final int minExtraLetters;

    /** Uses the bundled word list and the default threshold. */
    public ContextWordRule(Collection<String> contextWords) {
        this(contextWords, loadDefaultWords(), DEFAULT_MIN_EXTRA_LETTERS);
    }

    public ContextWordRule(Collection<String> contextWords, Set<String> dictionary, int minExtraLetters) {
        this.contextWords = normalizeContext(contextWords);
        this.dictionary = new HashSet<>();
        for (String word : dictionary) {
            this.dictionary.add(word.toLowerCase(Locale.ROOT));
        }
        this.minExtraLetters = minExtraLetters;
    }

    @Override
    public boolean isSatisfiedBy(String password) {
        if (password == null) {
            return false;
        }
        for (String core : cores(password.toLowerCase(Locale.ROOT))) {
            if (core.isEmpty()) {
                continue;
            }
            if (dictionary.contains(core) || isBuiltFromContext(core)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String getDescription() {
        return "Password must not be built from a common name or word, or from your username or service name";
    }

    // --- helpers ---

    /** True if the letters contain a context word and little else. */
    private boolean isBuiltFromContext(String core) {
        String leftover = core;
        boolean found = false;
        for (String word : contextWords) {
            if (leftover.contains(word)) {
                found = true;
                leftover = leftover.replace(word, "");
            }
        }
        return found && leftover.length() < minExtraLetters;
    }

    /** Context words, longest first so "noxoloshabangu" is removed before "noxolo". */
    private static Set<String> normalizeContext(Collection<String> raw) {
        List<String> words = new ArrayList<>();
        if (raw != null) {
            for (String entry : raw) {
                if (entry == null) {
                    continue;
                }
                String lower = entry.toLowerCase(Locale.ROOT);
                addIfLongEnough(words, lettersOnly(lower));
                for (String token : lower.split("[^\\p{L}]+")) {
                    addIfLongEnough(words, token);
                }
            }
        }
        words.sort(Comparator.comparingInt(String::length).reversed().thenComparing(Comparator.naturalOrder()));
        return new LinkedHashSet<>(words);
    }

    private static void addIfLongEnough(List<String> words, String word) {
        if (word.length() >= MIN_CONTEXT_WORD_LENGTH) {
            words.add(word);
        }
    }

    /**
     * Letter-only versions of the password: with and without leading/trailing
     * digits and symbols, and with the digit 1 read as l or as i.
     */
    private static Set<String> cores(String lower) {
        Set<String> bases = new LinkedHashSet<>();
        bases.add(lower);
        bases.add(stripTrailingNonLetters(lower));
        bases.add(stripLeadingNonLetters(lower));
        bases.add(stripLeadingNonLetters(stripTrailingNonLetters(lower)));

        Set<String> result = new LinkedHashSet<>();
        for (String base : bases) {
            result.add(lettersOnly(decode(base, 'l')));
            result.add(lettersOnly(decode(base, 'i')));
        }
        return result;
    }

    private static String stripTrailingNonLetters(String s) {
        int end = s.length();
        while (end > 0 && !Character.isLetter(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(0, end);
    }

    private static String stripLeadingNonLetters(String s) {
        int start = 0;
        while (start < s.length() && !Character.isLetter(s.charAt(start))) {
            start++;
        }
        return s.substring(start);
    }

    private static String lettersOnly(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if (Character.isLetter(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
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

    private static Set<String> loadDefaultWords() {
        try (InputStream in = ContextWordRule.class.getResourceAsStream(RESOURCE)) {
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