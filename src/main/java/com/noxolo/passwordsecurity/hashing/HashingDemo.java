package com.noxolo.passwordsecurity.hashing;

import org.mindrot.jbcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Educational demo of why passwords must be hashed properly. It compares
 * three ways a system might store passwords: plaintext, unsalted SHA-256,
 * and bcrypt with a per-password salt.
 *
 * Only made-up sample passwords are used here. Never use this class to store
 * real passwords: it exists to show what goes wrong, not to be a storage layer.
 */
public class HashingDemo {

    /** bcrypt work factor used for the demo. Each +1 doubles the time per hash. */
    static final int DEMO_COST = 10;

    /** A tiny stand-in for the wordlists attackers use. */
    private static final List<String> SAMPLE_WORDLIST = List.of(
            "123456", "password", "qwerty", "letmein", "welcome", "Summer2024!", "dragon", "monkey");

    // ---- Approach 1: plaintext (nothing to compute; the "hash" is the password itself) ----

    // ---- Approach 2: unsalted SHA-256 ----

    /** Fast, unsalted SHA-256 as lowercase hex. Same input always gives the same output. */
    static String sha256Hex(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required on every Java platform", e);
        }
    }

    /**
     * What an attacker with a stolen table of unsalted hashes does: hash each guess
     * and compare. No work is needed per user, and identical hashes reveal shared passwords.
     */
    static Optional<String> crackSha256(String targetHash, List<String> wordlist) {
        return wordlist.stream().filter(guess -> sha256Hex(guess).equals(targetHash)).findFirst();
    }

    // ---- Approach 3: bcrypt (salted, deliberately slow) ----

    /** bcrypt hash with a fresh random salt. The salt and cost are stored inside the result. */
    static String bcryptHash(String password, int cost) {
        return BCrypt.hashpw(password, BCrypt.gensalt(cost));
    }

    static boolean bcryptVerify(String password, String storedHash) {
        return BCrypt.checkpw(password, storedHash);
    }

    /** Attacker's job against bcrypt: the salt forces separate work for every user and guess. */
    static Optional<String> crackBcrypt(String storedHash, List<String> wordlist) {
        return wordlist.stream().filter(guess -> bcryptVerify(guess, storedHash)).findFirst();
    }

    // ---- Speed comparison ----

    static long sha256GuessesPerSecond(int guesses) {
        long start = System.nanoTime();
        for (int i = 0; i < guesses; i++) {
            sha256Hex("guess" + i);
        }
        return perSecond(guesses, System.nanoTime() - start);
    }

    static long bcryptGuessesPerSecond(int cost, int guesses) {
        long start = System.nanoTime();
        for (int i = 0; i < guesses; i++) {
            bcryptHash("guess" + i, cost);
        }
        return perSecond(guesses, System.nanoTime() - start);
    }

    private static long perSecond(int count, long elapsedNanos) {
        return Math.max(1, (long) (count / Math.max(1e-9, elapsedNanos / 1_000_000_000.0)));
    }

    // ---- The walkthrough ----

    public static void main(String[] args) {
        // Two made-up users who happen to share the same sample password.
        String alicePassword = "Summer2024!";
        String bobPassword = "Summer2024!";

        System.out.println("=== 1. Plaintext storage ===");
        System.out.println("alice -> " + alicePassword);
        System.out.println("bob   -> " + bobPassword);
        System.out.println("Anyone who reads the database reads every password. Never do this.");

        System.out.println();
        System.out.println("=== 2. Unsalted SHA-256 ===");
        String aliceSha = sha256Hex(alicePassword);
        String bobSha = sha256Hex(bobPassword);
        System.out.println("alice -> " + aliceSha);
        System.out.println("bob   -> " + bobSha);
        System.out.println("Identical hashes: " + aliceSha.equals(bobSha)
                + " (a thief can see these two users share a password)");
        System.out.println("Cracked from a tiny wordlist: "
                + crackSha256(aliceSha, SAMPLE_WORDLIST).orElse("not found"));

        System.out.println();
        System.out.println("=== 3. bcrypt (cost " + DEMO_COST + ", random salt per password) ===");
        String aliceBcrypt = bcryptHash(alicePassword, DEMO_COST);
        String bobBcrypt = bcryptHash(bobPassword, DEMO_COST);
        System.out.println("alice -> " + aliceBcrypt);
        System.out.println("bob   -> " + bobBcrypt);
        System.out.println("Identical hashes: " + aliceBcrypt.equals(bobBcrypt)
                + " (the salt hides that they share a password)");
        System.out.println("Correct password verifies: " + bcryptVerify(alicePassword, aliceBcrypt));
        System.out.println("Wrong password verifies:   " + bcryptVerify("not-the-password", aliceBcrypt));

        System.out.println();
        System.out.println("=== Speed: why slow is good ===");
        long sha = sha256GuessesPerSecond(200_000);
        long bcrypt = bcryptGuessesPerSecond(DEMO_COST, 3);
        System.out.println("SHA-256 : ~" + String.format("%,d", sha) + " guesses/second on this machine");
        System.out.println("bcrypt  : ~" + String.format("%,d", bcrypt) + " guesses/second on this machine");
        System.out.println("bcrypt makes every guess far more expensive for an attacker,"
                + " while a login still takes only a fraction of a second.");
        System.out.println("Note: bcrypt only uses the first 72 bytes of a password.");
    }
}
