package com.noxolo.passwordsecurity.breach;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Checks a password against the Have I Been Pwned breach corpus using
 * k-anonymity: the password is SHA-1 hashed locally, only the first 5 hex
 * characters of the hash are sent, and the remaining 35 characters are
 * matched locally against the suffixes HIBP returns.
 *
 * SHA-1 is used here only because the HIBP API is keyed on it; it is not
 * used to store or protect passwords.
 */
public class BreachChecker {

    private static final int PREFIX_LENGTH = 5;

    private final HibpClient client;

    public BreachChecker(HibpClient client) {
        this.client = client;
    }

    /** Result of a breach lookup. {@code count} is 0 when the password was not found. */
    public record BreachResult(boolean breached, long count) {}

    /**
     * @param password the password to check (never logged; only a hash prefix leaves the machine)
     * @throws BreachCheckException if the lookup could not be completed
     */
    public BreachResult check(String password) throws BreachCheckException {
        String hash = sha1Hex(password);
        String prefix = hash.substring(0, PREFIX_LENGTH);
        String suffix = hash.substring(PREFIX_LENGTH);

        String body;
        try {
            body = client.fetchRange(prefix);
        } catch (IOException e) {
            throw new BreachCheckException("Could not reach the breach database", e);
        }
        return findSuffix(body, suffix);
    }

    private static BreachResult findSuffix(String body, String suffix) throws BreachCheckException {
        if (body == null) {
            throw new BreachCheckException("Empty response from breach database");
        }
        for (String line : body.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int colon = trimmed.indexOf(':');
            if (colon < 0) {
                throw new BreachCheckException("Malformed response from breach database");
            }
            if (!trimmed.substring(0, colon).equalsIgnoreCase(suffix)) {
                continue;
            }
            long count;
            try {
                count = Long.parseLong(trimmed.substring(colon + 1).trim());
            } catch (NumberFormatException e) {
                throw new BreachCheckException("Malformed count in breach database response", e);
            }
            // A count of 0 is a padding entry (Add-Padding), not a real match.
            return count > 0 ? new BreachResult(true, count) : new BreachResult(false, 0);
        }
        return new BreachResult(false, 0);
    }

    static String sha1Hex(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is required on every Java platform", e);
        }
    }
}
