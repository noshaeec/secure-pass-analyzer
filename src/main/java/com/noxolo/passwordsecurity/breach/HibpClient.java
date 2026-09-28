package com.noxolo.passwordsecurity.breach;

import java.io.IOException;

/**
 * Fetches the list of hash suffixes for a given 5-character SHA-1 prefix.
 * Kept as an interface so BreachChecker can be unit tested without the network.
 */
public interface HibpClient {

    /**
     * @param prefix exactly 5 uppercase hex characters (the only part of the hash ever sent)
     * @return the raw response body: lines of the form {@code SUFFIX:COUNT}
     */
    String fetchRange(String prefix) throws IOException;
}
