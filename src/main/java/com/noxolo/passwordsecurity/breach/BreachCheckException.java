package com.noxolo.passwordsecurity.breach;

/**
 * Thrown when a breach lookup could not be completed (network error,
 * unexpected HTTP status, malformed response). Callers should report the
 * check as "unavailable" rather than treating the password as safe.
 */
public class BreachCheckException extends Exception {

    public BreachCheckException(String message) {
        super(message);
    }

    public BreachCheckException(String message, Throwable cause) {
        super(message, cause);
    }
}
