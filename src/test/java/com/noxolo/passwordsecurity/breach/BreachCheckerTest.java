package com.noxolo.passwordsecurity.breach;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class BreachCheckerTest {

    // Well-known test vector: SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    private static final String PREFIX = "5BAA6";
    private static final String SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    /** Fake client that records the prefix it was asked for. */
    private static class FakeClient implements HibpClient {
        String requestedPrefix;
        final String body;
        final boolean fail;

        FakeClient(String body, boolean fail) {
            this.body = body;
            this.fail = fail;
        }

        @Override
        public String fetchRange(String prefix) throws IOException {
            requestedPrefix = prefix;
            if (fail) {
                throw new IOException("network down");
            }
            return body;
        }
    }

    @Test
    void sha1MatchesKnownVector() {
        assertEquals(PREFIX + SUFFIX, BreachChecker.sha1Hex("password"));
    }

    @Test
    void reportsBreachedPasswordWithCount() throws Exception {
        FakeClient client = new FakeClient("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
                + SUFFIX + ":10437277\r\n", false);
        BreachChecker.BreachResult result = new BreachChecker(client).check("password");
        assertTrue(result.breached());
        assertEquals(10437277L, result.count());
    }

    @Test
    void reportsNotBreachedWhenSuffixAbsent() throws Exception {
        FakeClient client = new FakeClient("0018A45C4D1DEF81644B54AB7F969B88D65:1\n", false);
        BreachChecker.BreachResult result = new BreachChecker(client).check("password");
        assertFalse(result.breached());
        assertEquals(0L, result.count());
    }

    @Test
    void matchingIsCaseInsensitive() throws Exception {
        FakeClient client = new FakeClient(SUFFIX.toLowerCase() + ":42\n", false);
        assertTrue(new BreachChecker(client).check("password").breached());
    }

    @Test
    void paddingEntryWithZeroCountIsNotAMatch() throws Exception {
        FakeClient client = new FakeClient(SUFFIX + ":0\n", false);
        assertFalse(new BreachChecker(client).check("password").breached());
    }

    @Test
    void onlyFiveCharacterPrefixIsSent() throws Exception {
        FakeClient client = new FakeClient("", false);
        new BreachChecker(client).check("password");
        assertEquals(PREFIX, client.requestedPrefix);
        assertEquals(5, client.requestedPrefix.length());
    }

    @Test
    void networkFailureBecomesBreachCheckException() {
        FakeClient client = new FakeClient(null, true);
        assertThrows(BreachCheckException.class, () -> new BreachChecker(client).check("password"));
    }

    @Test
    void malformedResponseBecomesBreachCheckException() {
        FakeClient client = new FakeClient("this is not a range response\n", false);
        assertThrows(BreachCheckException.class, () -> new BreachChecker(client).check("password"));
    }
}
