package com.noxolo.passwordsecurity.hashing;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashingDemoTest {

    // Low cost keeps the tests fast; the demo itself uses HashingDemo.DEMO_COST.
    private static final int TEST_COST = 4;

    @Test
    void sha256MatchesKnownVector() {
        assertEquals("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                HashingDemo.sha256Hex("password"));
    }

    @Test
    void unsaltedSha256GivesIdenticalHashesForSamePassword() {
        assertEquals(HashingDemo.sha256Hex("Summer2024!"), HashingDemo.sha256Hex("Summer2024!"));
    }

    @Test
    void unsaltedSha256IsCrackedByAWordlist() {
        String stolen = HashingDemo.sha256Hex("letmein");
        assertEquals("letmein", HashingDemo.crackSha256(stolen, List.of("123456", "letmein")).orElse(null));
    }

    @Test
    void sha256CrackFailsWhenPasswordIsNotInTheWordlist() {
        String stolen = HashingDemo.sha256Hex("a-long-unusual-passphrase");
        assertTrue(HashingDemo.crackSha256(stolen, List.of("123456", "letmein")).isEmpty());
    }

    @Test
    void bcryptGivesDifferentHashesForSamePassword() {
        String first = HashingDemo.bcryptHash("Summer2024!", TEST_COST);
        String second = HashingDemo.bcryptHash("Summer2024!", TEST_COST);
        assertNotEquals(first, second);
    }

    @Test
    void bcryptHashRecordsItsCostFactor() {
        assertTrue(HashingDemo.bcryptHash("anything", TEST_COST).startsWith("$2a$04$"));
    }

    @Test
    void bcryptVerifiesCorrectPasswordAndRejectsWrongOne() {
        String hash = HashingDemo.bcryptHash("Summer2024!", TEST_COST);
        assertTrue(HashingDemo.bcryptVerify("Summer2024!", hash));
        assertFalse(HashingDemo.bcryptVerify("summer2024!", hash));
    }

    @Test
    void bcryptCrackFindsAWeakPasswordButNotAStrongOne() {
        String weak = HashingDemo.bcryptHash("letmein", TEST_COST);
        String strong = HashingDemo.bcryptHash("a-long-unusual-passphrase", TEST_COST);
        List<String> wordlist = List.of("123456", "letmein");

        assertEquals("letmein", HashingDemo.crackBcrypt(weak, wordlist).orElse(null));
        assertTrue(HashingDemo.crackBcrypt(strong, wordlist).isEmpty());
    }
}
