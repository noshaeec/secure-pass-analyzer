package com.noxolo.passwordsecurity.breach;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Pattern;

/**
 * HIBP "Pwned Passwords" range API client using the JDK's built-in HttpClient.
 * Only the 5-character hash prefix is placed in the request URL.
 */
public class HttpHibpClient implements HibpClient {

    private static final String BASE_URL = "https://api.pwnedpasswords.com/range/";
    private static final Pattern PREFIX = Pattern.compile("[0-9A-F]{5}");

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Override
    public String fetchRange(String prefix) throws IOException {
        if (!PREFIX.matcher(prefix).matches()) {
            throw new IllegalArgumentException("prefix must be exactly 5 uppercase hex characters");
        }

        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + prefix))
                .timeout(Duration.ofSeconds(10))
                .header("User-Agent", "secure-pass-analyzer")
                // Asks HIBP to pad responses so their size doesn't reveal how many matches exist.
                .header("Add-Padding", "true")
                .GET()
                .build();

        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("HIBP returned HTTP " + response.statusCode());
            }
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while contacting HIBP", e);
        }
    }
}
