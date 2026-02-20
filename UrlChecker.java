package com.securescan.util;

import java.net.URI;
import java.util.*;
import java.util.regex.*;

/**
 * UrlChecker
 * ----------
 * Extracts all URLs from a block of text and checks each one
 * using local heuristics only — no API key or internet connection needed.
 *
 * Detects:
 *   - Unencrypted HTTP links
 *   - Known URL shorteners (bit.ly, tinyurl, etc.)
 *   - Raw IP addresses used instead of domain names
 *   - Excessive subdomains (domain spoofing technique)
 *   - Brand impersonation (paypal, amazon, microsoft, etc.)
 *   - Malformed / unparseable URLs
 */
public class UrlChecker {

    // ── URL extraction regex ──────────────────────────────────────────────
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)\\b((?:https?://|www\\.)[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])",
            Pattern.CASE_INSENSITIVE
    );

    // ── Known URL shortener domains ───────────────────────────────────────
    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl",
            "short.link", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
            "tiny.cc", "lnkd.in", "db.tt", "qr.ae", "adf.ly"
    );

    // ── Brand names to watch for spoofing ─────────────────────────────────
    private static final String[] BRANDS = {
            "paypal", "amazon", "google", "microsoft", "apple",
            "netflix", "bank", "secure", "login", "account", "verify",
            "ebay", "dropbox", "linkedin", "instagram", "facebook"
    };

    // ─────────────────────────────────────────────────────────────────────
    //  PUBLIC API
    // ─────────────────────────────────────────────────────────────────────

    /** Extract all unique URLs found in the given text. */
    public List<String> extractUrls(String text) {
        if (text == null || text.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) {
            String url = m.group(1);
            if (!urls.contains(url)) urls.add(url);
        }
        return Collections.unmodifiableList(urls);
    }

    /**
     * Check a list of URLs using local heuristics.
     *
     * @param urls  List of URLs to analyse.
     * @return      Map of url → UrlStatus with threat level and reason.
     */
    public Map<String, UrlStatus> checkUrls(List<String> urls) {
        Map<String, UrlStatus> results = new LinkedHashMap<>();
        for (String url : urls) {
            results.put(url, localCheck(url));
        }
        return results;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  LOCAL HEURISTICS
    // ─────────────────────────────────────────────────────────────────────

    private UrlStatus localCheck(String url) {
        String lower = url.toLowerCase();
        try {
            // Normalise for parsing
            String parseTarget = lower.startsWith("www.") ? "http://" + url : url;
            String host = new URI(parseTarget).getHost();
            if (host == null) host = lower;
            host = host.toLowerCase();

            // 1. Unencrypted HTTP
            if (lower.startsWith("http://")) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "Uses unencrypted HTTP — credentials can be intercepted");
            }

            // 2. Known URL shortener
            for (String s : SHORTENERS) {
                if (host.equals(s) || host.endsWith("." + s)) {
                    return new UrlStatus(url, Threat.SUSPICIOUS,
                            "Shortened URL (" + s + ") — hides the true destination");
                }
            }

            // 3. Raw IP address instead of domain name
            if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "URL uses a raw IP address instead of a domain name");
            }

            // 4. Excessive subdomains (more than 4 parts = suspicious)
            String[] parts = host.split("\\.");
            if (parts.length > 4) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "Excessive subdomains (" + host + ") — common spoofing technique");
            }

            // 5. Brand impersonation check
            for (String brand : BRANDS) {
                if (host.contains(brand) && !host.equals(brand + ".com")
                        && !host.endsWith("." + brand + ".com")) {
                    return new UrlStatus(url, Threat.SUSPICIOUS,
                            "Domain contains '" + brand + "' but is not the official site — possible brand spoofing");
                }
            }

            // 6. Suspicious keyword patterns in path
            String path = lower;
            if (path.contains("login") || path.contains("signin") || path.contains("verify")
                    || path.contains("update") || path.contains("confirm") || path.contains("secure")) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "URL path contains phishing keywords (login/verify/confirm)");
            }

            return new UrlStatus(url, Threat.CLEAN, "No threats detected");

        } catch (Exception e) {
            return new UrlStatus(url, Threat.SUSPICIOUS,
                    "Malformed URL — could not be parsed");
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  DATA TYPES
    // ─────────────────────────────────────────────────────────────────────

    public enum Threat { CLEAN, SUSPICIOUS, MALICIOUS }

    public static class UrlStatus {
        public final String url;
        public final Threat threat;
        public final String reason;

        public UrlStatus(String url, Threat threat, String reason) {
            this.url    = url;
            this.threat = threat;
            this.reason = reason;
        }

        public boolean isFlagged() { return threat != Threat.CLEAN; }
    }
}
