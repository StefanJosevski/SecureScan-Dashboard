package com.securescan.util;

import com.securescan.model.AnalysisResult;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HeaderParser
 * ------------
 * Parses raw email header text and extracts forensic fields:
 *   - X-Originating-IP / X-Sender-IP
 *   - Received: from (first hop)
 *   - DKIM-Signature status
 *   - SPF / Authentication-Results
 *   - Return-Path
 *
 * Populates the header fields on an AnalysisResult.
 * Also adds PhishingIndicators when headers show suspicious routing.
 */
public class HeaderParser {

    // ── Patterns ──────────────────────────────────────────────────────────
    private static final Pattern P_ORIG_IP   = Pattern.compile(
            "(?:X-Originating-IP|X-Sender-IP|X-Source-IP):\\s*([\\d.a-fA-F:]+)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern P_RECEIVED  = Pattern.compile(
            "Received:\\s+from\\s+(\\S+)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern P_DKIM      = Pattern.compile(
            "DKIM-Signature:\\s*(.*?)(?=\\r?\\n\\S|$)",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern P_SPF       = Pattern.compile(
            "(?:Authentication-Results|Received-SPF):[^\\n]*?(pass|fail|softfail|neutral|none)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern P_RETURN    = Pattern.compile(
            "Return-Path:\\s*<?(.*?)>?\\s*$",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final Pattern P_FROM_HDR  = Pattern.compile(
            "^From:\\s*(.*?)$",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final Pattern P_DISPLAY   = Pattern.compile(
            "\"?([^\"<@]+?)\"?\\s*<([^>]+)>",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern P_IP        = Pattern.compile(
            "\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b");

    // ─────────────────────────────────────────────────────────────────────

    /**
     * Parse raw header text and populate result header fields.
     * Returns true if any header content was found.
     */
    public static boolean parse(String rawText, AnalysisResult result) {
        if (rawText == null || rawText.isBlank()) return false;

        boolean found = false;

        // ── Originating IP ────────────────────────────────────────────────
        Matcher m = P_ORIG_IP.matcher(rawText);
        if (m.find()) {
            result.setHeaderOriginatingIp(m.group(1).trim());
            found = true;
        }

        // ── Received-from (first hop only) ────────────────────────────────
        m = P_RECEIVED.matcher(rawText);
        if (m.find()) {
            String recv = m.group(1).trim();
            // Try to extract IP from the line too
            Matcher ipM = P_IP.matcher(rawText.substring(m.start(), Math.min(m.end() + 120, rawText.length())));
            String ip = ipM.find() ? "  [" + ipM.group(1) + "]" : "";
            result.setHeaderReceivedFrom(recv + ip);
            found = true;
        }

        // ── DKIM ──────────────────────────────────────────────────────────
        m = P_DKIM.matcher(rawText);
        if (m.find()) {
            String dkimLine = m.group(1).replaceAll("\\s+", " ").trim();
            // Extract d= (signing domain) and a= (algorithm)
            String domain = extract(dkimLine, "d=([\\w.-]+)");
            String algo   = extract(dkimLine, "a=([\\w-]+)");
            result.setHeaderDkim(domain.isEmpty() ? "Present" : "domain=" + domain
                    + (algo.isEmpty() ? "" : "  algo=" + algo));
            found = true;
        } else {
            result.setHeaderDkim("Not present");
        }

        // ── SPF ───────────────────────────────────────────────────────────
        m = P_SPF.matcher(rawText);
        if (m.find()) {
            result.setHeaderSpf(m.group(1).toUpperCase());
            found = true;
        }

        // ── Return-Path ───────────────────────────────────────────────────
        m = P_RETURN.matcher(rawText);
        if (m.find()) {
            result.setHeaderReturnPath(m.group(1).trim());
            found = true;
        }

        result.setHeaderParsed(found);
        return found;
    }

    /**
     * Check parsed headers for suspicious signals.
     * Returns a SuspicionReport describing what was found.
     */
    public static SuspicionReport evaluate(AnalysisResult result, String rawText) {
        SuspicionReport report = new SuspicionReport();

        // ── SPF FAIL ──────────────────────────────────────────────────────
        String spf = result.getHeaderSpf();
        if (spf.equalsIgnoreCase("FAIL") || spf.equalsIgnoreCase("SOFTFAIL")) {
            report.addFlag("SPF " + spf,
                    "Server is not authorised to send on behalf of this domain", 30);
        }

        // ── No DKIM ───────────────────────────────────────────────────────
        if ("Not present".equals(result.getHeaderDkim())) {
            report.addFlag("No DKIM Signature",
                    "Email lacks a DKIM digital signature — cannot verify sender identity", 20);
        }

        // ── Return-Path mismatch ──────────────────────────────────────────
        String returnPath = result.getHeaderReturnPath();
        String from       = result.getEmail().getFrom();
        if (!returnPath.isBlank() && !from.isBlank()) {
            String rpDomain   = extractDomain(returnPath);
            String fromDomain = extractDomain(from);
            if (!rpDomain.isBlank() && !fromDomain.isBlank()
                    && !rpDomain.equalsIgnoreCase(fromDomain)) {
                report.addFlag("Return-Path Domain Mismatch",
                        "Return-Path domain (" + rpDomain + ") differs from From domain ("
                                + fromDomain + ")", 25);
            }
        }

        // ── Display name spoofing ─────────────────────────────────────────
        if (rawText != null) {
            Matcher fromHdr = P_FROM_HDR.matcher(rawText);
            if (fromHdr.find()) {
                String fromLine = fromHdr.group(1);
                Matcher dispM = P_DISPLAY.matcher(fromLine);
                if (dispM.find()) {
                    String displayName = dispM.group(1).trim().toLowerCase();
                    String emailAddr   = dispM.group(2).trim().toLowerCase();
                    String[] trustedBrands = {
                            "paypal", "amazon", "google", "microsoft", "apple",
                            "netflix", "bank", "support", "security", "account",
                            "noreply", "service", "help", "admin", "facebook",
                            "instagram", "linkedin", "dropbox", "ebay"
                    };
                    for (String brand : trustedBrands) {
                        if (displayName.contains(brand) && !emailAddr.contains(brand)) {
                            report.addFlag("Display Name Spoofing",
                                    "Display name claims to be '" + brand
                                            + "' but email address does not match", 35);
                            break;
                        }
                    }
                }
            }
        }

        // ── Private/suspicious originating IP ────────────────────────────
        String ip = result.getHeaderOriginatingIp();
        if (!ip.isBlank()) {
            if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) {
                report.addFlag("Private Originating IP",
                        "Email originated from private/internal IP: " + ip
                                + " — may indicate spoofing", 20);
            }
        }

        return report;
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private static String extract(String text, String regex) {
        Matcher m = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(text);
        return m.find() ? m.group(1) : "";
    }

    private static String extractDomain(String emailOrAddr) {
        int at = emailOrAddr.indexOf('@');
        if (at < 0) return "";
        return emailOrAddr.substring(at + 1).trim().toLowerCase()
                .replaceAll("[>\"\\s]", "");
    }

    // ─────────────────────────────────────────────────────────────────────

    public static class SuspicionReport {
        private final java.util.List<String> names   = new java.util.ArrayList<>();
        private final java.util.List<String> reasons = new java.util.ArrayList<>();
        private final java.util.List<Integer> weights = new java.util.ArrayList<>();

        public void addFlag(String name, String reason, int weight) {
            names.add(name);
            reasons.add(reason);
            weights.add(weight);
        }

        public boolean hasFlags()                  { return !names.isEmpty(); }
        public java.util.List<String>  getNames()  { return names; }
        public java.util.List<String>  getReasons(){ return reasons; }
        public java.util.List<Integer> getWeights(){ return weights; }
        public int totalWeight()                   { return weights.stream().mapToInt(i->i).sum(); }
    }
}
