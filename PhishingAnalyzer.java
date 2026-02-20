package com.securescan.analysis;

import com.securescan.model.AnalysisResult;
import com.securescan.model.Email;
import com.securescan.model.PhishingIndicator;

import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;

/**
 * PhishingAnalyzer  v2
 * --------------------
 * Upgraded detection engine with:
 *  1. Keyword highlighting  — records exact matched words per category
 *  2. Expanded urgency/threat vocabulary (40+ patterns)
 *  3. Homoglyph detection   — paypaI, miсrosoft, аmazon (Cyrillic/Unicode lookalikes)
 *  4. Lookalike domain detection — paypal-secure.com, amaz0n.com, micros0ft.com
 *  5. ALL CAPS subject detection
 *  6. Display name vs email mismatch
 *  7. Confidence score calculation  (0–100%)
 *  8. Excessive punctuation / exclamation marks
 *  9. Request for credentials / personal info
 * 10. Greeting mismatch (Dear Customer / Dear User instead of real name)
 */
public class PhishingAnalyzer {

    // ─────────────────────────────────────────────────────────────────────
    //  URGENCY / THREAT KEYWORDS
    // ─────────────────────────────────────────────────────────────────────
    private static final List<String> URGENCY_KEYWORDS = List.of(
            "urgent", "immediately", "act now", "limited time", "expires soon",
            "account suspended", "account locked", "account disabled", "verify now",
            "verify immediately", "confirm now", "confirm your", "validate your",
            "update your", "click here", "click immediately", "respond immediately",
            "final notice", "last warning", "last chance", "do not ignore",
            "failure to respond", "24 hours", "48 hours", "within 24", "within 48",
            "your account will be", "will be terminated", "will be suspended",
            "will be deleted", "will be closed", "action required", "action needed",
            "security alert", "security warning", "unusual activity", "suspicious activity",
            "unauthorized access", "your password", "reset your password",
            "prize", "winner", "congratulations", "won a", "selected you",
            "free gift", "claim your", "bonus offer"
    );

    // ─────────────────────────────────────────────────────────────────────
    //  CREDENTIAL HARVEST KEYWORDS
    // ─────────────────────────────────────────────────────────────────────
    private static final List<String> CREDENTIAL_KEYWORDS = List.of(
            "enter your password", "enter your username", "enter your email",
            "provide your", "submit your", "confirm your password",
            "social security", "ssn", "credit card", "card number",
            "bank account", "routing number", "pin number", "date of birth",
            "mother's maiden", "security question", "passphrase"
    );

    // ─────────────────────────────────────────────────────────────────────
    //  HOMOGLYPH MAP  (look-alike Unicode chars → ASCII)
    // ─────────────────────────────────────────────────────────────────────
    private static final Map<Character, Character> HOMOGLYPHS = new HashMap<>();
    static {
        // Cyrillic lookalikes
        HOMOGLYPHS.put('а', 'a'); HOMOGLYPHS.put('е', 'e'); HOMOGLYPHS.put('о', 'o');
        HOMOGLYPHS.put('р', 'p'); HOMOGLYPHS.put('с', 'c'); HOMOGLYPHS.put('х', 'x');
        HOMOGLYPHS.put('у', 'y'); HOMOGLYPHS.put('і', 'i'); HOMOGLYPHS.put('ν', 'v');
        // Zero/O, 1/l/I swaps
        HOMOGLYPHS.put('0', 'o'); HOMOGLYPHS.put('1', 'l'); HOMOGLYPHS.put('|', 'l');
        // Greek lookalikes
        HOMOGLYPHS.put('α', 'a'); HOMOGLYPHS.put('ο', 'o'); HOMOGLYPHS.put('ν', 'v');
        // Misc
        HOMOGLYPHS.put('ḿ', 'm'); HOMOGLYPHS.put('ṁ', 'm');
    }

    // ─────────────────────────────────────────────────────────────────────
    //  BRAND LOOKALIKE PATTERNS
    // ─────────────────────────────────────────────────────────────────────
    private static final List<Pattern> LOOKALIKE_PATTERNS = List.of(
            Pattern.compile("pay[p][a4][l1][^a-z]", Pattern.CASE_INSENSITIVE),   // payp4l, paypa1
            Pattern.compile("amaz[o0]n", Pattern.CASE_INSENSITIVE),               // amaz0n
            Pattern.compile("micr[o0]s[o0]ft", Pattern.CASE_INSENSITIVE),        // micr0soft
            Pattern.compile("g[o0]{2}gl[e3]", Pattern.CASE_INSENSITIVE),         // g00gle
            Pattern.compile("app[l1][e3]", Pattern.CASE_INSENSITIVE),            // app1e
            Pattern.compile("netfl[i1]x", Pattern.CASE_INSENSITIVE),             // netfl1x
            Pattern.compile("faceb[o0]{2}k", Pattern.CASE_INSENSITIVE),          // faceb00k
            Pattern.compile("pay[\\-_]?pal\\.(?!com)", Pattern.CASE_INSENSITIVE), // paypal.net etc
            Pattern.compile("amazon\\.(?!com|co\\.|de|fr|es|it|ca|au)", Pattern.CASE_INSENSITIVE)
    );

    // ─────────────────────────────────────────────────────────────────────
    //  SUSPICIOUS LINK PATTERNS
    // ─────────────────────────────────────────────────────────────────────
    private static final List<String> SHORTENERS = List.of(
            "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl",
            "short.link", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
            "tiny.cc", "lnkd.in", "db.tt", "qr.ae", "adf.ly"
    );

    // ─────────────────────────────────────────────────────────────────────
    //  MAIN ANALYSIS
    // ─────────────────────────────────────────────────────────────────────

    public AnalysisResult analyze(Email email) {
        List<PhishingIndicator> indicators = new ArrayList<>();
        Map<String, List<String>> matchedKeywords = new LinkedHashMap<>();
        int score = 0;

        String body    = email.getBody()    != null ? email.getBody()    : "";
        String subject = email.getSubject() != null ? email.getSubject() : "";
        String from    = email.getFrom()    != null ? email.getFrom()    : "";
        String replyTo = email.getReplyTo() != null ? email.getReplyTo() : "";
        String lower   = body.toLowerCase();
        String fullText = subject + " " + body;

        // ── 1. Suspicious / shortened links ──────────────────────────────
        List<String> linkMatches = new ArrayList<>();
        if (lower.contains("http://")) linkMatches.add("http:// (unencrypted)");
        for (String s : SHORTENERS) {
            if (lower.contains(s)) linkMatches.add(s);
        }
        if (!linkMatches.isEmpty()) {
            matchedKeywords.put("Suspicious Links", linkMatches);
            indicators.add(new PhishingIndicator(
                    "Suspicious Link",
                    "Contains: " + String.join(", ", linkMatches),
                    30));
            score += 30;
        }

        // ── 2. Urgency / fear language ────────────────────────────────────
        List<String> urgencyMatches = findMatches(fullText.toLowerCase(), URGENCY_KEYWORDS);
        if (!urgencyMatches.isEmpty()) {
            matchedKeywords.put("Urgency Language", urgencyMatches);
            String preview = urgencyMatches.stream().limit(4).collect(Collectors.joining(", "));
            indicators.add(new PhishingIndicator(
                    "Urgency Language",
                    "Matched: \"" + preview + "\""
                            + (urgencyMatches.size() > 4 ? " +" + (urgencyMatches.size()-4) + " more" : ""),
                    20 + Math.min(urgencyMatches.size() * 3, 15)));
            score += 20 + Math.min(urgencyMatches.size() * 3, 15);
        }

        // ── 3. Credential harvesting ──────────────────────────────────────
        List<String> credMatches = findMatches(lower, CREDENTIAL_KEYWORDS);
        if (!credMatches.isEmpty()) {
            matchedKeywords.put("Credential Harvest", credMatches);
            indicators.add(new PhishingIndicator(
                    "Credential Harvesting",
                    "Requests sensitive data: " + credMatches.stream().limit(3).collect(Collectors.joining(", ")),
                    35));
            score += 35;
        }

        // ── 4. Sender / Reply-To mismatch ─────────────────────────────────
        if (!from.isBlank() && !replyTo.isBlank()
                && !from.equalsIgnoreCase(replyTo)) {
            String fromDomain   = extractDomain(from);
            String replyDomain  = extractDomain(replyTo);
            if (!fromDomain.isBlank() && !replyDomain.isBlank()
                    && !fromDomain.equalsIgnoreCase(replyDomain)) {
                matchedKeywords.put("Sender Mismatch", List.of(from + " → " + replyTo));
                indicators.add(new PhishingIndicator(
                        "Sender / Reply-To Mismatch",
                        "From: " + from + "  |  Reply-To: " + replyTo,
                        25));
                score += 25;
            }
        }

        // ── 5. ALL CAPS subject ───────────────────────────────────────────
        if (subject.length() > 6) {
            String lettersOnly = subject.replaceAll("[^a-zA-Z]", "");
            long upper = lettersOnly.chars().filter(Character::isUpperCase).count();
            if (lettersOnly.length() > 0 && (double) upper / lettersOnly.length() > 0.7) {
                matchedKeywords.put("ALL CAPS Subject", List.of(subject));
                indicators.add(new PhishingIndicator(
                        "ALL CAPS Subject Line",
                        "Subject is predominantly uppercase — common social engineering tactic",
                        15));
                score += 15;
            }
        }

        // ── 6. Homoglyph attack ───────────────────────────────────────────
        String normalised = normaliseHomoglyphs(fullText);
        if (!normalised.equals(fullText)) {
            List<String> homoglyphChars = findHomoglyphChars(fullText);
            if (!homoglyphChars.isEmpty()) {
                matchedKeywords.put("Homoglyphs", homoglyphChars);
                indicators.add(new PhishingIndicator(
                        "Homoglyph / Unicode Spoofing",
                        "Contains lookalike characters: " + String.join(" ", homoglyphChars),
                        40));
                score += 40;
            }
        }

        // ── 7. Lookalike brand domain ─────────────────────────────────────
        List<String> lookalikeMatches = new ArrayList<>();
        for (Pattern p : LOOKALIKE_PATTERNS) {
            Matcher m = p.matcher(fullText);
            while (m.find()) {
                String found = m.group().trim();
                if (!lookalikeMatches.contains(found)) lookalikeMatches.add(found);
            }
        }
        if (!lookalikeMatches.isEmpty()) {
            matchedKeywords.put("Lookalike Domains", lookalikeMatches);
            indicators.add(new PhishingIndicator(
                    "Brand Lookalike Domain",
                    "Possible brand impersonation: " + String.join(", ", lookalikeMatches),
                    40));
            score += 40;
        }

        // ── 8. Excessive exclamation marks ────────────────────────────────
        long exclamCount = fullText.chars().filter(c -> c == '!').count();
        if (exclamCount >= 3) {
            matchedKeywords.put("Excessive Punctuation", List.of(exclamCount + " exclamation marks"));
            indicators.add(new PhishingIndicator(
                    "Excessive Punctuation",
                    exclamCount + " exclamation marks detected — typical of spam/scam content",
                    10));
            score += 10;
        }

        // ── 9. Generic greeting ───────────────────────────────────────────
        List<String> genericGreetings = List.of(
                "dear customer", "dear user", "dear account holder",
                "dear member", "dear valued customer", "hello user",
                "dear sir", "dear madam", "to whom it may concern"
        );
        List<String> greetingMatches = findMatches(lower, genericGreetings);
        if (!greetingMatches.isEmpty()) {
            matchedKeywords.put("Generic Greeting", greetingMatches);
            indicators.add(new PhishingIndicator(
                    "Generic / Impersonal Greeting",
                    "Uses non-personalised greeting: \"" + greetingMatches.get(0) + "\""
                            + " — legitimate services usually address you by name",
                    15));
            score += 15;
        }

        // ── Clamp score ───────────────────────────────────────────────────
        score = Math.min(score, 100);

        // ── Build result ──────────────────────────────────────────────────
        AnalysisResult result = new AnalysisResult(email);
        result.setRiskScore(score);
        result.setIndicators(indicators);
        result.setRiskLevel(result.calculateRiskLevel(score));
        result.setMatchedKeywords(matchedKeywords);
        result.setConfidencePercent(calculateConfidence(score, indicators.size()));
        result.setSummary(buildSummary(result));

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  CONFIDENCE CALCULATION
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Confidence measures how certain we are the risk score is correct.
     * Formula:
     *   - Base: risk score itself (higher score = more signals = more confident)
     *   - Bonus: number of independent indicator types caught
     *   - Penalty: very low scores (few signals → low confidence in SAFE verdict)
     */
    public static int calculateConfidence(int riskScore, int indicatorCount) {
        // Start from score
        double conf = riskScore;

        // Each additional independent indicator adds confidence
        conf += indicatorCount * 5.0;

        // If score is very low, confidence in "safe" is also moderate not high
        // (we can't be 100% sure just because nothing was found)
        if (riskScore < 20) conf = Math.max(conf, 30.0);

        // Cap at 97 — never claim 100% certainty
        return (int) Math.min(conf, 97);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────

    private List<String> findMatches(String text, List<String> keywords) {
        List<String> found = new ArrayList<>();
        for (String kw : keywords) {
            if (text.contains(kw) && !found.contains(kw)) found.add(kw);
        }
        return found;
    }

    private String normaliseHomoglyphs(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            sb.append(HOMOGLYPHS.getOrDefault(c, c));
        }
        return sb.toString();
    }

    private List<String> findHomoglyphChars(String text) {
        List<String> found = new ArrayList<>();
        for (char c : text.toCharArray()) {
            if (HOMOGLYPHS.containsKey(c)) {
                String entry = "'" + c + "'→'" + HOMOGLYPHS.get(c) + "'";
                if (!found.contains(entry)) found.add(entry);
            }
        }
        return found;
    }

    private String extractDomain(String emailAddr) {
        int at = emailAddr.lastIndexOf('@');
        if (at < 0) return "";
        return emailAddr.substring(at + 1).toLowerCase().trim();
    }

    private String buildSummary(AnalysisResult result) {
        String level = result.getRiskLevel().getLabel();
        int    score = result.getRiskScore();
        int    conf  = result.getConfidencePercent();
        int    count = result.getIndicators().size();

        if (count == 0) {
            return "No phishing indicators detected. Content appears safe. "
                    + "Confidence: " + conf + "% (" + result.getConfidenceLabel() + ")";
        }

        String topIndicator = result.getIndicators().stream()
                .max(Comparator.comparingInt(i -> i.getWeight()))
                .map(i -> i.getName())
                .orElse("unknown");

        return level + " content detected. " + count + " indicator"
                + (count == 1 ? "" : "s") + " found. "
                + "Strongest signal: " + topIndicator + ". "
                + "Confidence: " + conf + "% (" + result.getConfidenceLabel() + ").";
    }
}
