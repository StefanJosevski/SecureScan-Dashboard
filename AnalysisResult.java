package com.securescan.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AnalysisResult {

    public enum RiskLevel {
        SAFE("Safe", "#4CAF50"),
        SUSPICIOUS("Suspicious", "#FF9800"),
        MALICIOUS("Malicious", "#F44336");

        private final String label;
        private final String color;

        RiskLevel(String label, String color) {
            this.label = label;
            this.color = color;
        }

        public String getLabel() { return label; }
        public String getColor() { return color; }
    }

    private Email                       email;
    private int                         riskScore;
    private RiskLevel                   riskLevel;
    private List<PhishingIndicator>     indicators;
    private LocalDateTime               analysisDate;
    private String                      summary;

    // ── NEW: confidence % (0–100) derived from score + indicator depth ──
    private int confidencePercent;

    // ── NEW: keyword matches per category  { "urgency" -> ["urgent","act now"], ... } ──
    private Map<String, List<String>>   matchedKeywords = new LinkedHashMap<>();

    // ── NEW: parsed email header fields ──
    private String headerOriginatingIp  = "";
    private String headerReceivedFrom   = "";
    private String headerDkim           = "";
    private String headerSpf            = "";
    private String headerReturnPath     = "";
    private boolean headerParsed        = false;

    public AnalysisResult(Email email) {
        this.email       = email;
        this.indicators  = new ArrayList<>();
        this.analysisDate = LocalDateTime.now();
    }

    // ── standard getters / setters ───────────────────────────────────────
    public Email                    getEmail()            { return email; }
    public int                      getRiskScore()        { return riskScore; }
    public void                     setRiskScore(int s)   { this.riskScore = s; }
    public RiskLevel                getRiskLevel()        { return riskLevel; }
    public void                     setRiskLevel(RiskLevel l) { this.riskLevel = l; }
    public List<PhishingIndicator>  getIndicators()       { return indicators; }
    public void                     setIndicators(List<PhishingIndicator> i) { this.indicators = i; }
    public LocalDateTime            getAnalysisDate()     { return analysisDate; }
    public String                   getSummary()          { return summary; }
    public void                     setSummary(String s)  { this.summary = s; }

    // ── confidence ───────────────────────────────────────────────────────
    public int  getConfidencePercent()       { return confidencePercent; }
    public void setConfidencePercent(int c)  { this.confidencePercent = c; }

    /** Human-readable confidence label. */
    public String getConfidenceLabel() {
        if (confidencePercent >= 85) return "Very High";
        if (confidencePercent >= 65) return "High";
        if (confidencePercent >= 45) return "Moderate";
        if (confidencePercent >= 25) return "Low";
        return "Very Low";
    }

    // ── keyword matches ──────────────────────────────────────────────────
    public Map<String, List<String>> getMatchedKeywords()  { return matchedKeywords; }
    public void setMatchedKeywords(Map<String, List<String>> m) { this.matchedKeywords = m; }

    public void addMatchedKeywords(String category, List<String> words) {
        matchedKeywords.put(category, words);
    }

    /** Flat list of all matched words across all categories. */
    public List<String> getAllMatchedKeywords() {
        List<String> all = new ArrayList<>();
        matchedKeywords.values().forEach(all::addAll);
        return all;
    }

    // ── header fields ────────────────────────────────────────────────────
    public boolean isHeaderParsed()                  { return headerParsed; }
    public void    setHeaderParsed(boolean b)        { this.headerParsed = b; }
    public String  getHeaderOriginatingIp()          { return headerOriginatingIp; }
    public void    setHeaderOriginatingIp(String s)  { this.headerOriginatingIp = s; }
    public String  getHeaderReceivedFrom()           { return headerReceivedFrom; }
    public void    setHeaderReceivedFrom(String s)   { this.headerReceivedFrom = s; }
    public String  getHeaderDkim()                   { return headerDkim; }
    public void    setHeaderDkim(String s)           { this.headerDkim = s; }
    public String  getHeaderSpf()                    { return headerSpf; }
    public void    setHeaderSpf(String s)            { this.headerSpf = s; }
    public String  getHeaderReturnPath()             { return headerReturnPath; }
    public void    setHeaderReturnPath(String s)     { this.headerReturnPath = s; }

    // ── risk calculation ─────────────────────────────────────────────────
    public RiskLevel calculateRiskLevel(int score) {
        if (score < 30) return RiskLevel.SAFE;
        if (score < 70) return RiskLevel.SUSPICIOUS;
        return RiskLevel.MALICIOUS;
    }

    @Override
    public String toString() {
        return "AnalysisResult{score=" + riskScore
                + ", level=" + riskLevel
                + ", confidence=" + confidencePercent + "%"
                + ", indicators=" + indicators.size()
                + ", date=" + analysisDate + "}";
    }
}
