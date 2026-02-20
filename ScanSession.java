package com.securescan.util;

import com.securescan.model.AnalysisResult;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * ScanSession
 * -----------
 * Keeps an in-memory log of every scan completed during the current
 * application session. Used by the Trend Chart tab to plot risk scores
 * over time.
 *
 * Singleton — call ScanSession.getInstance() from anywhere.
 */
public class ScanSession {

    private static final ScanSession INSTANCE = new ScanSession();
    public static ScanSession getInstance() { return INSTANCE; }

    private final List<ScanEntry> entries = new ArrayList<>();

    private ScanSession() {}

    /** Record a completed scan result. */
    public void record(AnalysisResult result) {
        entries.add(new ScanEntry(result, LocalDateTime.now()));
    }

    /** All entries in chronological order (unmodifiable view). */
    public List<ScanEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public int size() { return entries.size(); }

    public void clear() { entries.clear(); }

    // ─────────────────────────────────────────────────────────────────────

    public static class ScanEntry {
        private static final DateTimeFormatter FMT =
                DateTimeFormatter.ofPattern("HH:mm:ss");

        public final AnalysisResult result;
        public final LocalDateTime  timestamp;

        public ScanEntry(AnalysisResult result, LocalDateTime timestamp) {
            this.result    = result;
            this.timestamp = timestamp;
        }

        public int    getScore()     { return result.getRiskScore(); }
        public String getRiskLabel() { return result.getRiskLevel().getLabel(); }
        public String getLabel()     { return "#" + timestamp.format(FMT); }
    }
}
