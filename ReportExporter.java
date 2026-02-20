package com.securescan.util;

import com.securescan.model.AnalysisResult;
import com.securescan.model.PhishingIndicator;

import java.io.*;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

/**
 * ReportExporter
 * --------------
 * Generates a formatted PDF scan report using Apache PDFBox (loaded via
 * reflection so the app still runs if PDFBox is missing — falls back to .txt).
 *
 * Usage:
 *   ReportExporter.export(result, new File("report.pdf"));
 *
 * Requires in pom.xml:
 *   org.apache.pdfbox : pdfbox : 3.0.1
 */
public class ReportExporter {

    private static final DateTimeFormatter DT_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final float PAGE_WIDTH  = 595f;  // A4 in points
    private static final float PAGE_HEIGHT = 842f;
    private static final float MARGIN      = 50f;
    private static final float LINE_H      = 18f;

    // ─────────────────────────────────────────────────────────────────────
    //  PUBLIC ENTRY POINT
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Export result as PDF. Falls back to .txt if PDFBox is not on classpath.
     *
     * @param result     Completed AnalysisResult to export.
     * @param outputFile Destination file (e.g. "SecureScan_Report.pdf").
     * @throws Exception describing what went wrong or where the fallback was saved.
     */
    public static void export(AnalysisResult result, File outputFile) throws Exception {
        try {
            exportPdf(result, outputFile);
        } catch (ClassNotFoundException e) {
            File txt = new File(outputFile.getAbsolutePath().replace(".pdf", ".txt"));
            exportTxt(result, txt);
            throw new Exception("PDFBox not found — saved as plain text:\n" + txt.getAbsolutePath()
                    + "\n\nTo enable PDF export, add to pom.xml:\n"
                    + "<dependency>\n"
                    + "  <groupId>org.apache.pdfbox</groupId>\n"
                    + "  <artifactId>pdfbox</artifactId>\n"
                    + "  <version>3.0.1</version>\n"
                    + "</dependency>");
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  PDF EXPORT
    // ─────────────────────────────────────────────────────────────────────

    private static void exportPdf(AnalysisResult result, File outputFile) throws Exception {

        Class<?> docClass     = Class.forName("org.apache.pdfbox.pdmodel.PDDocument");
        Class<?> pageClass    = Class.forName("org.apache.pdfbox.pdmodel.PDPage");
        Class<?> rectClass    = Class.forName("org.apache.pdfbox.pdmodel.common.PDRectangle");
        Class<?> csClass      = Class.forName("org.apache.pdfbox.pdmodel.PDPageContentStream");
        Class<?> fontClass    = Class.forName("org.apache.pdfbox.pdmodel.font.PDType1Font");
        Class<?> stdFontClass = Class.forName("org.apache.pdfbox.pdmodel.font.Standard14Fonts");
        Class<?> fontNameEnum = Class.forName("org.apache.pdfbox.pdmodel.font.Standard14Fonts$FontName");

        // Resolve font enum constants
        Object[] enumVals = (Object[]) fontNameEnum.getEnumConstants();
        Object helvBold = Arrays.stream(enumVals).filter(e -> e.toString().equals("HELVETICA_BOLD")).findFirst().orElseThrow();
        Object helv     = Arrays.stream(enumVals).filter(e -> e.toString().equals("HELVETICA")).findFirst().orElseThrow();

        Object fontBold   = fontClass.getDeclaredConstructor(fontNameEnum).newInstance(helvBold);
        Object fontNormal = fontClass.getDeclaredConstructor(fontNameEnum).newInstance(helv);

        // Create document and page
        Object doc  = docClass.getDeclaredConstructor().newInstance();
        Object a4   = rectClass.getField("A4").get(null);
        Object page = pageClass.getDeclaredConstructor(rectClass).newInstance(a4);
        docClass.getMethod("addPage", pageClass).invoke(doc, page);

        // Open content stream
        Object cs = csClass.getDeclaredConstructor(docClass, pageClass).newInstance(doc, page);

        float y = PAGE_HEIGHT - MARGIN;

        // ── Navy header banner ──────────────────────────────
        setColor(cs, csClass, fontClass, 0.06f, 0.08f, 0.16f);
        fillRect(cs, csClass, 0, PAGE_HEIGHT - 80, PAGE_WIDTH, 80);

        setFont(cs, csClass, fontClass, fontNameEnum, fontBold, 20);
        setColor(cs, csClass, fontClass, 0.88f, 0.95f, 0.99f);
        drawText(cs, csClass, "SecureScan -- Phishing Analysis Report", MARGIN, PAGE_HEIGHT - 38);

        setFont(cs, csClass, fontClass, fontNameEnum, fontNormal, 10);
        setColor(cs, csClass, fontClass, 0.22f, 0.74f, 0.97f);
        drawText(cs, csClass, "Generated: " + DT_FMT.format(result.getAnalysisDate()), MARGIN, PAGE_HEIGHT - 60);

        y = PAGE_HEIGHT - 102;

        // ── Risk level pill ─────────────────────────────────
        float[] rc = riskColor(result.getRiskLevel());
        setColor(cs, csClass, fontClass, rc[0], rc[1], rc[2]);
        fillRect(cs, csClass, MARGIN, y - 32, 220, 38);

        setFont(cs, csClass, fontClass, fontNameEnum, fontBold, 13);
        setColor(cs, csClass, fontClass, 1f, 1f, 1f);
        drawText(cs, csClass, "RISK: " + result.getRiskLevel().getLabel().toUpperCase()
                + "   Score: " + result.getRiskScore() + " / 100", MARGIN + 10, y - 16);

        y -= 56;

        // ── Summary ─────────────────────────────────────────
        y = sectionHeader(cs, csClass, fontClass, fontNameEnum, fontBold, "SUMMARY", y);
        setFont(cs, csClass, fontClass, fontNameEnum, fontNormal, 11);
        setColor(cs, csClass, fontClass, 0.12f, 0.18f, 0.26f);
        y = wrappedText(cs, csClass, fontClass, fontNameEnum, fontNormal, result.getSummary(), y, 90);
        y -= 8;

        // ── Email details ───────────────────────────────────
        y = sectionHeader(cs, csClass, fontClass, fontNameEnum, fontBold, "EMAIL DETAILS", y);
        y = kvRow(cs, csClass, fontClass, fontNameEnum, fontBold, fontNormal, "From",     result.getEmail().getFrom(),    y);
        y = kvRow(cs, csClass, fontClass, fontNameEnum, fontBold, fontNormal, "Reply-To", result.getEmail().getReplyTo(), y);
        y = kvRow(cs, csClass, fontClass, fontNameEnum, fontBold, fontNormal, "Subject",  result.getEmail().getSubject(), y);
        y -= 8;

        // ── Indicators ──────────────────────────────────────
        y = sectionHeader(cs, csClass, fontClass, fontNameEnum, fontBold,
                "PHISHING INDICATORS (" + result.getIndicators().size() + " found)", y);

        if (result.getIndicators().isEmpty()) {
            setFont(cs, csClass, fontClass, fontNameEnum, fontNormal, 11);
            setColor(cs, csClass, fontClass, 0.09f, 0.64f, 0.27f);
            drawText(cs, csClass, "No indicators detected.", MARGIN, y);
            y -= LINE_H;
        } else {
            for (int i = 0; i < result.getIndicators().size(); i++) {
                if (y < 100) break;
                PhishingIndicator ind = result.getIndicators().get(i);
                float rowBg = i % 2 == 0 ? 0.97f : 0.93f;
                setColor(cs, csClass, fontClass, rowBg, rowBg, rowBg);
                fillRect(cs, csClass, MARGIN, y - 28, PAGE_WIDTH - 2 * MARGIN, 32);

                setFont(cs, csClass, fontClass, fontNameEnum, fontBold, 11);
                setColor(cs, csClass, fontClass, 0.55f, 0.09f, 0.09f);
                drawText(cs, csClass, ind.getName() + "  (+" + ind.getWeight() + "pt)", MARGIN + 6, y - 10);

                setFont(cs, csClass, fontClass, fontNameEnum, fontNormal, 10);
                setColor(cs, csClass, fontClass, 0.3f, 0.3f, 0.3f);
                String desc = ind.getDescription();
                if (desc.length() > 88) desc = desc.substring(0, 85) + "...";
                drawText(cs, csClass, desc, MARGIN + 6, y - 24);
                y -= 36;
            }
        }

        // ── Footer ──────────────────────────────────────────
        setColor(cs, csClass, fontClass, 0.06f, 0.08f, 0.16f);
        fillRect(cs, csClass, 0, 0, PAGE_WIDTH, 36);
        setFont(cs, csClass, fontClass, fontNameEnum, fontNormal, 9);
        setColor(cs, csClass, fontClass, 0.22f, 0.74f, 0.97f);
        drawText(cs, csClass, "SecureScan Phishing Intelligence Platform  |  For security review purposes only",
                MARGIN, 12);

        // Close stream and save
        csClass.getMethod("close").invoke(cs);
        docClass.getMethod("save", File.class).invoke(doc, outputFile);
        docClass.getMethod("close").invoke(doc);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  PDF DRAWING HELPERS
    // ─────────────────────────────────────────────────────────────────────

    private static float sectionHeader(Object cs, Class<?> csClass, Class<?> fontClass,
                                       Class<?> fontNameEnum, Object fontBold, String heading, float y) throws Exception {
        setColor(cs, csClass, fontClass, 0.06f, 0.08f, 0.16f);
        fillRect(cs, csClass, MARGIN, y - 4, PAGE_WIDTH - 2 * MARGIN, 2);
        setFont(cs, csClass, fontClass, fontNameEnum, fontBold, 11);
        setColor(cs, csClass, fontClass, 0.06f, 0.08f, 0.16f);
        drawText(cs, csClass, heading, MARGIN, y + 6);
        return y - 22;
    }

    private static float kvRow(Object cs, Class<?> csClass, Class<?> fontClass,
                               Class<?> fontNameEnum, Object fontBold, Object fontNormal,
                               String key, String value, float y) throws Exception {
        if (value == null || value.isBlank()) return y;
        setFont(cs, csClass, fontClass, fontNameEnum, fontBold, 10);
        setColor(cs, csClass, fontClass, 0.2f, 0.2f, 0.5f);
        drawText(cs, csClass, key + ":", MARGIN, y);
        setFont(cs, csClass, fontClass, fontNameEnum, fontNormal, 10);
        setColor(cs, csClass, fontClass, 0.2f, 0.2f, 0.2f);
        String v = value.length() > 72 ? value.substring(0, 69) + "..." : value;
        drawText(cs, csClass, v, MARGIN + 65, y);
        return y - LINE_H;
    }

    private static float wrappedText(Object cs, Class<?> csClass, Class<?> fontClass,
                                     Class<?> fontNameEnum, Object font, String text, float y, int charsPerLine) throws Exception {
        if (text == null) return y;
        while (!text.isEmpty()) {
            String line = text.length() > charsPerLine ? text.substring(0, charsPerLine) : text;
            drawText(cs, csClass, line, MARGIN, y);
            text = text.length() > charsPerLine ? text.substring(charsPerLine) : "";
            y -= LINE_H;
        }
        return y;
    }

    private static void setFont(Object cs, Class<?> csClass, Class<?> fontClass,
                                Class<?> fontNameEnum, Object font, int size) throws Exception {
        csClass.getMethod("setFont", fontClass, float.class).invoke(cs, font, (float) size);
    }

    private static void setColor(Object cs, Class<?> csClass, Class<?> fontClass,
                                 float r, float g, float b) throws Exception {
        csClass.getMethod("setNonStrokingColor", float.class, float.class, float.class)
                .invoke(cs, r, g, b);
    }

    private static void fillRect(Object cs, Class<?> csClass,
                                 float x, float y, float w, float h) throws Exception {
        csClass.getMethod("addRect", float.class, float.class, float.class, float.class)
                .invoke(cs, x, y, w, h);
        csClass.getMethod("fill").invoke(cs);
    }

    private static void drawText(Object cs, Class<?> csClass, String text,
                                 float x, float y) throws Exception {
        csClass.getMethod("beginText").invoke(cs);
        csClass.getMethod("newLineAtOffset", float.class, float.class).invoke(cs, x, y);
        // Strip non-ASCII for Type1 font compatibility
        String safe = text == null ? "" : text.replaceAll("[^\\x20-\\x7E]", "");
        csClass.getMethod("showText", String.class).invoke(cs, safe);
        csClass.getMethod("endText").invoke(cs);
    }

    private static float[] riskColor(AnalysisResult.RiskLevel level) {
        return switch (level) {
            case SAFE       -> new float[]{0.09f, 0.64f, 0.27f};
            case SUSPICIOUS -> new float[]{0.85f, 0.47f, 0.04f};
            case MALICIOUS  -> new float[]{0.86f, 0.15f, 0.15f};
        };
    }

    // ─────────────────────────────────────────────────────────────────────
    //  PLAIN TEXT FALLBACK
    // ─────────────────────────────────────────────────────────────────────

    public static void exportTxt(AnalysisResult result, File outputFile) throws IOException {
        String bar = "=".repeat(60);
        StringBuilder sb = new StringBuilder();
        sb.append("SECURESCAN — PHISHING ANALYSIS REPORT\n");
        sb.append(bar).append("\n");
        sb.append("Date:      ").append(DT_FMT.format(result.getAnalysisDate())).append("\n");
        sb.append("Subject:   ").append(result.getEmail().getSubject()).append("\n");
        sb.append("From:      ").append(result.getEmail().getFrom()).append("\n");
        sb.append("Reply-To:  ").append(result.getEmail().getReplyTo()).append("\n");
        sb.append(bar).append("\n");
        sb.append("RISK LEVEL : ").append(result.getRiskLevel().getLabel().toUpperCase()).append("\n");
        sb.append("RISK SCORE : ").append(result.getRiskScore()).append(" / 100\n");
        sb.append(bar).append("\n");
        sb.append("SUMMARY:\n").append(result.getSummary()).append("\n\n");
        sb.append("INDICATORS (").append(result.getIndicators().size()).append(" found):\n");
        if (result.getIndicators().isEmpty()) {
            sb.append("  No phishing indicators detected.\n");
        } else {
            for (PhishingIndicator ind : result.getIndicators()) {
                sb.append("  [+").append(ind.getWeight()).append("pt] ")
                        .append(ind.getName()).append(": ").append(ind.getDescription()).append("\n");
            }
        }
        sb.append(bar).append("\n");
        sb.append("SecureScan Phishing Intelligence Platform\n");
        try (Writer w = new FileWriter(outputFile)) {
            w.write(sb.toString());
        }
    }
}
