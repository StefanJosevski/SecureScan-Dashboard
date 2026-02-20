package com.securescan.analysis;

import com.securescan.model.AnalysisResult;
import com.securescan.model.Email;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PhishingAnalyzerTest {

    @Test
    void safeEmail_shouldBeSafeOrLowScore() {
        PhishingAnalyzer analyzer = new PhishingAnalyzer();

        Email email = new Email(
                "hr@company.com",
                "hr@company.com",
                "Meeting Reminder",
                "Reminder: team meeting tomorrow at 2pm."
        );

        AnalysisResult result = analyzer.analyze(email);

        assertTrue(result.getRiskScore() < 30);
        assertEquals(AnalysisResult.RiskLevel.SAFE, result.getRiskLevel());
    }

    @Test
    void phishingEmail_shouldBeMalicious() {
        PhishingAnalyzer analyzer = new PhishingAnalyzer();

        Email email = new Email(
                "support@bank-secure.com",
                "reply@scam-domain.com",
                "URGENT: Verify Account",
                "Act now! Verify immediately at http://bit.ly/fake-login"
        );

        AnalysisResult result = analyzer.analyze(email);

        assertTrue(result.getRiskScore() >= 70);
        assertEquals(AnalysisResult.RiskLevel.MALICIOUS, result.getRiskLevel());
        assertTrue(result.getIndicators().size() >= 2);
    }
}
