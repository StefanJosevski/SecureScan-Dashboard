package com.securescan;

import com.securescan.analysis.PhishingAnalyzer;
import com.securescan.model.AnalysisResult;
import com.securescan.model.Email;

public class SecureScanApp {

    public static void main(String[] args) {

        Email email = new Email(
                "support@bank-secure.com",
                "reply@scam-domain.com",
                "URGENT: Verify Your Account",
                "Act now! Verify immediately at http://bit.ly/fake-login"
        );

        PhishingAnalyzer analyzer = new PhishingAnalyzer();
        AnalysisResult result = analyzer.analyze(email);

        System.out.println(result);
        System.out.println(result.getSummary());
    }
}
