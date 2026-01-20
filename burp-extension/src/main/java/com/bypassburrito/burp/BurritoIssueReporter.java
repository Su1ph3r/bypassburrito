package com.bypassburrito.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Reports successful WAF bypasses as Burp Scanner issues
 */
public class BurritoIssueReporter {

    private final MontoyaApi api;

    public BurritoIssueReporter(MontoyaApi api) {
        this.api = api;
    }

    public void reportBypass(BurritoBypassResult result) {
        if (!result.isSuccess() || result.getSuccessfulBypass() == null) {
            return;
        }

        String name = "WAF Bypass Found - " + result.getAttackType();

        String detail = buildIssueDetail(result);
        String background = buildBackground(result);
        String remediation = buildRemediation(result);
        String remediationBackground = buildRemediationBackground();

        AuditIssue issue = AuditIssue.auditIssue(
            name,
            detail,
            remediation,
            result.getTargetUrl(),
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.CERTAIN,
            background,
            remediationBackground,
            AuditIssueSeverity.HIGH
        );

        api.siteMap().add(issue);
        api.logging().logToOutput("Reported WAF bypass issue: " + name);
    }

    private String buildIssueDetail(BurritoBypassResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>BypassBurrito discovered a WAF bypass for <b>")
          .append(escapeHtml(result.getAttackType()))
          .append("</b> attack.</p>");

        if (result.getWafType() != null) {
            sb.append("<h4>WAF Detected</h4>");
            sb.append("<p>").append(escapeHtml(result.getWafType()));
            if (result.getWafConfidence() > 0) {
                sb.append(" (confidence: ").append(String.format("%.0f%%", result.getWafConfidence() * 100)).append(")");
            }
            sb.append("</p>");
        }

        sb.append("<h4>Original Payload (Blocked)</h4>");
        sb.append("<pre>").append(escapeHtml(result.getOriginalPayloadValue())).append("</pre>");

        sb.append("<h4>Bypass Payload (Success)</h4>");
        sb.append("<pre>").append(escapeHtml(result.getSuccessfulBypass().getPayload())).append("</pre>");

        if (result.getSuccessfulBypass().getMutations() != null &&
            !result.getSuccessfulBypass().getMutations().isEmpty()) {
            sb.append("<h4>Mutations Applied</h4>");
            sb.append("<ul>");
            for (String mutation : result.getSuccessfulBypass().getMutations()) {
                sb.append("<li>").append(escapeHtml(mutation)).append("</li>");
            }
            sb.append("</ul>");
        }

        if (result.getCurlCommand() != null && !result.getCurlCommand().isEmpty()) {
            sb.append("<h4>Curl Command</h4>");
            sb.append("<pre>").append(escapeHtml(result.getCurlCommand())).append("</pre>");
        }

        return sb.toString();
    }

    private String buildBackground(BurritoBypassResult result) {
        return "<p>A Web Application Firewall (WAF) was detected protecting this application. " +
               "However, BypassBurrito was able to craft a payload that evades the WAF's detection " +
               "while maintaining the attack's functionality. This indicates a gap in the WAF's " +
               "rule coverage that could be exploited by attackers.</p>" +
               "<p>The bypass was discovered using LLM-powered mutation strategies that " +
               "iteratively modify payloads to avoid detection patterns.</p>";
    }

    private String buildRemediation(BurritoBypassResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>To address this WAF bypass:</p>");
        sb.append("<ol>");
        sb.append("<li>Review and update WAF rules to detect the bypass payload pattern</li>");
        sb.append("<li>Consider implementing multiple layers of defense (WAF + application-level validation)</li>");
        sb.append("<li>Add detection for the specific mutations used in this bypass:</li>");
        sb.append("<ul>");

        if (result.getSuccessfulBypass().getMutations() != null) {
            for (String mutation : result.getSuccessfulBypass().getMutations()) {
                sb.append("<li>").append(escapeHtml(mutation)).append("</li>");
            }
        }

        sb.append("</ul>");
        sb.append("<li>Test the fix using BypassBurrito to ensure the bypass no longer works</li>");
        sb.append("</ol>");

        return sb.toString();
    }

    private String buildRemediationBackground() {
        return "<p>WAF bypasses can occur due to various factors including:</p>" +
               "<ul>" +
               "<li>Incomplete pattern matching in WAF rules</li>" +
               "<li>Encoding transformations that evade detection</li>" +
               "<li>Protocol-level evasion techniques</li>" +
               "<li>Overly permissive allowlisting</li>" +
               "</ul>" +
               "<p>Regular testing with bypass tools like BypassBurrito helps identify " +
               "gaps in WAF coverage before attackers discover them.</p>";
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
