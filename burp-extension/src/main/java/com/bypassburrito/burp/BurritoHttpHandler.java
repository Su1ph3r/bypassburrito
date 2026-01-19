package com.bypassburrito.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;

/**
 * HTTP handler for intercepting responses and optionally auto-analyzing
 */
public class BurritoHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final BurritoExtension extension;
    private boolean autoAnalyze = false;

    public BurritoHttpHandler(MontoyaApi api, BurritoExtension extension) {
        this.api = api;
        this.extension = extension;
    }

    public void setAutoAnalyze(boolean autoAnalyze) {
        this.autoAnalyze = autoAnalyze;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Pass through without modification
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!autoAnalyze) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Check for WAF block indicators
        int status = responseReceived.statusCode();
        String body = responseReceived.bodyToString();

        if (isLikelyWAFBlock(status, body)) {
            extension.getLogging().logToOutput(
                "Potential WAF block detected: " + responseReceived.initiatingRequest().url()
            );
            // Could auto-queue for bypass testing here
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private boolean isLikelyWAFBlock(int status, String body) {
        // Common WAF block indicators
        if (status == 403 || status == 406 || status == 429 || status == 503) {
            String lowerBody = body.toLowerCase();
            return lowerBody.contains("blocked") ||
                   lowerBody.contains("forbidden") ||
                   lowerBody.contains("access denied") ||
                   lowerBody.contains("waf") ||
                   lowerBody.contains("firewall") ||
                   lowerBody.contains("cloudflare") ||
                   lowerBody.contains("akamai") ||
                   lowerBody.contains("imperva") ||
                   lowerBody.contains("modsecurity");
        }
        return false;
    }
}
