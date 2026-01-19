package com.bypassburrito.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.bypassburrito.burp.ui.BurritoTab;

/**
 * BypassBurrito Burp Suite Extension
 *
 * This extension integrates with the BypassBurrito server to provide
 * LLM-powered WAF bypass generation directly within Burp Suite Pro.
 */
public class BurritoExtension implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;
    private BurritoApiClient apiClient;
    private BurritoTab tab;

    public static final String EXTENSION_NAME = "BypassBurrito";
    public static final String VERSION = "1.0.0";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        // Set extension name
        api.extension().setName(EXTENSION_NAME);

        logging.logToOutput("Initializing " + EXTENSION_NAME + " v" + VERSION);

        // Create API client (default to localhost:8089)
        this.apiClient = new BurritoApiClient("http://localhost:8089", logging);

        // Register context menu for right-click "Send to BypassBurrito"
        api.userInterface().registerContextMenuItemsProvider(
            new BurritoContextMenu(api, this)
        );

        // Register custom tab in Burp UI
        this.tab = new BurritoTab(api, this);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab);

        // Register HTTP handler for intercepting responses
        api.http().registerHttpHandler(new BurritoHttpHandler(api, this));

        logging.logToOutput(EXTENSION_NAME + " loaded successfully!");
        logging.logToOutput("Make sure the BypassBurrito server is running: burrito serve --port 8089");
    }

    public MontoyaApi getApi() {
        return api;
    }

    public Logging getLogging() {
        return logging;
    }

    public BurritoApiClient getApiClient() {
        return apiClient;
    }

    public BurritoTab getTab() {
        return tab;
    }

    public void setServerUrl(String url) {
        this.apiClient = new BurritoApiClient(url, logging);
        logging.logToOutput("Server URL updated to: " + url);
    }

    /**
     * Submit a bypass request to the BypassBurrito server
     */
    public void submitBypassRequest(BurritoBypassRequest request) {
        tab.addPendingRequest(request);

        // Submit asynchronously
        new Thread(() -> {
            try {
                String jobId = apiClient.submitBypass(request);
                if (jobId != null) {
                    logging.logToOutput("Bypass job submitted: " + jobId);
                    tab.updateRequestStatus(request.getId(), "running", jobId);

                    // Poll for results
                    pollForResult(jobId, request.getId());
                }
            } catch (Exception e) {
                logging.logToError("Failed to submit bypass: " + e.getMessage());
                tab.updateRequestStatus(request.getId(), "failed", null);
            }
        }).start();
    }

    private void pollForResult(String jobId, String requestId) {
        int maxAttempts = 300; // 5 minutes with 1 second intervals
        int attempt = 0;

        while (attempt < maxAttempts) {
            try {
                Thread.sleep(1000);
                BurritoBypassResult result = apiClient.getBypassStatus(jobId);

                if (result != null) {
                    String status = result.getStatus();

                    if ("completed".equals(status)) {
                        logging.logToOutput("Bypass completed for job: " + jobId);
                        tab.addResult(result);

                        // Report as Burp issue if successful
                        if (result.isSuccess()) {
                            reportBypassIssue(result);
                        }
                        return;
                    } else if ("failed".equals(status) || "cancelled".equals(status)) {
                        logging.logToOutput("Bypass " + status + " for job: " + jobId);
                        tab.updateRequestStatus(requestId, status, jobId);
                        return;
                    }

                    // Update progress
                    tab.updateProgress(requestId, result.getProgress());
                }

                attempt++;
            } catch (Exception e) {
                logging.logToError("Error polling for result: " + e.getMessage());
                attempt++;
            }
        }

        logging.logToOutput("Bypass timed out for job: " + jobId);
        tab.updateRequestStatus(requestId, "timeout", jobId);
    }

    private void reportBypassIssue(BurritoBypassResult result) {
        if (result.getSuccessfulBypass() == null) {
            return;
        }

        BurritoIssueReporter reporter = new BurritoIssueReporter(api);
        reporter.reportBypass(result);
    }
}
