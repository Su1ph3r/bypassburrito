package com.bypassburrito.burp;

import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Represents the result of a bypass operation from the BypassBurrito server
 */
public class BurritoBypassResult {

    private String id;
    private String status;
    private int progress;
    private boolean success;

    @SerializedName("original_payload")
    private PayloadInfo originalPayload;

    @SerializedName("successful_bypass")
    private BypassInfo successfulBypass;

    @SerializedName("waf_detected")
    private WafInfo wafDetected;

    @SerializedName("total_iterations")
    private int totalIterations;

    private String duration;

    @SerializedName("curl_command")
    private String curlCommand;

    private String error;

    // Getters and Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getProgress() {
        return progress;
    }

    public void setProgress(int progress) {
        this.progress = progress;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public PayloadInfo getOriginalPayload() {
        return originalPayload;
    }

    public String getOriginalPayloadValue() {
        return originalPayload != null ? originalPayload.getValue() : "";
    }

    public BypassInfo getSuccessfulBypass() {
        return successfulBypass;
    }

    public WafInfo getWafDetected() {
        return wafDetected;
    }

    public String getWafType() {
        return wafDetected != null ? wafDetected.getType() : null;
    }

    public double getWafConfidence() {
        return wafDetected != null ? wafDetected.getConfidence() : 0;
    }

    public int getTotalIterations() {
        return totalIterations;
    }

    public String getDuration() {
        return duration;
    }

    public String getCurlCommand() {
        return curlCommand;
    }

    public String getError() {
        return error;
    }

    public String getTargetUrl() {
        // Extract from request if available
        return "";
    }

    public String getAttackType() {
        return originalPayload != null ? originalPayload.getType() : "unknown";
    }

    // Nested classes

    public static class PayloadInfo {
        private String value;
        private String type;

        public String getValue() {
            return value;
        }

        public String getType() {
            return type;
        }
    }

    public static class BypassInfo {
        private PayloadInfo payload;
        private List<String> mutations;
        private int iteration;

        @SerializedName("response_code")
        private int responseCode;

        public String getPayload() {
            return payload != null ? payload.getValue() : "";
        }

        public PayloadInfo getPayloadInfo() {
            return payload;
        }

        public List<String> getMutations() {
            return mutations;
        }

        public int getIteration() {
            return iteration;
        }

        public int getResponseCode() {
            return responseCode;
        }
    }

    public static class WafInfo {
        private String type;
        private String name;
        private double confidence;

        public String getType() {
            return type;
        }

        public String getName() {
            return name;
        }

        public double getConfidence() {
            return confidence;
        }
    }
}
