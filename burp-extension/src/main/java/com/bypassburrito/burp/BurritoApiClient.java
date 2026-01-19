package com.bypassburrito.burp;

import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import okhttp3.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * HTTP client for communicating with the BypassBurrito server
 */
public class BurritoApiClient {

    private final String baseUrl;
    private final OkHttpClient client;
    private final Gson gson;
    private final Logging logging;
    private String authToken;

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    public BurritoApiClient(String baseUrl, Logging logging) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.logging = logging;
        this.gson = new Gson();
        this.client = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }

    public void setAuthToken(String token) {
        this.authToken = token;
    }

    /**
     * Check if the server is healthy
     */
    public boolean isHealthy() {
        try {
            Request request = buildRequest("/api/v1/health", "GET", null);
            try (Response response = client.newCall(request).execute()) {
                return response.isSuccessful();
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get server configuration
     */
    public JsonObject getConfig() {
        try {
            Request request = buildRequest("/api/v1/config", "GET", null);
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return gson.fromJson(response.body().string(), JsonObject.class);
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to get config: " + e.getMessage());
        }
        return null;
    }

    /**
     * Submit a bypass request
     */
    public String submitBypass(BurritoBypassRequest bypassRequest) throws IOException {
        JsonObject json = new JsonObject();
        json.addProperty("id", bypassRequest.getId());

        JsonObject target = new JsonObject();
        target.addProperty("url", bypassRequest.getUrl());
        target.addProperty("method", bypassRequest.getMethod());
        target.addProperty("parameter", bypassRequest.getParameter());
        target.addProperty("position", bypassRequest.getPosition());
        json.add("target", target);

        // Add payloads array
        com.google.gson.JsonArray payloads = new com.google.gson.JsonArray();
        for (String payload : bypassRequest.getPayloads()) {
            JsonObject p = new JsonObject();
            p.addProperty("value", payload);
            p.addProperty("type", bypassRequest.getAttackType());
            payloads.add(p);
        }
        json.add("payloads", payloads);

        Request request = buildRequest("/api/v1/bypass", "POST", json.toString());
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                JsonObject result = gson.fromJson(response.body().string(), JsonObject.class);
                return result.has("id") ? result.get("id").getAsString() : null;
            } else {
                String errorBody = response.body() != null ? response.body().string() : "Unknown error";
                logging.logToError("Bypass submission failed: " + response.code() + " - " + errorBody);
                return null;
            }
        }
    }

    /**
     * Get bypass job status
     */
    public BurritoBypassResult getBypassStatus(String jobId) throws IOException {
        Request request = buildRequest("/api/v1/bypass/" + jobId, "GET", null);
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                return gson.fromJson(response.body().string(), BurritoBypassResult.class);
            }
        }
        return null;
    }

    /**
     * Cancel a bypass job
     */
    public boolean cancelBypass(String jobId) {
        try {
            Request request = buildRequest("/api/v1/bypass/" + jobId, "DELETE", null);
            try (Response response = client.newCall(request).execute()) {
                return response.isSuccessful();
            }
        } catch (Exception e) {
            logging.logToError("Failed to cancel bypass: " + e.getMessage());
            return false;
        }
    }

    /**
     * Detect WAF on a target
     */
    public JsonObject detectWAF(String url) {
        try {
            JsonObject json = new JsonObject();
            json.addProperty("url", url);

            Request request = buildRequest("/api/v1/detect", "POST", json.toString());
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return gson.fromJson(response.body().string(), JsonObject.class);
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to detect WAF: " + e.getMessage());
        }
        return null;
    }

    /**
     * Get learned patterns
     */
    public JsonObject getPatterns(String wafFilter, String attackFilter) {
        try {
            StringBuilder path = new StringBuilder("/api/v1/patterns");
            if (wafFilter != null || attackFilter != null) {
                path.append("?");
                if (wafFilter != null) {
                    path.append("waf=").append(wafFilter);
                    if (attackFilter != null) path.append("&");
                }
                if (attackFilter != null) {
                    path.append("attack=").append(attackFilter);
                }
            }

            Request request = buildRequest(path.toString(), "GET", null);
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return gson.fromJson(response.body().string(), JsonObject.class);
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to get patterns: " + e.getMessage());
        }
        return null;
    }

    /**
     * Get queue status
     */
    public JsonObject getQueue() {
        try {
            Request request = buildRequest("/api/v1/queue", "GET", null);
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return gson.fromJson(response.body().string(), JsonObject.class);
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to get queue: " + e.getMessage());
        }
        return null;
    }

    private Request buildRequest(String path, String method, String body) {
        Request.Builder builder = new Request.Builder()
            .url(baseUrl + path);

        if (authToken != null && !authToken.isEmpty()) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        switch (method.toUpperCase()) {
            case "POST":
                builder.post(body != null ? RequestBody.create(body, JSON) : RequestBody.create("", JSON));
                break;
            case "PUT":
                builder.put(body != null ? RequestBody.create(body, JSON) : RequestBody.create("", JSON));
                break;
            case "DELETE":
                builder.delete();
                break;
            default:
                builder.get();
        }

        return builder.build();
    }
}
