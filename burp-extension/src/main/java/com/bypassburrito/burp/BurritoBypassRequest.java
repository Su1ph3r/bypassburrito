package com.bypassburrito.burp;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a bypass request to send to the BypassBurrito server
 */
public class BurritoBypassRequest {

    private String id;
    private String url;
    private String method;
    private String parameter;
    private String position;
    private String attackType;
    private List<String> payloads;
    private String rawRequest;

    public BurritoBypassRequest() {
        this.payloads = new ArrayList<>();
        this.method = "GET";
        this.position = "query";
        this.attackType = "sqli";
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getParameter() {
        return parameter;
    }

    public void setParameter(String parameter) {
        this.parameter = parameter;
    }

    public String getPosition() {
        return position;
    }

    public void setPosition(String position) {
        this.position = position;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public List<String> getPayloads() {
        return payloads;
    }

    public void setPayloads(List<String> payloads) {
        this.payloads = payloads;
    }

    public String getRawRequest() {
        return rawRequest;
    }

    public void setRawRequest(String rawRequest) {
        this.rawRequest = rawRequest;
    }
}
