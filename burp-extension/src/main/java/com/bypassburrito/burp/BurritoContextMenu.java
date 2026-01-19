package com.bypassburrito.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Context menu provider for right-click "Send to BypassBurrito" functionality
 */
public class BurritoContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final BurritoExtension extension;

    public BurritoContextMenu(MontoyaApi api, BurritoExtension extension) {
        this.api = api;
        this.extension = extension;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Only show for requests
        if (event.selectedRequestResponses().isEmpty() &&
            event.messageEditorRequestResponse().isEmpty()) {
            return menuItems;
        }

        // Get the request(s)
        List<HttpRequestResponse> requestResponses = new ArrayList<>();
        if (event.selectedRequestResponses().isPresent()) {
            requestResponses.addAll(event.selectedRequestResponses().get());
        }
        if (event.messageEditorRequestResponse().isPresent()) {
            requestResponses.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (requestResponses.isEmpty()) {
            return menuItems;
        }

        // Create main menu
        JMenu burritoMenu = new JMenu("BypassBurrito");

        // Send to Bypass Generator
        JMenuItem sendToBypass = new JMenuItem("Send to Bypass Generator");
        sendToBypass.addActionListener(e -> showBypassDialog(requestResponses));
        burritoMenu.add(sendToBypass);

        // Quick bypass submenus
        JMenu quickBypass = new JMenu("Quick Bypass");

        JMenuItem sqliBypass = new JMenuItem("SQLi Bypass");
        sqliBypass.addActionListener(e -> quickBypass(requestResponses, "sqli"));
        quickBypass.add(sqliBypass);

        JMenuItem xssBypass = new JMenuItem("XSS Bypass");
        xssBypass.addActionListener(e -> quickBypass(requestResponses, "xss"));
        quickBypass.add(xssBypass);

        JMenuItem cmdiBypass = new JMenuItem("Command Injection Bypass");
        cmdiBypass.addActionListener(e -> quickBypass(requestResponses, "cmdi"));
        quickBypass.add(cmdiBypass);

        JMenuItem pathBypass = new JMenuItem("Path Traversal Bypass");
        pathBypass.addActionListener(e -> quickBypass(requestResponses, "path_traversal"));
        quickBypass.add(pathBypass);

        burritoMenu.add(quickBypass);
        burritoMenu.addSeparator();

        // Detect WAF
        JMenuItem detectWAF = new JMenuItem("Detect WAF");
        detectWAF.addActionListener(e -> detectWAF(requestResponses.get(0)));
        burritoMenu.add(detectWAF);

        menuItems.add(burritoMenu);
        return menuItems;
    }

    private void showBypassDialog(List<HttpRequestResponse> requestResponses) {
        HttpRequestResponse reqRes = requestResponses.get(0);
        HttpRequest request = reqRes.request();

        // Extract parameters
        List<HttpParameter> params = request.parameters();

        if (params.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                "No parameters found in request. Add a parameter to test.",
                "BypassBurrito",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Create dialog
        JDialog dialog = new JDialog((Frame) null, "BypassBurrito - Configure Bypass", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(500, 400);
        dialog.setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // URL
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("Target URL:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        JTextField urlField = new JTextField(request.url());
        urlField.setEditable(false);
        mainPanel.add(urlField, gbc);

        // Parameter selection
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        mainPanel.add(new JLabel("Parameter:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        JComboBox<String> paramCombo = new JComboBox<>();
        for (HttpParameter param : params) {
            paramCombo.addItem(param.name() + " (" + param.type().name() + ")");
        }
        mainPanel.add(paramCombo, gbc);

        // Attack type
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        mainPanel.add(new JLabel("Attack Type:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        JComboBox<String> attackCombo = new JComboBox<>(new String[]{
            "sqli", "xss", "cmdi", "path_traversal", "ssti", "xxe"
        });
        mainPanel.add(attackCombo, gbc);

        // Custom payload (optional)
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        mainPanel.add(new JLabel("Custom Payload:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        JTextField payloadField = new JTextField();
        mainPanel.add(payloadField, gbc);
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
        mainPanel.add(new JLabel("<html><i>(Leave empty to use built-in payloads)</i></html>"), gbc);

        dialog.add(mainPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());
        JButton submitBtn = new JButton("Start Bypass");
        submitBtn.addActionListener(e -> {
            int selectedIdx = paramCombo.getSelectedIndex();
            HttpParameter selectedParam = params.get(selectedIdx);

            BurritoBypassRequest bypassReq = new BurritoBypassRequest();
            bypassReq.setId(UUID.randomUUID().toString());
            bypassReq.setUrl(request.url());
            bypassReq.setMethod(request.method());
            bypassReq.setParameter(selectedParam.name());
            bypassReq.setPosition(paramTypeToPosition(selectedParam.type()));
            bypassReq.setAttackType((String) attackCombo.getSelectedItem());

            String customPayload = payloadField.getText().trim();
            if (!customPayload.isEmpty()) {
                bypassReq.setPayloads(List.of(customPayload));
            }

            extension.submitBypassRequest(bypassReq);
            dialog.dispose();

            // Switch to BypassBurrito tab
            extension.getTab().setVisible(true);
        });

        buttonPanel.add(cancelBtn);
        buttonPanel.add(submitBtn);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    private void quickBypass(List<HttpRequestResponse> requestResponses, String attackType) {
        HttpRequestResponse reqRes = requestResponses.get(0);
        HttpRequest request = reqRes.request();
        List<HttpParameter> params = request.parameters();

        if (params.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                "No parameters found in request.",
                "BypassBurrito",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Use first parameter for quick bypass
        HttpParameter param = params.get(0);

        BurritoBypassRequest bypassReq = new BurritoBypassRequest();
        bypassReq.setId(UUID.randomUUID().toString());
        bypassReq.setUrl(request.url());
        bypassReq.setMethod(request.method());
        bypassReq.setParameter(param.name());
        bypassReq.setPosition(paramTypeToPosition(param.type()));
        bypassReq.setAttackType(attackType);

        extension.submitBypassRequest(bypassReq);
        extension.getLogging().logToOutput("Quick " + attackType + " bypass started for parameter: " + param.name());
    }

    private void detectWAF(HttpRequestResponse reqRes) {
        String url = reqRes.request().url();

        new Thread(() -> {
            extension.getLogging().logToOutput("Detecting WAF for: " + url);
            var result = extension.getApiClient().detectWAF(url);
            if (result != null) {
                boolean detected = result.has("detected") && result.get("detected").getAsBoolean();
                if (detected) {
                    String wafType = result.has("type") ? result.get("type").getAsString() : "Unknown";
                    double confidence = result.has("confidence") ? result.get("confidence").getAsDouble() * 100 : 0;
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(null,
                            String.format("WAF Detected: %s\nConfidence: %.0f%%", wafType, confidence),
                            "BypassBurrito - WAF Detection",
                            JOptionPane.INFORMATION_MESSAGE);
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(null,
                            "No WAF detected (or WAF is not blocking)",
                            "BypassBurrito - WAF Detection",
                            JOptionPane.INFORMATION_MESSAGE);
                    });
                }
            } else {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(null,
                        "Failed to connect to BypassBurrito server.\nMake sure it's running: burrito serve",
                        "BypassBurrito Error",
                        JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    private String paramTypeToPosition(HttpParameterType type) {
        switch (type) {
            case URL: return "query";
            case BODY: return "body";
            case COOKIE: return "cookie";
            default: return "query";
        }
    }
}
