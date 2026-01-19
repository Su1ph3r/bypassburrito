package com.bypassburrito.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.bypassburrito.burp.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main UI tab for BypassBurrito extension
 */
public class BurritoTab extends JPanel {

    private final MontoyaApi api;
    private final BurritoExtension extension;

    private JTabbedPane mainTabs;
    private JTable resultsTable;
    private DefaultTableModel resultsModel;
    private JTextArea logArea;
    private JTextField serverUrlField;
    private JTextField authTokenField;
    private JLabel statusLabel;

    private final Map<String, Integer> requestRowMap = new ConcurrentHashMap<>();

    public BurritoTab(MontoyaApi api, BurritoExtension extension) {
        this.api = api;
        this.extension = extension;
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        mainTabs = new JTabbedPane();

        // Results tab
        mainTabs.addTab("Results", createResultsPanel());

        // Queue tab
        mainTabs.addTab("Queue", createQueuePanel());

        // Configuration tab
        mainTabs.addTab("Configuration", createConfigPanel());

        // Log tab
        mainTabs.addTab("Log", createLogPanel());

        add(mainTabs, BorderLayout.CENTER);

        // Status bar
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("Ready");
        statusBar.add(statusLabel);
        add(statusBar, BorderLayout.SOUTH);
    }

    private JPanel createResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Results table
        String[] columns = {"#", "URL", "Parameter", "Attack", "WAF", "Status", "Bypass Payload", "Mutations"};
        resultsModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultsTable = new JTable(resultsModel);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // Set column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(250);
        resultsTable.getColumnModel().getColumn(7).setPreferredWidth(150);

        // Double-click to view details
        resultsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = resultsTable.getSelectedRow();
                    if (row >= 0) {
                        showResultDetails(row);
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(resultsTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> clearResults());
        toolbar.add(clearBtn);

        JButton exportBtn = new JButton("Export Results");
        exportBtn.addActionListener(e -> exportResults());
        toolbar.add(exportBtn);

        panel.add(toolbar, BorderLayout.NORTH);

        return panel;
    }

    private JPanel createQueuePanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JTextArea queueInfo = new JTextArea("Queue status will be displayed here.\n\nUse 'Refresh' to update.");
        queueInfo.setEditable(false);
        panel.add(new JScrollPane(queueInfo), BorderLayout.CENTER);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refreshBtn = new JButton("Refresh Queue");
        refreshBtn.addActionListener(e -> {
            var queue = extension.getApiClient().getQueue();
            if (queue != null) {
                queueInfo.setText("Queue Status:\n" + queue.toString());
            } else {
                queueInfo.setText("Failed to fetch queue. Is the server running?");
            }
        });
        toolbar.add(refreshBtn);
        panel.add(toolbar, BorderLayout.NORTH);

        return panel;
    }

    private JPanel createConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        // Server URL
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Server URL:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        serverUrlField = new JTextField("http://localhost:8089", 30);
        panel.add(serverUrlField, gbc);

        // Auth Token
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("Auth Token:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        authTokenField = new JPasswordField(30);
        panel.add(authTokenField, gbc);

        // Test Connection button
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> testConnection());
        buttonPanel.add(testBtn);

        JButton saveBtn = new JButton("Save Configuration");
        saveBtn.addActionListener(e -> saveConfiguration());
        buttonPanel.add(saveBtn);

        panel.add(buttonPanel, gbc);

        // Instructions
        gbc.gridy = 3;
        JTextArea instructions = new JTextArea(
            "Instructions:\n\n" +
            "1. Start the BypassBurrito server:\n" +
            "   burrito serve --port 8089\n\n" +
            "2. Configure the server URL above\n\n" +
            "3. Right-click on any request in Burp and select:\n" +
            "   'BypassBurrito' > 'Send to Bypass Generator'\n\n" +
            "4. Results will appear in the 'Results' tab and as Burp Scanner issues"
        );
        instructions.setEditable(false);
        instructions.setBackground(panel.getBackground());
        instructions.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        panel.add(instructions, gbc);

        // Filler
        gbc.gridy = 4; gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);

        return panel;
    }

    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        panel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(e -> logArea.setText(""));
        toolbar.add(clearBtn);
        panel.add(toolbar, BorderLayout.NORTH);

        return panel;
    }

    public void addPendingRequest(BurritoBypassRequest request) {
        SwingUtilities.invokeLater(() -> {
            int row = resultsModel.getRowCount() + 1;
            resultsModel.addRow(new Object[]{
                row,
                truncate(request.getUrl(), 50),
                request.getParameter(),
                request.getAttackType(),
                "-",
                "Pending",
                "-",
                "-"
            });
            requestRowMap.put(request.getId(), row - 1);
            log("Queued bypass request: " + request.getId());
        });
    }

    public void updateRequestStatus(String requestId, String status, String jobId) {
        SwingUtilities.invokeLater(() -> {
            Integer row = requestRowMap.get(requestId);
            if (row != null && row < resultsModel.getRowCount()) {
                resultsModel.setValueAt(status, row, 5);
            }
            log("Request " + requestId + " status: " + status);
        });
    }

    public void updateProgress(String requestId, int progress) {
        SwingUtilities.invokeLater(() -> {
            Integer row = requestRowMap.get(requestId);
            if (row != null && row < resultsModel.getRowCount()) {
                resultsModel.setValueAt("Running (" + progress + "%)", row, 5);
            }
        });
    }

    public void addResult(BurritoBypassResult result) {
        SwingUtilities.invokeLater(() -> {
            Integer row = requestRowMap.get(result.getId());
            if (row != null && row < resultsModel.getRowCount()) {
                String status = result.isSuccess() ? "SUCCESS" : "No bypass";
                String waf = result.getWafType() != null ? result.getWafType() : "-";
                String payload = result.isSuccess() && result.getSuccessfulBypass() != null ?
                    truncate(result.getSuccessfulBypass().getPayload(), 60) : "-";
                String mutations = result.isSuccess() && result.getSuccessfulBypass() != null &&
                    result.getSuccessfulBypass().getMutations() != null ?
                    String.join(", ", result.getSuccessfulBypass().getMutations()) : "-";

                resultsModel.setValueAt(waf, row, 4);
                resultsModel.setValueAt(status, row, 5);
                resultsModel.setValueAt(payload, row, 6);
                resultsModel.setValueAt(truncate(mutations, 40), row, 7);
            }

            if (result.isSuccess()) {
                log("BYPASS FOUND for " + result.getId() + ": " +
                    (result.getSuccessfulBypass() != null ? result.getSuccessfulBypass().getPayload() : ""));
            } else {
                log("No bypass found for " + result.getId());
            }
        });
    }

    private void showResultDetails(int row) {
        StringBuilder details = new StringBuilder();
        for (int i = 0; i < resultsModel.getColumnCount(); i++) {
            details.append(resultsModel.getColumnName(i)).append(": ")
                   .append(resultsModel.getValueAt(row, i)).append("\n");
        }

        JTextArea textArea = new JTextArea(details.toString());
        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JOptionPane.showMessageDialog(this,
            new JScrollPane(textArea),
            "Result Details",
            JOptionPane.INFORMATION_MESSAGE);
    }

    private void clearResults() {
        resultsModel.setRowCount(0);
        requestRowMap.clear();
        log("Results cleared");
    }

    private void exportResults() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = chooser.getSelectedFile();
                try (java.io.PrintWriter writer = new java.io.PrintWriter(file)) {
                    // Write header
                    for (int i = 0; i < resultsModel.getColumnCount(); i++) {
                        writer.print(resultsModel.getColumnName(i));
                        if (i < resultsModel.getColumnCount() - 1) writer.print(",");
                    }
                    writer.println();

                    // Write rows
                    for (int row = 0; row < resultsModel.getRowCount(); row++) {
                        for (int col = 0; col < resultsModel.getColumnCount(); col++) {
                            Object val = resultsModel.getValueAt(row, col);
                            writer.print("\"" + (val != null ? val.toString().replace("\"", "\"\"") : "") + "\"");
                            if (col < resultsModel.getColumnCount() - 1) writer.print(",");
                        }
                        writer.println();
                    }
                }
                log("Exported results to: " + file.getAbsolutePath());
                JOptionPane.showMessageDialog(this, "Results exported successfully!");
            } catch (Exception e) {
                log("Export failed: " + e.getMessage());
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void testConnection() {
        String url = serverUrlField.getText().trim();
        String token = authTokenField.getText().trim();

        extension.setServerUrl(url);
        if (!token.isEmpty()) {
            extension.getApiClient().setAuthToken(token);
        }

        new Thread(() -> {
            boolean healthy = extension.getApiClient().isHealthy();
            SwingUtilities.invokeLater(() -> {
                if (healthy) {
                    JOptionPane.showMessageDialog(this,
                        "Connected to BypassBurrito server successfully!",
                        "Connection Test",
                        JOptionPane.INFORMATION_MESSAGE);
                    statusLabel.setText("Connected to " + url);
                } else {
                    JOptionPane.showMessageDialog(this,
                        "Failed to connect to server.\nMake sure burrito serve is running.",
                        "Connection Test",
                        JOptionPane.ERROR_MESSAGE);
                    statusLabel.setText("Disconnected");
                }
            });
        }).start();
    }

    private void saveConfiguration() {
        // Configuration is already applied via testConnection
        JOptionPane.showMessageDialog(this,
            "Configuration saved.\nNote: Settings are not persisted between Burp sessions yet.",
            "Configuration",
            JOptionPane.INFORMATION_MESSAGE);
    }

    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        extension.getLogging().logToOutput(message);
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max - 3) + "...";
    }
}
