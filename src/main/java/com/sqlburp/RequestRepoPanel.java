package com.sqlburp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RequestRepoPanel extends JPanel {

    private final MontoyaApi api;
    private final SQLBurp mainExtension;
    
    private final RepoTableModel tableModel;
    private final JTable table;
    
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    
    private final Set<String> blacklist = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final List<ProxyRequestRecord> records = new CopyOnWriteArrayList<>();
    
    // Checkboxes
    private final JCheckBox uaCheck = new JCheckBox("Useragent");
    private final JCheckBox cookieCheck = new JCheckBox("Cookie");
    private final JCheckBox queryCheck = new JCheckBox("Query parameter");
    private final JCheckBox bodyCheck = new JCheckBox("Body parameter");
    private final JCheckBox pathCheck = new JCheckBox("Path injection");
    private final JCheckBox headersCheck = new JCheckBox("Add common headers");

    private final ExecutorService seqExecutor = Executors.newSingleThreadExecutor();

    public RequestRepoPanel(MontoyaApi api, SQLBurp mainExtension) {
        this.api = api;
        this.mainExtension = mainExtension;
        
        setLayout(new BorderLayout());
        
        tableModel = new RepoTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();
        
        // Add listener to update the underlying record when the user edits the request
        requestEditor.uiComponent().addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentHidden(java.awt.event.ComponentEvent e) {
                saveEditedRequest();
            }
        });
        
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            
            // Save any pending edits from the previously selected row before switching
            saveEditedRequest();
            
            int[] selected = table.getSelectedRows();
            if (selected.length == 1) {
                int mrow = table.convertRowIndexToModel(selected[0]);
                ProxyRequestRecord rec = records.get(mrow);
                requestEditor.setRequest(rec.rr.request());
                if (rec.rr.response() != null) {
                    responseEditor.setResponse(rec.rr.response());
                } else {
                    responseEditor.setResponse(null);
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        
        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorTabs);
        splitPane.setResizeWeight(0.5);
        add(splitPane, BorderLayout.CENTER);
        
        // Toolbar
        JPanel topPanel = new JPanel(new BorderLayout());
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> table.selectAll());
        
        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> table.clearSelection());
        
        JButton removeBtn = new JButton("Remove");
        removeBtn.setForeground(new Color(220, 53, 69)); // Red text for destructive action
        removeBtn.addActionListener(e -> removeSelected());
        
        JButton seqScanBtn = new JButton("Scan Sequential");
        seqScanBtn.putClientProperty("JButton.buttonType", "default"); // Primary button style
        seqScanBtn.setBackground(new Color(13, 110, 253));
        seqScanBtn.setForeground(Color.WHITE);
        seqScanBtn.addActionListener(e -> scanSelected(true));
        
        JButton parScanBtn = new JButton("Scan Parallel");
        parScanBtn.putClientProperty("JButton.buttonType", "default"); // Primary button style
        parScanBtn.setBackground(new Color(25, 135, 84));
        parScanBtn.setForeground(Color.WHITE);
        parScanBtn.addActionListener(e -> scanSelected(false));
        
        toolbar.add(selectAllBtn);
        toolbar.add(deselectAllBtn);
        toolbar.addSeparator();
        toolbar.add(removeBtn);
        toolbar.addSeparator();
        toolbar.add(seqScanBtn);
        toolbar.add(parScanBtn);
        
        // Injection points panel
        JPanel injectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        injectPanel.setBorder(BorderFactory.createTitledBorder("Mark Injection Points"));
        injectPanel.add(uaCheck);
        injectPanel.add(cookieCheck);
        injectPanel.add(queryCheck);
        injectPanel.add(bodyCheck);
        injectPanel.add(pathCheck);
        injectPanel.add(headersCheck);
        
        JButton markBtn = new JButton("Mark Selected");
        markBtn.addActionListener(e -> markSelected());
        injectPanel.add(markBtn);
        
        JButton clearBtn = new JButton("Clear Selected");
        clearBtn.addActionListener(e -> clearSelected());
        injectPanel.add(clearBtn);
        
        topPanel.add(toolbar, BorderLayout.NORTH);
        topPanel.add(injectPanel, BorderLayout.SOUTH);
        
        add(topPanel, BorderLayout.NORTH);
    }
    
    private void saveEditedRequest() {
        if (requestEditor.isModified()) {
            int[] selected = table.getSelectedRows();
            if (selected.length == 1) {
                int mrow = table.convertRowIndexToModel(selected[0]);
                ProxyRequestRecord rec = records.get(mrow);
                HttpRequest editedReq = requestEditor.getRequest();
                rec.rr = burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(editedReq, rec.rr.response());
                tableModel.fireTableRowsUpdated(mrow, mrow);
            }
        }
    }
    
    public void handleProxyRequest(HttpRequestResponse rr) {
        String path = rr.request().pathWithoutQuery().toLowerCase();
        if (path.endsWith(".js") || path.endsWith(".css") || path.endsWith(".png") ||
            path.endsWith(".jpg") || path.endsWith(".jpeg") || path.endsWith(".gif") ||
            path.endsWith(".svg") || path.endsWith(".ico") || path.endsWith(".woff") ||
            path.endsWith(".woff2") || path.endsWith(".ttf") || path.endsWith(".eot")) {
            return;
        }

        String key = generateKey(rr.request());
        if (blacklist.contains(key)) return;
        
        // Check if already exists in records
        for (ProxyRequestRecord rec : records) {
            if (rec.key.equals(key)) {
                // Update response if needed
                if (rec.rr.response() == null && rr.response() != null) {
                    rec.rr = rr;
                    SwingUtilities.invokeLater(() -> tableModel.fireTableDataChanged());
                }
                return;
            }
        }
        
        ProxyRequestRecord rec = new ProxyRequestRecord(key, rr);
        records.add(rec);
        SwingUtilities.invokeLater(() -> tableModel.fireTableRowsInserted(records.size() - 1, records.size() - 1));
    }
    
    private void removeSelected() {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) return;
        
        // Remove from end to start to not mess up indices
        List<ProxyRequestRecord> toRemove = new ArrayList<>();
        for (int i = selected.length - 1; i >= 0; i--) {
            int mrow = table.convertRowIndexToModel(selected[i]);
            ProxyRequestRecord rec = records.get(mrow);
            toRemove.add(rec);
            blacklist.add(rec.key);
        }
        records.removeAll(toRemove);
        tableModel.fireTableDataChanged();
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
    }
    
    private void scanSelected(boolean sequential) {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) return;
        
        List<HttpRequestResponse> toScan = new ArrayList<>();
        for (int vrow : selected) {
            int mrow = table.convertRowIndexToModel(vrow);
            toScan.add(records.get(mrow).rr);
        }
        
        if (sequential) {
            seqExecutor.submit(() -> {
                for (HttpRequestResponse rr : toScan) {
                    mainExtension.submitScanBlocking(rr.request(), rr.httpService());
                }
            });
        } else {
            for (HttpRequestResponse rr : toScan) {
                mainExtension.submitScanAsync(rr.request(), rr.httpService());
            }
        }
    }
    
    private void markSelected() {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) return;
        
        for (int vrow : selected) {
            int mrow = table.convertRowIndexToModel(vrow);
            ProxyRequestRecord rec = records.get(mrow);
            HttpRequest mutated = mutateRequest(rec.rr.request());
            rec.rr = burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(mutated, rec.rr.response());
            tableModel.fireTableRowsUpdated(mrow, mrow);
        }
        
        if (selected.length == 1) {
            int mrow = table.convertRowIndexToModel(selected[0]);
            requestEditor.setRequest(records.get(mrow).rr.request());
        }
    }
    
    private void clearSelected() {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) return;
        
        for (int vrow : selected) {
            int mrow = table.convertRowIndexToModel(vrow);
            ProxyRequestRecord rec = records.get(mrow);
            
            // Rebuild the request by converting to a string, removing *, and parsing back
            String rawReq = rec.rr.request().toString().replace("*", "");
            HttpRequest cleared = HttpRequest.httpRequest(reqHttpService(rec.rr.request()), rawReq);
            rec.rr = burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(cleared, rec.rr.response());
            tableModel.fireTableRowsUpdated(mrow, mrow);
        }
        
        if (selected.length == 1) {
            int mrow = table.convertRowIndexToModel(selected[0]);
            requestEditor.setRequest(records.get(mrow).rr.request());
        }
    }
    
    private burp.api.montoya.http.HttpService reqHttpService(HttpRequest req) {
        return burp.api.montoya.http.HttpService.httpService(req.httpService().host(), req.httpService().port(), req.httpService().secure());
    }
    
    private HttpRequest mutateRequest(HttpRequest original) {
        HttpRequest req = original;
        
        if (uaCheck.isSelected()) {
            boolean found = false;
            for (HttpHeader h : req.headers()) {
                if (h.name().equalsIgnoreCase("User-Agent")) {
                    req = req.withUpdatedHeader(h.name(), h.value() + "*");
                    found = true;
                    break;
                }
            }
            if (!found) {
                req = req.withAddedHeader("User-Agent", "Mozilla/5.0*");
            }
        }
        
        if (cookieCheck.isSelected()) {
            boolean found = false;
            for (HttpHeader h : req.headers()) {
                if (h.name().equalsIgnoreCase("Cookie")) {
                    String cookieStr = h.value();
                    String[] cookies = cookieStr.split(";");
                    StringBuilder mutatedCookie = new StringBuilder();
                    for (int i = 0; i < cookies.length; i++) {
                        String c = cookies[i];
                        if (c.contains("=")) {
                            mutatedCookie.append(c).append("*");
                        } else {
                            mutatedCookie.append(c);
                        }
                        if (i < cookies.length - 1) mutatedCookie.append(";");
                    }
                    req = req.withUpdatedHeader(h.name(), mutatedCookie.toString());
                    found = true;
                    break;
                }
            }
            if (!found) {
                req = req.withAddedHeader("Cookie", "session=123*");
            }
        }
        if (pathCheck.isSelected()) {
            String path = req.pathWithoutQuery();
            if (!path.endsWith("*")) {
                String newPath = path + "*";
                String query = (req.query() != null && !req.query().isEmpty()) ? "?" + req.query() : "";
                req = req.withPath(newPath + query);
            }
        }
        
        List<HttpParameter> paramsToAdd = new ArrayList<>();
        List<HttpParameter> paramsToRemove = new ArrayList<>();
        
        for (ParsedHttpParameter p : req.parameters()) {
            if ((queryCheck.isSelected() && p.type() == HttpParameterType.URL) ||
                (bodyCheck.isSelected() && p.type() == HttpParameterType.BODY)) {
                
                paramsToRemove.add(p);
                if (p.type() == HttpParameterType.URL) {
                    paramsToAdd.add(HttpParameter.urlParameter(p.name(), p.value() + "*"));
                } else {
                    paramsToAdd.add(HttpParameter.bodyParameter(p.name(), p.value() + "*"));
                }
            }
        }
        
        for (HttpParameter p : paramsToRemove) {
            req = req.withRemovedParameters(p);
        }
        for (HttpParameter p : paramsToAdd) {
            req = req.withAddedParameters(p);
        }
        
        if (headersCheck.isSelected()) {
            String[] commonHeaders = {"X-Forwarded-For", "X-Forwarded-Host", "Client-IP", "Referer", "True-Client-IP"};
            for (String ch : commonHeaders) {
                boolean found = false;
                for (HttpHeader h : req.headers()) {
                    if (h.name().equalsIgnoreCase(ch)) {
                        req = req.withUpdatedHeader(h.name(), h.value() + "*");
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    req = req.withAddedHeader(ch, "127.0.0.1*");
                }
            }
        }
        
        return req;
    }
    
    private String generateKey(HttpRequest req) {
        return req.method() + " " + req.path() + " " + (req.bodyToString() != null ? req.bodyToString().hashCode() : 0);
    }
    
    private static class ProxyRequestRecord {
        String key;
        HttpRequestResponse rr;
        
        public ProxyRequestRecord(String key, HttpRequestResponse rr) {
            this.key = key;
            this.rr = rr;
        }
    }
    
    private class RepoTableModel extends AbstractTableModel {
        private final String[] columns = {"Method", "URL", "Status"};
        
        @Override
        public int getRowCount() { return records.size(); }
        
        @Override
        public int getColumnCount() { return columns.length; }
        
        @Override
        public String getColumnName(int column) { return columns[column]; }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ProxyRequestRecord rec = records.get(rowIndex);
            switch (columnIndex) {
                case 0: return rec.rr.request().method();
                case 1: return rec.rr.request().url();
                case 2: return rec.rr.response() != null ? rec.rr.response().statusCode() : "Pending";
            }
            return null;
        }
    }
}
