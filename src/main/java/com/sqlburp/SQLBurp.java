package com.sqlburp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.utilities.json.JsonObjectNode;

import static burp.api.montoya.utilities.json.JsonObjectNode.jsonObjectNode;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

public class SQLBurp implements BurpExtension {

    private MontoyaApi          api;
    private Logging             logging;
    private PersistenceManager  persist;
    private ApiClient           apiClient;

    private ConfigPanel         configPanel;
    private ScanTableModel      tableModel;
    private JTable              scanTable;
    private JTextArea           previewArea;
    private JPanel              mainPanel;

    private final Map<String, Thread>     pollThreads = new ConcurrentHashMap<>();
    private final Map<String, ScanRecord> recordsMap  = new ConcurrentHashMap<>();
    private volatile String               selectedTid = null;
    private JScrollPane                   previewScroll;
    private RequestRepoPanel              repoPanel;

    // ------------------------------------------------------------------
    // BurpExtension entry point
    // ------------------------------------------------------------------

    @Override
    public void initialize(MontoyaApi api) {
        this.api       = api;
        this.logging   = api.logging();
        this.apiClient = new ApiClient(api.http());

        api.extension().setName("SQLBurp");

        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                stopAllTasks();
            }
        });

        this.persist = new PersistenceManager(
            api.persistence().extensionData(),
            logging
        );

        SwingUtilities.invokeLater(this::buildUi);
    }

    // ------------------------------------------------------------------
    // UI construction
    // ------------------------------------------------------------------

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout());

        // --- Config panel ---
        configPanel = new ConfigPanel();
        configPanel.pingBtn.addActionListener(e -> pingServer());
        JScrollPane configScroll = new JScrollPane(configPanel);

        // --- Scan table ---
        tableModel = new ScanTableModel();
        scanTable  = new JTable(tableModel);
        scanTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scanTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        scanTable.getColumnModel().getColumn(4).setCellRenderer(new StatusCellRenderer());

        TableRowSorter<ScanTableModel> sorter = new TableRowSorter<>(tableModel);
        scanTable.setRowSorter(sorter);

        scanTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int vrow = scanTable.getSelectedRow();
            if (vrow < 0) return;
            int mrow = scanTable.convertRowIndexToModel(vrow);
            ScanRecord rec = tableModel.getRecord(mrow);
            if (rec != null) {
                selectedTid = rec.taskId;
                refreshPreview(rec);
            }
        });

        scanTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }
            @Override public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }
        });

        JScrollPane tableScroll = new JScrollPane(scanTable);

        // --- Preview area ---
        previewArea = new JTextArea("Select a scan row above to view its log.");
        previewArea.setEditable(false);
        previewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewArea.setLineWrap(true);
        previewArea.setWrapStyleWord(true);
        previewScroll = new JScrollPane(previewArea);

        // --- Toolbar for Scans tab ---
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        JButton stopAllBtn        = new JButton("Stop All");
        JButton removeFinishedBtn = new JButton("Remove Finished");
        JButton clearAllBtn       = new JButton("Clear All");
        stopAllBtn.addActionListener(e -> stopAllTasks());
        removeFinishedBtn.addActionListener(e -> removeFinished());
        clearAllBtn.addActionListener(e -> clearAll());
        toolbar.add(stopAllBtn);
        toolbar.add(removeFinishedBtn);
        toolbar.addSeparator();
        toolbar.add(clearAllBtn);

        // Table + log split inside Scans tab
        JSplitPane scansSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, previewScroll);
        scansSplit.setResizeWeight(0.5);

        JPanel scansTab = new JPanel(new BorderLayout());
        scansTab.add(toolbar, BorderLayout.NORTH);
        scansTab.add(scansSplit, BorderLayout.CENTER);

        // --- Request Repo Tab ---
        repoPanel = new RequestRepoPanel(api, this);

        // --- Tabbed pane ---
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request Repository", repoPanel);
        tabs.addTab("Options", configScroll);
        tabs.addTab("Scans",   scansTab);

        mainPanel.add(tabs, BorderLayout.CENTER);

        // Apply Burp theme
        api.userInterface().applyThemeToComponent(mainPanel);

        // Register tab
        api.userInterface().registerSuiteTab("SQLBurp", mainPanel);

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(new SqlBurpMenuProvider());

        // Register Proxy Handlers
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {
                return ProxyRequestReceivedAction.continueWith(req);
            }
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
                return ProxyRequestToBeSentAction.continueWith(req);
            }
        });
        
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse res) {
                if (api.scope().isInScope(res.request().url())) {
                    String path = res.request().pathWithoutQuery().toLowerCase();
                    if (!path.endsWith(".js") && !path.endsWith(".png") && !path.endsWith(".svg") && 
                        !path.endsWith(".css") && !path.endsWith(".ico") && !path.endsWith(".jpg") && 
                        !path.endsWith(".jpeg") && !path.endsWith(".gif") && !path.endsWith(".woff") && 
                        !path.endsWith(".woff2") && !path.endsWith(".ttf")) {
                        burp.api.montoya.http.message.HttpRequestResponse rr = 
                            burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(res.request(), res);
                        repoPanel.handleProxyRequest(rr);
                    }
                }
                return ProxyResponseReceivedAction.continueWith(res);
            }
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse res) {
                return ProxyResponseToBeSentAction.continueWith(res);
            }
        });

        // Restore persisted scans
        new Thread(this::restorePersistedScans, "sqlburp-restore").start();
    }

    // ------------------------------------------------------------------
    // Context menu provider
    // ------------------------------------------------------------------

    private class SqlBurpMenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<MessageEditorHttpRequestResponse> messages =
                event.messageEditorRequestResponse()
                     .map(List::of)
                     .orElse(Collections.emptyList());

            if (messages.isEmpty()) {
                // Also handle selection from other tools
                List<burp.api.montoya.http.message.HttpRequestResponse> selected =
                    event.selectedRequestResponses();
                if (selected.isEmpty()) return Collections.emptyList();

                JMenuItem item = new JMenuItem("Send to SQLMap API");
                item.addActionListener(e -> {
                    Set<String> seen = new HashSet<>();
                    for (var rr : selected) {
                        if (rr.request() == null) continue;
                        String key = dedupKey(rr.httpService().host(),
                                              rr.httpService().port(),
                                              rr.request().toByteArray());
                        if (seen.add(key)) {
                            String proto = rr.httpService().secure() ? "https" : "http";
                            String target = proto + "://" + rr.httpService().host()
                                          + ":" + rr.httpService().port();
                            String method = rr.request().method();
                            String raw    = rr.request().toString();
                            new Thread(() -> submitScan(target, method, raw,
                                rr.httpService().secure()), "sqlburp-scan").start();
                        }
                    }
                });
                return List.of(item);
            }

            JMenuItem item = new JMenuItem("Send to SQLMap API");
            item.addActionListener(e -> {
                Set<String> seen = new HashSet<>();
                for (var msg : messages) {
                    if (msg.requestResponse().request() == null) continue;
                    var rr     = msg.requestResponse();
                    String key = dedupKey(rr.httpService().host(),
                                          rr.httpService().port(),
                                          rr.request().toByteArray());
                    if (seen.add(key)) {
                        String raw    = rr.request().toString();
                        String proto  = rr.httpService().secure() ? "https" : "http";
                        String target = proto + "://" + rr.httpService().host()
                                      + ":" + rr.httpService().port();
                        String method = rr.request().method();
                        new Thread(() -> submitScan(target, method, raw,
                            rr.httpService().secure()), "sqlburp-scan").start();
                    }
                }
            });
            return List.of(item);
        }
    }

    private String dedupKey(String host, int port, ByteArray rawBytes) {
        return host + ":" + port + ":" + Arrays.hashCode(rawBytes.getBytes());
    }

    // ------------------------------------------------------------------
    // Scan submission
    // ------------------------------------------------------------------

    public void submitScanAsync(HttpRequest req, HttpService svc) {
        String proto = svc.secure() ? "https" : "http";
        String target = proto + "://" + svc.host() + ":" + svc.port();
        String method = req.method();
        String raw = req.toString();
        new Thread(() -> submitScanInternal(target, method, raw, svc.secure()), "sqlburp-scan").start();
    }

    public void submitScanBlocking(HttpRequest req, HttpService svc) {
        String proto = svc.secure() ? "https" : "http";
        String target = proto + "://" + svc.host() + ":" + svc.port();
        String method = req.method();
        String raw = req.toString();
        
        String taskId = submitScanInternal(target, method, raw, svc.secure());
        if (taskId == null) return;
        
        while (true) {
            ScanRecord r = recordsMap.get(taskId);
            if (r == null) break;
            if (ScanRecord.STATUS_DONE.equals(r.status) || ScanRecord.STATUS_ERROR.equals(r.status) || ScanRecord.STATUS_STOPPED.equals(r.status) || ScanRecord.STATUS_VULN.equals(r.status)) {
                break;
            }
            try { Thread.sleep(2000); } catch (Exception ignored) {}
        }
    }

    private void submitScan(String target, String method, String rawRequest, boolean ssl) {
        submitScanInternal(target, method, rawRequest, ssl);
    }

    private String submitScanInternal(String target, String method, String rawRequest, boolean ssl) {
        String taskId = null;
        ScanRecord rec = null;
        try {
            apiClient.setAuth(configPanel.getApiUser(), configPanel.getApiPass());
            String baseUrl = configPanel.getApiUrl();
            taskId = apiClient.newTask(baseUrl);

            rec = new ScanRecord(taskId, target, method);
            ScanOptions opts = configPanel.readOptions(ssl);
            rec.options = opts;

            final ScanRecord fRec = rec;
            recordsMap.put(taskId, rec);
            SwingUtilities.invokeLater(() -> tableModel.addRow(fRec));

            // Write request to a temp file for sqlmap
            File tmp = File.createTempFile("sqlburp_", ".txt");
            tmp.deleteOnExit();
            String rawRequestStr = rawRequest.replace("%2A", "*").replace("%2a", "*");
            // sqlmap's -r parser chokes on HTTP/2 string format, so we downgrade it to HTTP/1.1 for the text file
            rawRequestStr = rawRequestStr.replaceFirst("(?i)HTTP/2(?:\\.0)?\\s*(\r?\n)", "HTTP/1.1$1");
            
            // Workaround for a bug in sqlmap's PROBLEMATIC_CUSTOM_INJECTION_PATTERNS 
            // where (;q=[^;']+) matches newlines and consumes all subsequent headers, hiding their '*' markers
            rawRequestStr = rawRequestStr.replace(";q=", "; q=");

            if (!rawRequestStr.endsWith("\n\n") && !rawRequestStr.endsWith("\r\n\r\n")) {
                if (rawRequestStr.endsWith("\r\n")) rawRequestStr += "\r\n";
                else if (rawRequestStr.endsWith("\n")) rawRequestStr += "\n";
                else rawRequestStr += "\r\n\r\n";
            }
            try (FileWriter fw = new FileWriter(tmp)) { fw.write(rawRequestStr); }
            rec.tmpFilePath = tmp.getAbsolutePath();

            JsonObjectNode optDict = opts.toApiDict(rec.tmpFilePath);
            apiClient.post(baseUrl, "/option/" + taskId + "/set", optDict);

            JsonObjectNode empty = jsonObjectNode();
            var startResp = apiClient.post(baseUrl, "/scan/" + taskId + "/start", empty);
            rec.appendLog("[" + ts() + "] Scan started (engineid="
                + startResp.asObject().getString("engineid") + ")");
            rec.status = ScanRecord.STATUS_RUNNING;

            persist.addTaskId(taskId);
            persist.saveScanRecord(rec);

            SwingUtilities.invokeLater(() -> {
                tableModel.refreshRow(fRec);
                maybeRefreshPreview(fRec);
            });

            startPollThread(rec, baseUrl);

        } catch (Exception ex) {
            String msg = "[Error] " + ex.getMessage();
            logging.logToError(msg);
            if (rec != null) {
                rec.status = ScanRecord.STATUS_ERROR;
                rec.appendLog(msg);
                final ScanRecord fRec = rec;
                SwingUtilities.invokeLater(() -> {
                    tableModel.refreshRow(fRec);
                    maybeRefreshPreview(fRec);
                });
                persist.saveScanRecord(rec);
            }
        }
        return taskId;
    }

    // ------------------------------------------------------------------
    // Poll thread management
    // ------------------------------------------------------------------

    private void startPollThread(ScanRecord rec, String baseUrl) {
        PollWorker worker = new PollWorker(
            rec, apiClient, baseUrl,
            configPanel.getPollMs(),
            persist, logging,
            updated -> SwingUtilities.invokeLater(() -> {
                tableModel.refreshRow(updated);
                maybeRefreshPreview(updated);
            })
        );
        Thread t = new Thread(worker, "sqlburp-poll-" + rec.taskId);
        t.setDaemon(true);
        pollThreads.put(rec.taskId, t);
        t.start();
    }

    private void stopTask(String taskId) {
        Thread pt = pollThreads.remove(taskId);
        if (pt != null) pt.interrupt();
        ScanRecord rec = recordsMap.get(taskId);
        if (rec != null && ScanRecord.STATUS_RUNNING.equals(rec.status)) {
            rec.status = ScanRecord.STATUS_STOPPED;
            apiClient.stopTask(configPanel.getApiUrl(), taskId);
            persist.saveScanRecord(rec);
            SwingUtilities.invokeLater(() -> {
                tableModel.refreshRow(rec);
                maybeRefreshPreview(rec);
            });
        }
    }

    private void stopAllTasks() {
        new ArrayList<>(pollThreads.keySet()).forEach(this::stopTask);
    }

    // ------------------------------------------------------------------
    // Row removal
    // ------------------------------------------------------------------

    private void deleteSelectedRow() {
        int vrow = scanTable.getSelectedRow();
        if (vrow < 0) return;
        int mrow = scanTable.convertRowIndexToModel(vrow);
        ScanRecord rec = tableModel.getRecord(mrow);
        if (rec == null) return;
        stopTask(rec.taskId);
        apiClient.deleteTask(configPanel.getApiUrl(), rec.taskId);
        persist.deleteScanRecord(rec.taskId);
        recordsMap.remove(rec.taskId);
        if (rec.taskId.equals(selectedTid)) {
            selectedTid = null;
            previewArea.setText("Select a scan row above to view its log.");
        }
        tableModel.removeRow(mrow);
    }

    private void removeFinished() {
        Set<String> terminal = Set.of(
            ScanRecord.STATUS_DONE, ScanRecord.STATUS_STOPPED, ScanRecord.STATUS_ERROR);
        // Single reverse pass: remove from table and clean up in one go
        for (int i = tableModel.getRowCount() - 1; i >= 0; i--) {
            ScanRecord r = tableModel.getRecord(i);
            if (r != null && terminal.contains(r.status)) {
                persist.deleteScanRecord(r.taskId);
                recordsMap.remove(r.taskId);
                pollThreads.remove(r.taskId);
                if (r.taskId.equals(selectedTid)) {
                    selectedTid = null;
                    previewArea.setText("Select a scan row above to view its log.");
                }
                tableModel.removeRow(i);
            }
        }
    }

    private void clearAll() {
        stopAllTasks();
        for (int i = tableModel.getRowCount() - 1; i >= 0; i--) {
            ScanRecord r = tableModel.getRecord(i);
            if (r != null) {
                apiClient.deleteTask(configPanel.getApiUrl(), r.taskId);
                persist.deleteScanRecord(r.taskId);
                recordsMap.remove(r.taskId);
                if (r.taskId.equals(selectedTid)) {
                    selectedTid = null;
                    previewArea.setText("Select a scan row above to view its log.");
                }
                tableModel.removeRow(i);
            }
        }
    }

    // ------------------------------------------------------------------
    // Context menu for table rows
    // ------------------------------------------------------------------

    private void showContextMenu(MouseEvent e) {
        int vrow = scanTable.rowAtPoint(e.getPoint());
        if (vrow < 0) return;
        scanTable.setRowSelectionInterval(vrow, vrow);
        int mrow = scanTable.convertRowIndexToModel(vrow);
        ScanRecord rec = tableModel.getRecord(mrow);
        if (rec == null) return;

        JPopupMenu menu = new JPopupMenu();
        JMenuItem stopItem   = new JMenuItem("Stop Task");
        JMenuItem deleteItem = new JMenuItem("Delete Task");
        stopItem.addActionListener(ev -> stopTask(rec.taskId));
        deleteItem.addActionListener(ev -> deleteSelectedRow());
        menu.add(stopItem);
        menu.add(deleteItem);
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    // ------------------------------------------------------------------
    // Preview
    // ------------------------------------------------------------------

    private void maybeRefreshPreview(ScanRecord rec) {
        if (rec.taskId.equals(selectedTid)) refreshPreview(rec, false);
    }

    private void refreshPreview(ScanRecord rec) {
        refreshPreview(rec, true);
    }

    private void refreshPreview(ScanRecord rec, boolean scrollToTop) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(rec.target).append(" [").append(rec.method).append("] ===\n");
        sb.append("Task ID : ").append(rec.taskId).append("\n");
        sb.append("Status  : ").append(rec.status).append("\n");
        sb.append("Started : ").append(rec.started).append("\n\n");
        sb.append("--- Options ---\n");
        for (String line : rec.options.summaryLines()) sb.append(line).append("\n");
        
        if (rec.tmpFilePath != null) {
            sb.append("\n--- Equivalent Command ---\n");
            sb.append(rec.options.toCommandString(rec.tmpFilePath)).append("\n");
        }
        
        sb.append("\n--- Log ---\n");
        synchronized (rec.logLines) {
            for (String line : rec.logLines) sb.append(line).append("\n");
        }

        if (scrollToTop) {
            previewArea.setText(sb.toString());
            previewArea.setCaretPosition(0);
        } else {
            java.awt.Point viewPos = previewScroll.getViewport().getViewPosition();
            previewArea.setText(sb.toString());
            SwingUtilities.invokeLater(() -> {
                java.awt.Dimension viewSize = previewScroll.getViewport().getViewSize();
                java.awt.Dimension extentSize = previewScroll.getViewport().getExtentSize();
                int maxY = Math.max(0, viewSize.height - extentSize.height);
                viewPos.y = Math.min(viewPos.y, maxY);
                previewScroll.getViewport().setViewPosition(viewPos);
            });
        }
    }

    // ------------------------------------------------------------------
    // Ping
    // ------------------------------------------------------------------

    private void pingServer() {
        String base = configPanel.getApiUrl();
        new Thread(() -> {
            try {
                apiClient.setAuth(configPanel.getApiUser(), configPanel.getApiPass());
                String tid = apiClient.newTask(base);
                apiClient.deleteTask(base, tid);
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "sqlmapapi server is reachable.\n" + base,
                        "Ping OK", JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Could not reach sqlmapapi server:\n" + base
                            + "\n\nError: " + ex.getMessage(),
                        "Ping Failed", JOptionPane.ERROR_MESSAGE));
            }
        }, "sqlburp-ping").start();
    }

    // ------------------------------------------------------------------
    // Restore persisted scans on load
    // ------------------------------------------------------------------

    private void restorePersistedScans() {
        List<String> stored = persist.loadTaskIds();
        if (stored.isEmpty()) {
            logging.logToOutput("SQLBurp: no stored scans found on restore.");
            return;
        }
        logging.logToOutput("SQLBurp: restoring " + stored.size() + " stored scan(s).");
        String base = configPanel.getApiUrl();
        for (String taskId : stored) {
            try {
                ScanRecord rec = persist.loadScanRecord(taskId);
                if (rec != null) {
                    recordsMap.put(taskId, rec);
                    SwingUtilities.invokeLater(() -> tableModel.addRow(rec));
                    // If was running, try to reconnect poll
                    if (ScanRecord.STATUS_RUNNING.equals(rec.status)) {
                        try {
                            String apiStatus = apiClient.scanStatus(base, taskId);
                            if ("running".equals(apiStatus)) {
                                startPollThread(rec, base);
                            } else {
                                rec.status = ScanRecord.STATUS_STOPPED;
                                persist.saveScanRecord(rec);
                                SwingUtilities.invokeLater(() -> tableModel.refreshRow(rec));
                            }
                        } catch (Exception ignored) {
                            rec.status = ScanRecord.STATUS_STOPPED;
                            persist.saveScanRecord(rec);
                            SwingUtilities.invokeLater(() -> tableModel.refreshRow(rec));
                        }
                    }
                }
            } catch (Exception ex) {
                logging.logToError("SQLBurp: error restoring task " + taskId + ": " + ex.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    private String ts() {
        return LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }
}
