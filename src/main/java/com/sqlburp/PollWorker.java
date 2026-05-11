package com.sqlburp;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.json.JsonArrayNode;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

public class PollWorker implements Runnable {

    private volatile boolean running = true;

    private final ScanRecord          record;
    private final ApiClient           api;
    private final String              baseUrl;
    private final int                 pollIntervalMs;
    private final PersistenceManager  persist;
    private final Logging             logging;
    private final Consumer<ScanRecord> onUpdate;

    public PollWorker(ScanRecord record, ApiClient api, String baseUrl,
                      int pollIntervalMs, PersistenceManager persist,
                      Logging logging, Consumer<ScanRecord> onUpdate) {
        this.record         = record;
        this.api            = api;
        this.baseUrl        = baseUrl;
        this.pollIntervalMs = pollIntervalMs;
        this.persist        = persist;
        this.logging        = logging;
        this.onUpdate       = onUpdate;
    }

    public void stop() { running = false; }

    private String ts() {
        return LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    @Override
    public void run() {
        record.appendLog("[" + ts() + "] Polling started.");
        persist.saveScanRecord(record);
        onUpdate.accept(record);

        int seenLogCount = 0;
        try {
            while (running) {
                boolean dirty = false;

                String apiStatus;
                try {
                    apiStatus = api.scanStatus(baseUrl, record.taskId);
                } catch (Exception e) {
                    record.appendLog("[" + ts() + "] Poll error: " + e.getMessage());
                    record.status = ScanRecord.STATUS_ERROR;
                    persist.saveScanRecord(record);
                    onUpdate.accept(record);
                    sleep(5_000);
                    continue;
                }

                // Fetch new log lines
                try {
                    JsonNode linesNode = api.scanLog(baseUrl, record.taskId);
                    if (linesNode != null && linesNode.isArray()) {
                        JsonArrayNode lines = linesNode.asArray();
                        int total = lines.asList().size();
                        for (int i = seenLogCount; i < total; i++) {
                            JsonNode entry = lines.asList().get(i);
                            if (entry.isObject()) {
                                JsonObjectNode obj = entry.asObject();
                                String time  = obj.getString("time");
                                String level = obj.getString("level");
                                String msg   = obj.getString("message");
                                if ("DEBUG".equalsIgnoreCase(level)) continue;
                                record.appendLog("[" + (time != null ? time : "") + "]"
                                    + "[" + (level != null ? level : "INFO") + "] "
                                    + (msg != null ? msg : ""));
                            }
                        }
                        if (total > seenLogCount) {
                            seenLogCount = total;
                            dirty = true;
                        }
                    }
                } catch (Exception e) {
                    logging.logToError("SQLBurp: error fetching log for "
                        + record.taskId + ": " + e.getMessage());
                }

                if ("running".equals(apiStatus)) {
                    if (!ScanRecord.STATUS_RUNNING.equals(record.status)) {
                        record.status = ScanRecord.STATUS_RUNNING;
                        dirty = true;
                    }

                } else if ("terminated".equals(apiStatus) || "not running".equals(apiStatus)) {
                    try {
                        JsonNode dataNode = api.scanData(baseUrl, record.taskId);
                        if (dataNode != null && dataNode.isArray()
                                && !dataNode.asArray().asList().isEmpty()) {
                            for (JsonNode item : dataNode.asArray().asList()) {
                                record.results.add(item);
                            }
                            record.findings = record.results.size();
                            record.status   = ScanRecord.STATUS_VULN;
                            record.appendLog("\n=== INJECTION POINTS CONFIRMED ===");
                            for (JsonNode item : record.results) {
                                record.appendLog(item.toJsonString());
                            }
                        } else {
                            record.status = ScanRecord.STATUS_DONE;
                            record.appendLog("[" + ts() + "] Scan complete. No injections confirmed.");
                        }
                    } catch (Exception e) {
                        record.appendLog("[" + ts() + "] Data fetch error: " + e.getMessage());
                        record.status = ScanRecord.STATUS_ERROR;
                    }
                    persist.saveScanRecord(record);
                    onUpdate.accept(record);
                    break;
                }

                // Batch: persist and update UI once per cycle only if something changed
                if (dirty) {
                    persist.saveScanRecord(record);
                    onUpdate.accept(record);
                }

                sleep(pollIntervalMs);
            }
        } catch (Exception e) {
            record.appendLog("[Fatal] " + e.getMessage());
            record.status = ScanRecord.STATUS_ERROR;
            persist.saveScanRecord(record);
            onUpdate.accept(record);
        }
        record.appendLog("[" + ts() + "] Polling stopped.");
        persist.saveScanRecord(record);
    }

    private void sleep(int ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) { running = false; }
    }
}
