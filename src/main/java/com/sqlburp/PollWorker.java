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

    private void log(String msg) {
        record.appendLog(msg);
        persist.saveScanRecord(record);
        onUpdate.accept(record);
    }

    @Override
    public void run() {
        log("[" + ts() + "] Polling started.");
        int seenLogCount = 0;
        try {
            while (running) {
                String apiStatus;
                try {
                    apiStatus = api.scanStatus(baseUrl, record.taskId);
                } catch (Exception e) {
                    log("[" + ts() + "] Poll error: " + e.getMessage());
                    record.status = ScanRecord.STATUS_ERROR;
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
                            persist.saveScanRecord(record);
                            onUpdate.accept(record);
                        }
                    }
                } catch (Exception ignored) {}

                if ("running".equals(apiStatus)) {
                    record.status = ScanRecord.STATUS_RUNNING;
                    onUpdate.accept(record);

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
                            log("\n=== INJECTION POINTS CONFIRMED ===");
                            for (Object item : record.results) {
                                log(((JsonNode) item).toJsonString());
                            }
                        } else {
                            record.status = ScanRecord.STATUS_DONE;
                            log("[" + ts() + "] Scan complete. No injections confirmed.");
                        }
                    } catch (Exception e) {
                        log("[" + ts() + "] Data fetch error: " + e.getMessage());
                        record.status = ScanRecord.STATUS_ERROR;
                    }
                    persist.saveScanRecord(record);
                    onUpdate.accept(record);
                    break;
                }

                sleep(pollIntervalMs);
            }
        } catch (Exception e) {
            log("[Fatal] " + e.getMessage());
            record.status = ScanRecord.STATUS_ERROR;
            onUpdate.accept(record);
        }
        log("[" + ts() + "] Polling stopped.");
    }

    private void sleep(int ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) { running = false; }
    }
}