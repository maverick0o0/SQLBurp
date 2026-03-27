package com.sqlburp;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.utilities.json.JsonArrayNode;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.utilities.json.JsonArrayNode.jsonArrayNode;
import static burp.api.montoya.utilities.json.JsonObjectNode.jsonObjectNode;

public class PersistenceManager {

    private static final String KEY_TASKS    = "sqlburp_tasks";
    private static final String KEY_SCAN_PFX = "sqlburp_scan_";

    private final PersistedObject store;

    public PersistenceManager(PersistedObject store) {
        this.store = store;
    }

    // ------------------------------------------------------------------
    // Task list
    // ------------------------------------------------------------------

    public List<String> loadTaskIds() {
        String raw = store.getString(KEY_TASKS);
        if (raw == null || raw.isEmpty()) return new ArrayList<>();
        try {
            List<String> ids = new ArrayList<>();
            JsonNode node = JsonNode.jsonNode(raw);
            if (node != null && node.isArray()) {
                for (JsonNode item : node.asArray().asList()) {
                    ids.add(item.asString());
                }
            }
            return ids;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public void saveTaskIds(List<String> ids) {
        try {
            JsonArrayNode arr = jsonArrayNode();
            ids.forEach(arr::addString);
            store.setString(KEY_TASKS, arr.toJsonString());
        } catch (Exception ignored) {}
    }

    public void addTaskId(String taskId) {
        List<String> ids = loadTaskIds();
        if (!ids.contains(taskId)) {
            ids.add(taskId);
            saveTaskIds(ids);
        }
    }

    public void removeTaskId(String taskId) {
        List<String> ids = loadTaskIds();
        ids.remove(taskId);
        saveTaskIds(ids);
    }

    // ------------------------------------------------------------------
    // Scan records
    // ------------------------------------------------------------------

    public void saveScanRecord(ScanRecord rec) {
        try {
            JsonObjectNode n = jsonObjectNode();
            n.putString("taskId",   rec.taskId);
            n.putString("target",   rec.target);
            n.putString("method",   rec.method);
            n.putString("status",   rec.status);
            n.putNumber("findings", (long) rec.findings);
            n.putString("started",  rec.started);

            JsonArrayNode log = jsonArrayNode();
            rec.logLines.forEach(log::addString);
            n.put("logLines", log);

            JsonArrayNode results = jsonArrayNode();
            for (Object r : rec.results) {
                if (r instanceof JsonNode) {
                    results.add((JsonNode) r);
                } else {
                    results.addString(r.toString());
                }
            }
            n.put("results", results);
            n.put("options", rec.options.toJson());

            store.setString(KEY_SCAN_PFX + rec.taskId, n.toJsonString());
        } catch (Exception ignored) {}
    }

    public ScanRecord loadScanRecord(String taskId) {
        String raw = store.getString(KEY_SCAN_PFX + taskId);
        if (raw == null || raw.isEmpty()) return null;
        try {
            JsonNode node = JsonNode.jsonNode(raw);
            if (node == null || !node.isObject()) return null;
            JsonObjectNode j = node.asObject();

            ScanRecord r = new ScanRecord(
                taskId,
                j.getString("target") != null ? j.getString("target") : "(unknown)",
                j.getString("method") != null ? j.getString("method") : "GET"
            );
            r.status   = j.getString("status") != null ? j.getString("status") : ScanRecord.STATUS_DONE;
            Long findings = j.getLong("findings");
            r.findings = findings != null ? findings.intValue() : 0;

            JsonNode logNode = j.get("logLines");
            if (logNode != null && logNode.isArray()) {
                for (JsonNode line : logNode.asArray().asList()) r.logLines.add(line.asString());
            }

            JsonNode resultsNode = j.get("results");
            if (resultsNode != null && resultsNode.isArray()) {
                for (JsonNode res : resultsNode.asArray().asList()) r.results.add(res);
            }

            JsonNode optsNode = j.get("options");
            r.options = optsNode != null && optsNode.isObject()
                ? ScanOptions.fromJson(optsNode.asObject())
                : new ScanOptions();

            return r;
        } catch (Exception e) {
            return null;
        }
    }

    public void deleteScanRecord(String taskId) {
        store.setString(KEY_SCAN_PFX + taskId, null);
        removeTaskId(taskId);
    }
}
