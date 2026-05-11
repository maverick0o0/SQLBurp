package com.sqlburp;

import burp.api.montoya.utilities.json.JsonNode;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ScanRecord {

    public static final String STATUS_QUEUED  = "Queued";
    public static final String STATUS_RUNNING = "Running";
    public static final String STATUS_DONE    = "Finished";
    public static final String STATUS_VULN    = "Vulnerable";
    public static final String STATUS_ERROR   = "Error";
    public static final String STATUS_STOPPED = "Stopped";

    public final String     taskId;
    public final String     target;
    public final String     method;
    public volatile String  status;
    public volatile int     findings;
    public final String     started;
    public final List<String>   logLines;
    public final List<JsonNode> results;
    public       ScanOptions    options;

    public ScanRecord(String taskId, String target, String method) {
        this.taskId   = taskId;
        this.target   = target;
        this.method   = method;
        this.status   = STATUS_QUEUED;
        this.findings = 0;
        this.started  = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        this.logLines = Collections.synchronizedList(new ArrayList<>());
        this.results  = new CopyOnWriteArrayList<>();
        this.options  = new ScanOptions();
    }

    public void appendLog(String line) {
        logLines.add(line);
    }
}
