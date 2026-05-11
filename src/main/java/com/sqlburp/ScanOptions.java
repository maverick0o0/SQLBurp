package com.sqlburp;

import burp.api.montoya.utilities.json.JsonObjectNode;
import burp.api.montoya.utilities.json.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.utilities.json.JsonObjectNode.jsonObjectNode;

public class ScanOptions {

    private static final Pattern CUSTOM_ARG_PATTERN =
        Pattern.compile("--[\\w-]+=\\S+|--[\\w-]+");

    public int     level       = 1;
    public int     risk        = 1;
    public int     threads     = 1;
    public String  technique   = "BEUSTQ";
    public String  dbms        = "(auto)";
    public String  tamper      = "";
    public boolean batch       = true;
    public boolean randomAgent = false;
    public boolean forms       = false;
    public boolean getDbs      = true;
    public boolean currentUser = true;
    public boolean banner      = true;
    public boolean isDba       = false;
    public boolean forceSSL    = false;
    public int     verbose     = 2;
    public String  customArgs  = "";

    /**
     * Pre-configured answers for sqlmap prompts, used when batch=false.
     * Keys are the sqlmap --answers token (e.g. "crack", "dict").
     * Values are "Y", "N", or "" (ask interactively / omit).
     */
    public Map<String, String> answers = new LinkedHashMap<>();

    /** Known sqlmap prompts in display order. */
    public static final String[][] ANSWER_PROMPTS = {
        { "crack",    "Crack found hashes" },
        { "dict",     "Dictionary-based hash attack" },
        { "csvFile",  "Store hashes to CSV file" },
        { "common",   "Use common password suffixes" },
        { "quit",     "Quit after finding first injection" },
        { "merge",    "Merge scan results" },
        { "flush",    "Flush session and re-test" },
        { "schema",   "Retrieve full schema" },
        { "adjust",   "Adjust level/risk for WAF detection" },
        { "skipOther","Skip testing other parameters" },
    };

    public ScanOptions() {}

    public ScanOptions copy() {
        ScanOptions c = new ScanOptions();
        c.level       = this.level;
        c.risk        = this.risk;
        c.threads     = this.threads;
        c.technique   = this.technique;
        c.dbms        = this.dbms;
        c.tamper      = this.tamper;
        c.batch       = this.batch;
        c.randomAgent = this.randomAgent;
        c.forms       = this.forms;
        c.getDbs      = this.getDbs;
        c.currentUser = this.currentUser;
        c.banner      = this.banner;
        c.isDba       = this.isDba;
        c.forceSSL    = this.forceSSL;
        c.verbose     = this.verbose;
        c.customArgs  = this.customArgs;
        c.answers     = new LinkedHashMap<>(this.answers);
        return c;
    }

    public JsonObjectNode toApiDict(String requestFile) {
        JsonObjectNode n = jsonObjectNode();
        n.putString("requestFile",    requestFile);
        n.putNumber("level",          (long) level);
        n.putNumber("risk",           (long) risk);
        n.putNumber("threads",        (long) threads);
        n.putString("technique",      technique.isEmpty() ? "BEUSTQ" : technique);
        n.putBoolean("batch",          batch);
        n.putBoolean("randomAgent",    randomAgent);
        n.putBoolean("forms",          forms);
        n.putBoolean("getDbs",         getDbs);
        n.putBoolean("getCurrentUser", currentUser);
        n.putBoolean("getBanner",      banner);
        n.putBoolean("isDba",          isDba);
        n.putBoolean("forceSSL",       forceSSL);
        n.putNumber("verbose",         (long) verbose);
        if (dbms != null && !dbms.equals("(auto)") && !dbms.isEmpty()) {
            n.putString("dbms", dbms);
        }
        if (tamper != null && !tamper.isEmpty()) {
            n.putString("tamper", tamper);
        }
        if (customArgs != null && !customArgs.trim().isEmpty()) {
            applyCustomArgs(n, customArgs.trim());
        }
        // Build answers string from map (e.g. "crack=Y,dict=N")
        if (!batch && answers != null && !answers.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : answers.entrySet()) {
                if (e.getValue() != null && !e.getValue().isEmpty()) {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(e.getKey()).append('=').append(e.getValue());
                }
            }
            if (sb.length() > 0) {
                n.putString("answers", sb.toString());
            }
        }
        return n;
    }

    /**
     * Parses a free-form sqlmap argument string (e.g. "--delay=10 --timeout=30 --proxy=http://...")
     * and injects each recognised flag as its proper JSON key into the payload node.
     * Supports both "--flag=value" and "--flag value" forms, and bare boolean switches.
     */
    private void applyCustomArgs(JsonObjectNode n, String args) {
        List<String> tokens = new ArrayList<>();
        Matcher m = CUSTOM_ARG_PATTERN.matcher(args);
        while (m.find()) tokens.add(m.group());

        for (int i = 0; i < tokens.size(); i++) {
            String tok = tokens.get(i);
            String key, val = null;
            if (tok.contains("=")) {
                key = tok.substring(2, tok.indexOf('=')).toLowerCase();
                val = tok.substring(tok.indexOf('=') + 1);
            } else {
                key = tok.substring(2).toLowerCase();
                if (i + 1 < tokens.size() && !tokens.get(i + 1).startsWith("--")) {
                    val = tokens.get(++i);
                }
            }
            putCustomArg(n, key, val);
        }
    }

    private void putCustomArg(JsonObjectNode n, String flag, String val) {
        switch (flag) {
            case "delay":    n.putNumber("delay",   parseDouble(val)); break;
            case "timeout":  n.putNumber("timeout", parseDouble(val)); break;
            case "retries":  n.putNumber("retries",  parseLong(val)); break;
            case "time-sec": n.putNumber("timeSec",  parseLong(val)); break;
            case "union-cols": n.putString("unionCols", val != null ? val : ""); break;
            case "proxy":    n.putString("proxy",    val != null ? val : ""); break;
            case "proxy-cred": n.putString("proxyCred", val != null ? val : ""); break;
            case "tor-type": n.putString("torType",  val != null ? val : ""); break;
            case "tor-port": n.putNumber("torPort",  parseLong(val)); break;
            case "user-agent": n.putString("agent",  val != null ? val : ""); break;
            case "referer":  n.putString("referer",  val != null ? val : ""); break;
            case "cookie":   n.putString("cookie",   val != null ? val : ""); break;
            case "headers":  n.putString("headers",  val != null ? val : ""); break;
            case "auth-type": n.putString("authType", val != null ? val : ""); break;
            case "auth-cred": n.putString("authCred", val != null ? val : ""); break;
            case "prefix":   n.putString("prefix",   val != null ? val : ""); break;
            case "suffix":   n.putString("suffix",   val != null ? val : ""); break;
            case "safe-url": n.putString("safeUrl",  val != null ? val : ""); break;
            case "safe-post": n.putString("safePost", val != null ? val : ""); break;
            case "test-filter": n.putString("testFilter", val != null ? val : ""); break;
            case "dbms-cred": n.putString("dbmsCred", val != null ? val : ""); break;
            case "second-url": n.putString("secondUrl", val != null ? val : ""); break;
            case "tor":              n.putBoolean("tor",            true); break;
            case "check-tor":        n.putBoolean("checkTor",       true); break;
            case "ignore-proxy":     n.putBoolean("ignoreProxy",    true); break;
            case "ignore-redirects": n.putBoolean("ignoreRedirects",true); break;
            case "ignore-timeouts":  n.putBoolean("ignoreTimeouts", true); break;
            case "skip-urlencode":   n.putBoolean("skipUrlEncode",  true); break;
            case "mobile":           n.putBoolean("mobile",         true); break;
            case "force-ssl":        n.putBoolean("forceSSL",       true); break;
            case "flush-session":    n.putBoolean("flushSession",   true); break;
            case "fresh-queries":    n.putBoolean("freshQueries",   true); break;
            case "hex":              n.putBoolean("hexConvert",     true); break;
            case "predict-output":   n.putBoolean("predictOutput",  true); break;
            case "text-only":        n.putBoolean("textOnly",       true); break;
            default: break;
        }
    }

    private static long parseLong(String s) {
        if (s == null) return 0;
        try { return Long.parseLong(s.trim()); } catch (NumberFormatException e) { return 0; }
    }

    private static double parseDouble(String s) {
        if (s == null) return 0.0;
        try { return Double.parseDouble(s.trim()); } catch (NumberFormatException e) { return 0.0; }
    }

    public JsonObjectNode toJson() {
        JsonObjectNode n = jsonObjectNode();
        n.putNumber("level",       (long) level);
        n.putNumber("risk",        (long) risk);
        n.putNumber("threads",     (long) threads);
        n.putString("technique",   technique);
        n.putString("dbms",        dbms);
        n.putString("tamper",      tamper);
        n.putBoolean("batch",       batch);
        n.putBoolean("randomAgent", randomAgent);
        n.putBoolean("forms",       forms);
        n.putBoolean("getDbs",      getDbs);
        n.putBoolean("currentUser", currentUser);
        n.putBoolean("banner",      banner);
        n.putBoolean("isDba",       isDba);
        n.putBoolean("forceSSL",    forceSSL);
        n.putNumber("verbose",      (long) verbose);
        n.putString("customArgs",   customArgs);
        // Persist answers map as a nested JSON object
        JsonObjectNode answersNode = jsonObjectNode();
        if (answers != null) {
            for (Map.Entry<String, String> e : answers.entrySet()) {
                answersNode.putString(e.getKey(), e.getValue() != null ? e.getValue() : "");
            }
        }
        n.put("answers", answersNode);
        return n;
    }

    public static ScanOptions fromJson(JsonObjectNode j) {
        ScanOptions o = new ScanOptions();
        if (j == null) return o;
        o.level       = safeInt(j, "level", o.level);
        o.risk        = safeInt(j, "risk", o.risk);
        o.threads     = safeInt(j, "threads", o.threads);
        o.technique   = safeStr(j, "technique", o.technique);
        o.dbms        = safeStr(j, "dbms", o.dbms);
        o.tamper      = safeStr(j, "tamper", o.tamper);
        o.batch       = safeBool(j, "batch", o.batch);
        o.randomAgent = safeBool(j, "randomAgent", o.randomAgent);
        o.forms       = safeBool(j, "forms", o.forms);
        o.getDbs      = safeBool(j, "getDbs", o.getDbs);
        o.currentUser = safeBool(j, "currentUser", o.currentUser);
        o.banner      = safeBool(j, "banner", o.banner);
        o.isDba       = safeBool(j, "isDba", o.isDba);
        o.forceSSL    = safeBool(j, "forceSSL", o.forceSSL);
        o.verbose     = safeInt(j, "verbose", o.verbose);
        o.customArgs  = safeStr(j, "customArgs", o.customArgs);
        // Restore answers map
        JsonNode answersNode = j.get("answers");
        if (answersNode != null && answersNode.isObject()) {
            JsonObjectNode answersObj = answersNode.asObject();
            for (String[] prompt : ANSWER_PROMPTS) {
                String key = prompt[0];
                JsonNode valNode = answersObj.get(key);
                if (valNode != null && valNode.isString()) {
                    o.answers.put(key, valNode.asString());
                }
            }
        }
        return o;
    }

    /** Safely read a string from a Montoya JsonObjectNode (avoids NPE on missing keys). */
    private static String safeStr(JsonObjectNode j, String key, String fallback) {
        JsonNode n = j.get(key);
        return (n != null && n.isString()) ? n.asString() : fallback;
    }

    /** Safely read a boolean from a Montoya JsonObjectNode. */
    private static boolean safeBool(JsonObjectNode j, String key, boolean fallback) {
        JsonNode n = j.get(key);
        return (n != null && n.isBoolean()) ? n.asBoolean() : fallback;
    }

    /** Safely read an int from a Montoya JsonObjectNode. */
    private static int safeInt(JsonObjectNode j, String key, int fallback) {
        JsonNode n = j.get(key);
        if (n == null || !n.isNumber()) return fallback;
        return ((Number) n.asNumber()).intValue();
    }

    public String[] summaryLines() {
        StringBuilder flags = new StringBuilder();
        if (batch)       flags.append("batch ");
        if (randomAgent) flags.append("random-agent ");
        if (forms)       flags.append("forms ");
        if (getDbs)      flags.append("enum-dbs ");
        if (currentUser) flags.append("current-user ");
        if (banner)      flags.append("banner ");
        if (isDba)       flags.append("is-dba ");
        if (forceSSL)    flags.append("force-ssl ");

        StringBuilder answersStr = new StringBuilder();
        if (!batch && answers != null) {
            for (Map.Entry<String, String> e : answers.entrySet()) {
                if (e.getValue() != null && !e.getValue().isEmpty()) {
                    if (answersStr.length() > 0) answersStr.append(',');
                    answersStr.append(e.getKey()).append('=').append(e.getValue());
                }
            }
        }

        return new String[]{
            "Level     : " + level,
            "Risk      : " + risk,
            "Threads   : " + threads,
            "Technique : " + technique,
            "DBMS      : " + dbms,
            "Tamper    : " + (tamper.isEmpty() ? "(none)" : tamper),
            "Verbose   : " + verbose,
            "Flags     : " + (flags.length() == 0 ? "(none)" : flags.toString().trim()),
            "Extra Args: " + (customArgs.trim().isEmpty() ? "(none)" : customArgs.trim()),
            "Answers   : " + (answersStr.length() == 0 ? "(none)" : answersStr.toString()),
        };
    }
}
