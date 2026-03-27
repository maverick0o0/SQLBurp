package com.sqlburp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class ConfigPanel extends JPanel {

    final JTextField  apiUrlField;
    final JSpinner    levelSpin;
    final JSpinner    riskSpin;
    final JSpinner    threadsSpin;
    final JTextField  techniqueField;
    final JComboBox<String> dbmsCombo;
    final JTextField  tamperField;
    final JTextField  customArgsField;
    final JCheckBox   batchCheck;
    final JCheckBox   randomAgentCheck;
    final JCheckBox   formsCheck;
    final JCheckBox   dbsCheck;
    final JCheckBox   userCheck;
    final JCheckBox   bannerCheck;
    final JCheckBox   isdbaCheck;
    final JSpinner    pollSpin;
    final JButton     pingBtn;

    /** One combo per prompt: "Yes", "No", "Default" (omitted from answers string). */
    private final Map<String, JComboBox<String>> answerCombos = new LinkedHashMap<>();
    private JPanel answersPanel;

    private static final String[] YNA = { "Default", "Yes", "No" };

    public ConfigPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // --- API URL ---
        JPanel urlPanel = titledPanel("API");
        apiUrlField = new JTextField("http://127.0.0.1:8775", 20);
        urlPanel.add(label("URL")); urlPanel.add(apiUrlField);
        pingBtn = new JButton("Ping");
        urlPanel.add(pingBtn);
        add(urlPanel);

        // --- Scan options ---
        JPanel optPanel = titledPanel("Options");
        levelSpin     = new JSpinner(new SpinnerNumberModel(1, 1, 5, 1));
        riskSpin      = new JSpinner(new SpinnerNumberModel(1, 1, 3, 1));
        threadsSpin   = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
        techniqueField = new JTextField("BEUSTQ", 8);
        dbmsCombo     = new JComboBox<>(new String[]{
            "(auto)", "MySQL", "PostgreSQL", "Microsoft SQL Server",
            "Oracle", "SQLite", "Microsoft Access", "Firebird",
            "Sybase", "SAP MaxDB", "HSQLDB", "Informix"
        });
        tamperField = new JTextField("", 14);
        pollSpin    = new JSpinner(new SpinnerNumberModel(3, 1, 30, 1));

        optPanel.add(label("Level"));    optPanel.add(levelSpin);
        optPanel.add(label("Risk"));     optPanel.add(riskSpin);
        optPanel.add(label("Threads"));  optPanel.add(threadsSpin);
        optPanel.add(label("Technique"));optPanel.add(techniqueField);
        optPanel.add(label("DBMS"));     optPanel.add(dbmsCombo);
        optPanel.add(label("Tamper"));   optPanel.add(tamperField);
        optPanel.add(label("Poll (s)")); optPanel.add(pollSpin);
        add(optPanel);

        // --- Extra Args ---
        JPanel extraPanel = titledPanel("Extra sqlmap Arguments");
        customArgsField = new JTextField("", 40);
        customArgsField.setToolTipText("Additional sqlmap flags, e.g. --delay=2 --timeout=30 --proxy=http://127.0.0.1:8080");
        extraPanel.add(customArgsField);
        add(extraPanel);

        // --- Flags ---
        JPanel flagPanel = titledPanel("Flags");
        batchCheck       = new JCheckBox("Batch",        true);
        randomAgentCheck = new JCheckBox("Random Agent", false);
        formsCheck       = new JCheckBox("Forms",        false);
        dbsCheck         = new JCheckBox("Enum DBs",     true);
        userCheck        = new JCheckBox("Current User", true);
        bannerCheck      = new JCheckBox("Banner",       true);
        isdbaCheck       = new JCheckBox("Is DBA",       false);
        flagPanel.add(batchCheck);
        flagPanel.add(randomAgentCheck);
        flagPanel.add(formsCheck);
        flagPanel.add(dbsCheck);
        flagPanel.add(userCheck);
        flagPanel.add(bannerCheck);
        flagPanel.add(isdbaCheck);
        add(flagPanel);

        // --- Prompt Answers (hidden when Batch is on) ---
        answersPanel = buildAnswersPanel();
        answersPanel.setVisible(!batchCheck.isSelected());
        add(answersPanel);

        batchCheck.addActionListener(e -> answersPanel.setVisible(!batchCheck.isSelected()));

        add(Box.createVerticalGlue());
    }

    private JPanel buildAnswersPanel() {
        JPanel outer = titledPanel("Prompt Answers (used when Batch is off)");
        outer.setLayout(new BorderLayout());
        outer.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Prompt Answers (used when Batch is off)",
            TitledBorder.LEFT, TitledBorder.TOP));
        outer.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(2, 4, 2, 4);
        gc.anchor = GridBagConstraints.WEST;

        int row = 0;
        for (String[] prompt : ScanOptions.ANSWER_PROMPTS) {
            String key   = prompt[0];
            String label = prompt[1];

            JComboBox<String> combo = new JComboBox<>(YNA);
            combo.setSelectedIndex(0); // "Ask" by default
            answerCombos.put(key, combo);

            gc.gridx = 0; gc.gridy = row; gc.weightx = 1.0; gc.fill = GridBagConstraints.NONE;
            grid.add(new JLabel(label + ":"), gc);

            gc.gridx = 1; gc.weightx = 0;
            grid.add(combo, gc);

            row++;
        }

        outer.add(grid, BorderLayout.CENTER);
        return outer;
    }

    public ScanOptions readOptions(boolean forceSSL) {
        ScanOptions o = new ScanOptions();
        o.level       = (int) levelSpin.getValue();
        o.risk        = (int) riskSpin.getValue();
        o.threads     = (int) threadsSpin.getValue();
        o.technique   = techniqueField.getText().trim().isEmpty() ? "BEUSTQ" : techniqueField.getText().trim();
        o.dbms        = (String) dbmsCombo.getSelectedItem();
        o.tamper      = tamperField.getText().trim();
        o.batch       = batchCheck.isSelected();
        o.randomAgent = randomAgentCheck.isSelected();
        o.forms       = formsCheck.isSelected();
        o.getDbs      = dbsCheck.isSelected();
        o.currentUser = userCheck.isSelected();
        o.banner      = bannerCheck.isSelected();
        o.isDba       = isdbaCheck.isSelected();
        o.forceSSL    = forceSSL;
        o.verbose     = 2;
        o.customArgs  = customArgsField.getText().trim();

        // Read answers (only meaningful when batch=false, but always store them)
        o.answers = new LinkedHashMap<>();
        for (String[] prompt : ScanOptions.ANSWER_PROMPTS) {
            String key = prompt[0];
            JComboBox<String> combo = answerCombos.get(key);
            if (combo == null) continue;
            String selected = (String) combo.getSelectedItem();
            if ("Yes".equals(selected))          o.answers.put(key, "Y");
            else if ("No".equals(selected))      o.answers.put(key, "N");
            // "Default" -> omit
        }

        return o;
    }

    public String getApiUrl() { return apiUrlField.getText().trim(); }
    public int    getPollMs() { return (int) pollSpin.getValue() * 1_000; }

    private JPanel titledPanel(String title) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        p.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), title,
            TitledBorder.LEFT, TitledBorder.TOP));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private JLabel label(String text) {
        JLabel l = new JLabel(text + ":");
        l.setPreferredSize(new Dimension(72, 20));
        return l;
    }
}