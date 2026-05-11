package com.sqlburp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScanTableModel extends AbstractTableModel {

    private static final String[] COLS = {"#", "Task ID", "Target", "Method", "Status", "Findings", "Started"};

    private final List<ScanRecord> rows = new ArrayList<>();
    private final Map<String, Integer> indexByTaskId = new HashMap<>();

    @Override public int getRowCount()    { return rows.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }
    @Override public boolean isCellEditable(int r, int c) { return false; }

    @Override
    public Object getValueAt(int row, int col) {
        if (row < 0 || row >= rows.size()) return "";
        ScanRecord r = rows.get(row);
        return switch (col) {
            case 0 -> String.valueOf(row + 1);
            case 1 -> r.taskId;
            case 2 -> r.target;
            case 3 -> r.method;
            case 4 -> r.status;
            case 5 -> String.valueOf(r.findings);
            case 6 -> r.started;
            default -> "";
        };
    }

    public void addRow(ScanRecord rec) {
        int idx = rows.size();
        rows.add(rec);
        indexByTaskId.put(rec.taskId, idx);
        fireTableRowsInserted(idx, idx);
    }

    public void refreshRow(ScanRecord rec) {
        Integer idx = indexByTaskId.get(rec.taskId);
        if (idx != null && idx >= 0 && idx < rows.size()) {
            fireTableRowsUpdated(idx, idx);
        }
    }

    public void removeRow(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return;
        ScanRecord removed = rows.remove(modelRow);
        indexByTaskId.remove(removed.taskId);
        // Rebuild indices from the removal point onward
        for (int i = modelRow; i < rows.size(); i++) {
            indexByTaskId.put(rows.get(i).taskId, i);
        }
        fireTableRowsDeleted(modelRow, modelRow);
        // Refresh # column
        if (modelRow < rows.size()) fireTableRowsUpdated(modelRow, rows.size() - 1);
    }

    public ScanRecord getRecord(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return null;
        return rows.get(modelRow);
    }

    public List<ScanRecord> getRecords() { return rows; }
}
