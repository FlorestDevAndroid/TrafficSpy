package ru.florestdev.trafficspy;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class LogFile {
    private static final int MAX_LOGS = 1000;
    private static final List<String> logs = new ArrayList<>();
    private static final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    // Добавляем запись в лог
    public static synchronized void addLog(String entry) {
        if (logs.size() >= MAX_LOGS) {
            logs.remove(0);
        }
        logs.add("[" + sdf.format(new Date()) + "] " + entry);
    }

    // Получаем все логи в виде строки
    public static synchronized String getLogs() {
        if (logs.isEmpty()) {
            return "No logs available";
        }

        StringBuilder sb = new StringBuilder();
        for (String log : logs) {
            sb.append(log).append("\n");
        }
        return sb.toString();
    }

    // Получаем последние N записей
    public static synchronized String getLastLogs(int count) {
        if (logs.isEmpty()) {
            return "No logs available";
        }

        int start = Math.max(0, logs.size() - count);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < logs.size(); i++) {
            sb.append(logs.get(i)).append("\n");
        }
        return sb.toString();
    }

    // Очистка логов
    public static synchronized void clearLogs() {
        logs.clear();
    }
}