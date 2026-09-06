package ru.florestdev.trafficspy;

import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Environment;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    private static final int VPN_REQUEST_CODE = 1000;

    private Button btnStart, btnStop, btnExport;
    private TextView tvLog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnStart = findViewById(R.id.btn_start_vpn);
        btnStop = findViewById(R.id.btn_stop_vpn);
        btnExport = findViewById(R.id.btn_export_logs);
        tvLog = findViewById(R.id.tv_network_log);

        btnStart.setOnClickListener(v -> startVPN());
        btnStop.setOnClickListener(v -> stopVPN());
        btnExport.setOnClickListener(v -> exportLogs());

        // Обновляем лог каждые 2 секунды
        Thread logThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(2000);
                    runOnUiThread(this::updateLogDisplay);
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        logThread.start();
    }

    private void startVPN() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE);
        } else {
            startVpnService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpnService();
        } else {
            Toast.makeText(this, "VPN permission denied!", Toast.LENGTH_SHORT).show();
        }
    }

    private void startVpnService() {
        Intent intent = new Intent(this, VPNService.class);
        intent.setAction("START");
        startForegroundService(intent);

        btnStart.setEnabled(false);
        btnStop.setEnabled(true);
    }

    private void stopVPN() {
        Intent intent = new Intent(this, VPNService.class);
        intent.setAction("STOP");
        startService(intent);

        btnStart.setEnabled(true);
        btnStop.setEnabled(false);
    }

    private void updateLogDisplay() {
        String log = LogFile.getLogs();
        if (!log.isEmpty()) {
            tvLog.setText(log);
        }
    }

    private void exportLogs() {
        String logs = LogFile.getLogs();
        if (logs.isEmpty()) {
            Toast.makeText(this, "No logs to export", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            // Используем папку приложения (не требует разрешений!)
            File dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
            File file = new File(dir, "logs.txt");

            FileWriter writer = new FileWriter(file);
            writer.write(logs);
            writer.close();

            Toast.makeText(this, "Logs saved to: " + file.getAbsolutePath(), Toast.LENGTH_LONG).show();
        } catch (IOException e) {
            Toast.makeText(this, "Export failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            e.printStackTrace();
        }
    }
}