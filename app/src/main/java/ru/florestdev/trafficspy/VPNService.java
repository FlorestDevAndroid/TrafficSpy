package ru.florestdev.trafficspy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

public class VPNService extends VpnService {

    private static final String TAG = "VPNService";

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "vpn_channel";

    private static final String FAKE_DNS_IPV4 = "10.0.0.1";
    private static final String FAKE_DNS_IPV6 = "fd00::1";

    private static final String DNS_PRIMARY = "8.8.8.8";
    private static final String DNS_SECONDARY = "1.1.1.1";

    private static final int DNS_TIMEOUT_MS = 1500;

    private static final SimpleDateFormat sdf =
            new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;

    private volatile boolean isRunning = false;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_STICKY;
        }

        String action = intent.getAction();

        if ("START".equals(action)) {
            startVpn();
        } else if ("STOP".equals(action)) {
            stopVpn();
        }

        return START_STICKY;
    }

    private void startVpn() {
        if (isRunning) {
            return;
        }

        try {
            Builder builder = new Builder();

            // IPv4 Конфигурация
            builder.addAddress("10.0.0.2", 24);
            builder.addDnsServer(FAKE_DNS_IPV4);
            builder.addRoute(FAKE_DNS_IPV4, 32);

            // IPv6 Конфигурация (чтобы Android не зависал на IPv6 DNS)
            try {
                builder.addAddress("fd00::2", 128);
                builder.addDnsServer(FAKE_DNS_IPV6);
                builder.addRoute(FAKE_DNS_IPV6, 128);
            } catch (Exception e) {
                Log.w(TAG, "IPv6 setup skipped/failed: " + e.getMessage());
            }

            // Исключаем само приложение из VPN
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.addDisallowedApplication(getPackageName());
            }

            builder.setMtu(1500);
            builder.setSession("TrafficSpyDNS");

            vpnInterface = builder.establish();

            if (vpnInterface == null) {
                LogFile.addLog("ERROR: Interface creation failed");
                return;
            }

            isRunning = true;

            startForeground(
                    NOTIFICATION_ID,
                    createNotification("Monitoring Domains...")
            );

            LogFile.addLog("=== Traffic Monitor Started ===");

            vpnThread = new Thread(
                    new DnsInterceptor(vpnInterface),
                    "DnsInterceptor"
            );

            vpnThread.start();

        } catch (Exception e) {
            Log.e(TAG, "Error starting VPN", e);
            LogFile.addLog("ERROR: " + e.getMessage());
        }
    }

    private void stopVpn() {
        isRunning = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }

        stopForeground(true);
        LogFile.addLog("=== Traffic Monitor Stopped ===");
        stopSelf();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopVpn();
    }

    private class DnsInterceptor implements Runnable {

        private final ParcelFileDescriptor vpnFd;

        DnsInterceptor(ParcelFileDescriptor fd) {
            this.vpnFd = fd;
        }

        @Override
        public void run() {
            try (
                    FileInputStream in = new FileInputStream(vpnFd.getFileDescriptor());
                    FileOutputStream out = new FileOutputStream(vpnFd.getFileDescriptor());
                    DatagramSocket dnsSocket = new DatagramSocket()
            ) {
                protect(dnsSocket);
                dnsSocket.setSoTimeout(DNS_TIMEOUT_MS);

                InetAddress primaryDns = InetAddress.getByName(DNS_PRIMARY);
                InetAddress secondaryDns = InetAddress.getByName(DNS_SECONDARY);

                byte[] buffer = new byte[32767];

                while (isRunning && !Thread.currentThread().isInterrupted()) {
                    int length = in.read(buffer);

                    if (length <= 0) {
                        continue;
                    }

                    int ipVersion = (buffer[0] >> 4) & 0xF;

                    // Работаем только с IPv4
                    if (ipVersion != 4 || length < 20) {
                        continue;
                    }

                    int ihl = (buffer[0] & 0x0F) * 4;
                    if (length < ihl + 8) {
                        continue;
                    }

                    int protocol = buffer[9] & 0xFF;

                    // Перехватываем только UDP (17)
                    if (protocol != 17) {
                        continue;
                    }

                    int destPort = ((buffer[ihl + 2] & 0xFF) << 8) | (buffer[ihl + 3] & 0xFF);

                    // Проверяем, что запрос идет на 53 порт (DNS)
                    if (destPort != 53) {
                        continue;
                    }

                    int dnsOffset = ihl + 8;
                    int dnsLen = length - dnsOffset;

                    if (dnsLen <= 12) {
                        continue;
                    }

                    byte[] dnsQuery = new byte[dnsLen];
                    System.arraycopy(buffer, dnsOffset, dnsQuery, 0, dnsLen);

                    // Логируем домен
                    String domain = parseDnsDomain(dnsQuery);
                    if (domain != null && !domain.isEmpty()) {
                        LogFile.addLog(sdf.format(new Date()) + " | UDP/DNS | " + domain);
                    }

                    // Сохраняем заголовок исходного IP-пакета
                    byte[] rawPacketCopy = Arrays.copyOf(buffer, length);

                    // Отправляем запрос на реальный DNS
                    byte[] dnsResponsePayload = fetchDnsResult(dnsSocket, primaryDns, secondaryDns, dnsQuery, dnsLen);

                    if (dnsResponsePayload != null) {
                        byte[] replyIpPacket = buildUdpResponsePacket(
                                rawPacketCopy,
                                ihl,
                                dnsResponsePayload,
                                dnsResponsePayload.length
                        );

                        synchronized (out) {
                            out.write(replyIpPacket);
                            out.flush();
                        }
                    }
                }

            } catch (Exception e) {
                if (isRunning) {
                    Log.e(TAG, "DNS Loop Error", e);
                    LogFile.addLog("DNS ERROR: " + e.getMessage());
                }
            }
        }

        private byte[] fetchDnsResult(
                DatagramSocket socket,
                InetAddress primary,
                InetAddress secondary,
                byte[] query,
                int queryLen
        ) {
            byte[] responseBuffer = new byte[4096];

            // 1. Пробуем Primary DNS (8.8.8.8)
            try {
                DatagramPacket request = new DatagramPacket(query, queryLen, primary, 53);
                socket.send(request);

                DatagramPacket response = new DatagramPacket(responseBuffer, responseBuffer.length);
                socket.receive(response);

                return Arrays.copyOf(response.getData(), response.getLength());
            } catch (Exception ignored) {
            }

            // 2. Фолбэк на Secondary DNS (1.1.1.1)
            try {
                DatagramPacket request = new DatagramPacket(query, queryLen, secondary, 53);
                socket.send(request);

                DatagramPacket response = new DatagramPacket(responseBuffer, responseBuffer.length);
                socket.receive(response);

                return Arrays.copyOf(response.getData(), response.getLength());
            } catch (Exception ignored) {
            }

            return null;
        }

        private String parseDnsDomain(byte[] dnsData) {
            try {
                if (dnsData.length < 13) {
                    return null;
                }

                int pos = 12;
                StringBuilder domain = new StringBuilder();

                while (pos < dnsData.length) {
                    int len = dnsData[pos] & 0xFF;

                    if (len == 0) {
                        break;
                    }

                    if ((len & 0xC0) == 0xC0) {
                        break;
                    }

                    if (len > 63 || pos + 1 + len > dnsData.length) {
                        return null;
                    }

                    if (domain.length() > 0) {
                        domain.append('.');
                    }

                    pos++;
                    for (int i = 0; i < len; i++) {
                        domain.append((char) (dnsData[pos + i] & 0xFF));
                    }

                    pos += len;
                }

                return domain.toString();
            } catch (Exception e) {
                return null;
            }
        }

        private byte[] buildUdpResponsePacket(
                byte[] origPacket,
                int origIhl,
                byte[] payload,
                int payloadLen
        ) {
            int totalLen = origIhl + 8 + payloadLen;
            byte[] packet = new byte[totalLen];

            // Копируем исходный IP заголовок
            System.arraycopy(origPacket, 0, packet, 0, origIhl);

            // Инвертируем IP адреса (Src <-> Dst)
            System.arraycopy(origPacket, 16, packet, 12, 4); // New Src = Old Dst
            System.arraycopy(origPacket, 12, packet, 16, 4); // New Dst = Old Src

            // Устанавливаем Total Length
            packet[2] = (byte) ((totalLen >> 8) & 0xFF);
            packet[3] = (byte) (totalLen & 0xFF);

            // TTL и Протокол (UDP = 17)
            packet[8] = 64; // Дефолтный TTL ответа
            packet[9] = 17;

            // Сбрасываем и пересчитываем IP Checksum
            packet[10] = 0;
            packet[11] = 0;

            int ipChecksum = calculateIpChecksum(packet, origIhl);
            packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
            packet[11] = (byte) (ipChecksum & 0xFF);

            // UDP Header
            int udpOffset = origIhl;

            // Инвертируем порты (Src Port <-> Dst Port)
            packet[udpOffset] = origPacket[origIhl + 2];
            packet[udpOffset + 1] = origPacket[origIhl + 3];

            packet[udpOffset + 2] = origPacket[origIhl];
            packet[udpOffset + 3] = origPacket[origIhl + 1];

            // UDP Length
            int udpLen = 8 + payloadLen;
            packet[udpOffset + 4] = (byte) ((udpLen >> 8) & 0xFF);
            packet[udpOffset + 5] = (byte) (udpLen & 0xFF);

            // UDP Checksum = 0 (необязательна для IPv4 UDP)
            packet[udpOffset + 6] = 0;
            packet[udpOffset + 7] = 0;

            // Копируем payload DNS-ответа
            System.arraycopy(payload, 0, packet, origIhl + 8, payloadLen);

            return packet;
        }

        private int calculateIpChecksum(byte[] packet, int headerLength) {
            long sum = 0;

            for (int i = 0; i < headerLength; i += 2) {
                int word = ((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF);
                sum += word;

                while ((sum >> 16) != 0) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
            }

            return (int) (~sum & 0xFFFF);
        }
    }

    private Notification createNotification(String content) {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TrafficSpy")
                .setContentText(content)
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "VPN Service",
                    NotificationManager.IMPORTANCE_LOW
            );

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
}