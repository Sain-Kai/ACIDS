package com.sentinelmesh.controlplane.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Durable local audit trail with a cryptographic hash chain.
 *
 * Each record includes the previous record hash and its own SHA-256 hash.
 * Writes are appended and forced to disk before the call returns. This does
 * not replace WORM/object-lock or remote SIEM retention, but it makes silent
 * in-place editing detectable and gives every autonomous transition a
 * verifiable chain position.
 */
@Component
public class AuditLogger {
    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);
    private final Path logPath;
    private String lastHash;

    public AuditLogger(@Value("${sentinelmesh.audit-log-path}") String logPath) {
        this.logPath = Path.of(logPath);
        Path parent = this.logPath.getParent();
        try {
            if (parent != null) Files.createDirectories(parent);
            validateWholeChain();
            this.lastHash = loadLastHash();
        } catch (IOException e) {
            throw new IllegalStateException("cannot initialize audit log: " + this.logPath, e);
        }
    }

    public synchronized void log(String incidentId, String action, String detail) {
        String timestamp = Instant.now().toString();
        String prev = lastHash == null ? "GENESIS" : lastHash;
        String canonical = timestamp + "\t" + safe(incidentId) + "\t" + safe(action) + "\t" + safe(detail) + "\t" + prev;
        String hash = sha256(canonical);
        String line = String.format("%s incident=%s action=%s detail=%s prev_hash=%s hash=%s%n",
                timestamp, safe(incidentId), safe(action), safe(detail), prev, hash);
        try (FileChannel channel = FileChannel.open(logPath,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE,
                java.nio.file.StandardOpenOption.APPEND)) {
            byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
            channel.write(ByteBuffer.wrap(bytes));
            channel.force(true);
            lastHash = hash;
        } catch (IOException e) {
            // Autonomous security state transitions should never pretend an
            // audit write succeeded. Keep the old hash so a later successful
            // write remains chained to the last durable record.
            log.error("AUDIT LOG WRITE FAILED: {} ({})", line.trim(), e.getMessage());
            throw new IllegalStateException("audit log write failed", e);
        }
    }


    private void validateWholeChain() throws IOException {
        if (!Files.exists(logPath) || Files.size(logPath) == 0) return;
        String prev = "GENESIS";
        try (BufferedReader reader = Files.newBufferedReader(logPath, StandardCharsets.UTF_8)) {
            String line;
            long lineNo = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                if (line.isBlank()) continue;
                int incidentMarker = line.indexOf(" incident=");
                int actionMarker = line.indexOf(" action=", incidentMarker + 1);
                int detailMarker = line.indexOf(" detail=", actionMarker + 1);
                int prevMarker = line.indexOf(" prev_hash=", detailMarker + 1);
                int hashMarker = line.lastIndexOf(" hash=");
                if (incidentMarker < 0 || actionMarker < 0 || detailMarker < 0 || prevMarker < 0 || hashMarker < 0 || hashMarker <= prevMarker) {
                    throw new IOException("audit log record is malformed at line " + lineNo);
                }
                String timestamp = line.substring(0, incidentMarker).trim();
                String incident = line.substring(incidentMarker + 10, actionMarker);
                String action = line.substring(actionMarker + 8, detailMarker);
                String detail = line.substring(detailMarker + 8, prevMarker);
                String recordPrev = line.substring(prevMarker + 11, hashMarker);
                String recordHash = line.substring(hashMarker + 6).trim();
                if (!recordPrev.equals(prev)) throw new IOException("audit hash-chain break at line " + lineNo);
                if (!recordHash.matches("[0-9a-fA-F]{64}")) throw new IOException("audit record hash malformed at line " + lineNo);
                String canonical = timestamp + "\t" + incident + "\t" + action + "\t" + detail + "\t" + recordPrev;
                String expected = sha256(canonical);
                if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), recordHash.toLowerCase().getBytes(StandardCharsets.US_ASCII))) {
                    throw new IOException("audit record hash mismatch at line " + lineNo);
                }
                prev = recordHash.toLowerCase();
            }
        }
    }

    private String loadLastHash() throws IOException {
        if (!Files.exists(logPath) || Files.size(logPath) == 0) return null;
        try (RandomAccessFile raf = new RandomAccessFile(logPath.toFile(), "r")) {
            long length = raf.length();
            long start = Math.max(0, length - 65536);
            raf.seek(start);
            String line;
            String latest = null;
            while ((line = raf.readLine()) != null) {
                latest = line;
            }
            if (latest == null) return null;
            int marker = latest.lastIndexOf(" hash=");
            if (marker < 0) throw new IOException("audit log tail is malformed");
            String hash = latest.substring(marker + 6).trim();
            if (hash.length() != 64 || !hash.matches("[0-9a-fA-F]{64}")) {
                throw new IOException("audit log tail hash is malformed");
            }
            return hash.toLowerCase();
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }

    private static String sha256(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
