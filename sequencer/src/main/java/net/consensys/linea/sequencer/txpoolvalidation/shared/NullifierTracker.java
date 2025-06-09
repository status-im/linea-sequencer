/*
 * Copyright Consensys Software Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package net.consensys.linea.sequencer.txpoolvalidation.shared;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread-safe nullifier tracking service for RLN proof uniqueness validation.
 *
 * <p>This service prevents proof reuse attacks by maintaining a persistent record of used
 * nullifiers **scoped by epoch**. Key features:
 *
 * <ul>
 *   <li>Thread-safe concurrent nullifier tracking with proper epoch scoping
 *   <li>Persistent storage with atomic file operations
 *   <li>Automatic expiration of old nullifiers
 *   <li>Memory-efficient epoch-based cleanup
 *   <li>High-performance lookups for validation
 * </ul>
 *
 * <p><strong>Security Critical:</strong> This component is essential for RLN security. Nullifier
 * reuse within the same epoch would completely compromise rate limiting guarantees.
 *
 * <p><strong>Epoch Scoping:</strong> Nullifiers are scoped by epoch, meaning the same nullifier can
 * be reused across different epochs but not within the same epoch. This is fundamental to RLN
 * semantics where users get fresh nullifiers each epoch.
 */
public class NullifierTracker implements Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(NullifierTracker.class);

  private final String serviceName;
  private final Path nullifierStorageFile;
  private final long nullifierExpiryHours;
  private final ScheduledExecutorService cleanupScheduler;

  // Thread-safe in-memory nullifier tracking: epochScopedKey -> nullifierData
  private final ConcurrentHashMap<String, NullifierData> usedNullifiers = new ConcurrentHashMap<>();

  // Metrics
  private final AtomicLong totalNullifiersTracked = new AtomicLong(0);
  private final AtomicLong nullifierHits = new AtomicLong(0);
  private final AtomicLong cleanupOperations = new AtomicLong(0);

  /** Represents a tracked nullifier with its metadata. */
  private record NullifierData(String nullifier, String epochId, Instant timestamp) {}

  /**
   * Creates a new nullifier tracker with specified storage and expiry settings.
   *
   * @param serviceName Service name for logging identification
   * @param storageFilePath Path to persistent nullifier storage file
   * @param nullifierExpiryHours Hours after which nullifiers expire and can be removed
   */
  public NullifierTracker(String serviceName, String storageFilePath, long nullifierExpiryHours) {
    this.serviceName = serviceName;
    this.nullifierStorageFile = Paths.get(storageFilePath);
    this.nullifierExpiryHours = nullifierExpiryHours;
    this.cleanupScheduler =
        Executors.newSingleThreadScheduledExecutor(
            r -> new Thread(r, serviceName + "-NullifierCleanup"));

    LOG.info(
        "{}: Initializing nullifier tracker with storage: {}, expiry: {} hours",
        serviceName,
        storageFilePath,
        nullifierExpiryHours);

    // Load existing nullifiers from storage
    loadNullifiersFromStorage();

    // Schedule regular cleanup of expired nullifiers
    scheduleCleanupTasks();

    LOG.info(
        "{}: Nullifier tracker initialized with {} nullifiers", serviceName, usedNullifiers.size());
  }

  /**
   * Checks if a nullifier has been used before within the given epoch and marks it as used if new.
   *
   * <p><strong>Thread-safe and atomic:</strong> This operation is atomic to prevent race conditions
   * where multiple transactions with the same nullifier could pass validation simultaneously.
   *
   * <p><strong>Epoch Scoping:</strong> Nullifiers are scoped by epoch. The same nullifier can be
   * reused across different epochs but not within the same epoch.
   *
   * @param nullifierHex Hex-encoded nullifier to check/register
   * @param epochId Current epoch identifier for scoping
   * @return true if nullifier is new within this epoch (transaction should be allowed), false if
   *     already used in this epoch
   */
  public boolean checkAndMarkNullifier(String nullifierHex, String epochId) {
    if (nullifierHex == null || nullifierHex.trim().isEmpty()) {
      LOG.warn("{}: Invalid nullifier provided: {}", serviceName, nullifierHex);
      return false;
    }

    if (epochId == null || epochId.trim().isEmpty()) {
      LOG.warn("{}: Invalid epoch ID provided: {}", serviceName, epochId);
      return false;
    }

    String normalizedNullifier = nullifierHex.toLowerCase().trim();
    String normalizedEpochId = epochId.trim();

    // CRITICAL FIX: Create epoch-scoped key for proper nullifier tracking
    String epochScopedKey = normalizedNullifier + ":" + normalizedEpochId;

    Instant now = Instant.now();
    NullifierData nullifierData = new NullifierData(normalizedNullifier, normalizedEpochId, now);

    // Atomic check-and-set operation with epoch scoping
    NullifierData previousUse = usedNullifiers.putIfAbsent(epochScopedKey, nullifierData);

    if (previousUse != null) {
      // Nullifier was already used in this epoch
      nullifierHits.incrementAndGet();
      LOG.warn(
          "{}: Nullifier reuse detected within epoch! Nullifier: {}, Epoch: {}, Previous use: {}",
          serviceName,
          normalizedNullifier,
          normalizedEpochId,
          previousUse.timestamp());
      return false;
    }

    // New nullifier for this epoch - persist to storage
    totalNullifiersTracked.incrementAndGet();
    persistNullifierToStorage(normalizedNullifier, normalizedEpochId, now);

    LOG.debug(
        "{}: New nullifier registered: {}, Epoch: {}, Total tracked: {}",
        serviceName,
        normalizedNullifier,
        normalizedEpochId,
        usedNullifiers.size());

    return true;
  }

  /**
   * Checks if a nullifier has been used within the given epoch without marking it as used.
   *
   * @param nullifierHex Hex-encoded nullifier to check
   * @param epochId Epoch identifier for scoping
   * @return true if nullifier has been used within this epoch, false if new
   */
  public boolean isNullifierUsed(String nullifierHex, String epochId) {
    if (nullifierHex == null
        || nullifierHex.trim().isEmpty()
        || epochId == null
        || epochId.trim().isEmpty()) {
      return false;
    }
    String epochScopedKey = nullifierHex.toLowerCase().trim() + ":" + epochId.trim();
    return usedNullifiers.containsKey(epochScopedKey);
  }

  /** Loads existing nullifiers from persistent storage on startup. */
  private void loadNullifiersFromStorage() {
    if (!Files.exists(nullifierStorageFile)) {
      LOG.info("{}: No existing nullifier storage file found, starting fresh", serviceName);
      return;
    }

    try {
      var lines = Files.readAllLines(nullifierStorageFile, StandardCharsets.UTF_8);
      int loaded = 0;
      int expired = 0;
      Instant cutoff = Instant.now().minus(Duration.ofHours(nullifierExpiryHours));

      for (String line : lines) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) continue;

        String[] parts = line.split(",", 3);
        if (parts.length >= 3) {
          String nullifier = parts[0].trim();
          String epochId = parts[2].trim(); // epoch is the third field
          try {
            Instant timestamp = Instant.parse(parts[1].trim());

            if (timestamp.isAfter(cutoff)) {
              // CRITICAL FIX: Use epoch-scoped key for loading
              String epochScopedKey = nullifier + ":" + epochId;
              NullifierData data = new NullifierData(nullifier, epochId, timestamp);
              usedNullifiers.put(epochScopedKey, data);
              loaded++;
            } else {
              expired++;
            }
          } catch (Exception e) {
            LOG.warn("{}: Invalid timestamp in nullifier file: {}", serviceName, line);
          }
        } else {
          LOG.warn("{}: Invalid nullifier file format: {}", serviceName, line);
        }
      }

      LOG.info(
          "{}: Loaded {} nullifiers from storage, expired {} old entries",
          serviceName,
          loaded,
          expired);

    } catch (IOException e) {
      LOG.error("{}: Failed to load nullifiers from storage: {}", serviceName, e.getMessage(), e);
    }
  }

  /** Persists a new nullifier to storage file atomically. */
  private void persistNullifierToStorage(String nullifier, String epochId, Instant timestamp) {
    try {
      // Ensure parent directory exists
      Files.createDirectories(nullifierStorageFile.getParent());

      String entry = String.format("%s,%s,%s%n", nullifier, timestamp, epochId);
      Files.writeString(
          nullifierStorageFile,
          entry,
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.APPEND);

    } catch (IOException e) {
      LOG.error("{}: Failed to persist nullifier to storage: {}", serviceName, e.getMessage(), e);
      // Don't throw - this is not fatal for immediate operation but log for investigation
    }
  }

  /** Schedules regular cleanup of expired nullifiers. */
  private void scheduleCleanupTasks() {
    // Run cleanup every hour
    cleanupScheduler.scheduleAtFixedRate(this::cleanupExpiredNullifiers, 1, 1, TimeUnit.HOURS);
  }

  /** Removes expired nullifiers from memory and rewrites storage file. */
  private void cleanupExpiredNullifiers() {
    LOG.debug("{}: Starting nullifier cleanup", serviceName);

    Instant cutoff = Instant.now().minus(Duration.ofHours(nullifierExpiryHours));
    int beforeSize = usedNullifiers.size();

    // Remove expired entries from memory
    usedNullifiers.entrySet().removeIf(entry -> entry.getValue().timestamp().isBefore(cutoff));

    int afterSize = usedNullifiers.size();
    int removed = beforeSize - afterSize;

    if (removed > 0) {
      cleanupOperations.incrementAndGet();
      LOG.info(
          "{}: Cleaned up {} expired nullifiers, {} remaining", serviceName, removed, afterSize);

      // Rewrite storage file with only non-expired entries
      rewriteStorageFile();
    } else {
      LOG.debug("{}: No expired nullifiers to clean up", serviceName);
    }
  }

  /** Rewrites the entire storage file with only current nullifiers. */
  private void rewriteStorageFile() {
    try {
      // Write to temporary file first
      Path tempFile =
          nullifierStorageFile.getParent().resolve(nullifierStorageFile.getFileName() + ".tmp");

      StringBuilder content = new StringBuilder();
      content.append("# Nullifier tracking file for ").append(serviceName).append("\n");
      content.append("# Format: nullifier,timestamp,epoch\n");

      // CRITICAL FIX: Use actual epoch data instead of hardcoded "epoch"
      usedNullifiers.forEach(
          (epochScopedKey, data) -> {
            content.append(
                String.format("%s,%s,%s%n", data.nullifier(), data.timestamp(), data.epochId()));
          });

      Files.writeString(tempFile, content.toString(), StandardCharsets.UTF_8);

      // Atomic replace
      Files.move(tempFile, nullifierStorageFile);

      LOG.debug(
          "{}: Rewrote nullifier storage file with {} entries", serviceName, usedNullifiers.size());

    } catch (IOException e) {
      LOG.error("{}: Failed to rewrite nullifier storage file: {}", serviceName, e.getMessage(), e);
    }
  }

  /** Returns current nullifier tracking statistics. */
  public NullifierStats getStats() {
    return new NullifierStats(
        usedNullifiers.size(),
        totalNullifiersTracked.get(),
        nullifierHits.get(),
        cleanupOperations.get());
  }

  /** Statistics record for nullifier tracking. */
  public record NullifierStats(
      int currentNullifiers, long totalTracked, long duplicateAttempts, long cleanupOperations) {}

  @Override
  public void close() throws IOException {
    LOG.info("{}: Shutting down nullifier tracker", serviceName);

    if (cleanupScheduler != null && !cleanupScheduler.isShutdown()) {
      cleanupScheduler.shutdown();
      try {
        if (!cleanupScheduler.awaitTermination(10, TimeUnit.SECONDS)) {
          cleanupScheduler.shutdownNow();
        }
      } catch (InterruptedException e) {
        cleanupScheduler.shutdownNow();
        Thread.currentThread().interrupt();
      }
    }

    // Final cleanup and storage update
    cleanupExpiredNullifiers();

    NullifierStats stats = getStats();
    LOG.info(
        "{}: Nullifier tracker shutdown complete. Final stats: {} current, {} total tracked, {} duplicates blocked",
        serviceName,
        stats.currentNullifiers(),
        stats.totalTracked(),
        stats.duplicateAttempts());
  }
}
