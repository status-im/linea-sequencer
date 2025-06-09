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

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NullifierTrackerTest {

  @TempDir Path tempDir;
  private Path nullifierFile;
  private NullifierTracker tracker;

  @BeforeEach
  void setUp() {
    nullifierFile = tempDir.resolve("nullifiers.txt");
    tracker = new NullifierTracker("TestService", nullifierFile.toString(), 24L);
  }

  @AfterEach
  void tearDown() throws IOException {
    if (tracker != null) {
      tracker.close();
    }
  }

  @Test
  void testEpochScoping_sameNullifierDifferentEpochs_shouldAllow() {
    // Given: Same nullifier, different epochs
    String nullifier = "0x1234567890abcdef";
    String epoch1 = "epoch1";
    String epoch2 = "epoch2";

    // When: Use nullifier in epoch1
    boolean result1 = tracker.checkAndMarkNullifier(nullifier, epoch1);

    // Then: Should be allowed
    assertTrue(result1, "First use in epoch1 should be allowed");

    // When: Use same nullifier in epoch2
    boolean result2 = tracker.checkAndMarkNullifier(nullifier, epoch2);

    // Then: Should be allowed (different epoch)
    assertTrue(result2, "Same nullifier in different epoch should be allowed");
  }

  @Test
  void testEpochScoping_sameNullifierSameEpoch_shouldReject() {
    // Given: Same nullifier, same epoch
    String nullifier = "0x1234567890abcdef";
    String epoch = "epoch1";

    // When: Use nullifier first time
    boolean result1 = tracker.checkAndMarkNullifier(nullifier, epoch);

    // Then: Should be allowed
    assertTrue(result1, "First use should be allowed");

    // When: Try to use same nullifier in same epoch
    boolean result2 = tracker.checkAndMarkNullifier(nullifier, epoch);

    // Then: Should be rejected
    assertFalse(result2, "Reuse in same epoch should be rejected");
  }

  @Test
  void testIsNullifierUsed_withEpochScoping() {
    // Given: Nullifier used in specific epoch
    String nullifier = "0xabcdef1234567890";
    String epoch1 = "epoch1";
    String epoch2 = "epoch2";

    // Initially not used in any epoch
    assertFalse(tracker.isNullifierUsed(nullifier, epoch1));
    assertFalse(tracker.isNullifierUsed(nullifier, epoch2));

    // Use in epoch1
    tracker.checkAndMarkNullifier(nullifier, epoch1);

    // Should be marked as used in epoch1 but not epoch2
    assertTrue(tracker.isNullifierUsed(nullifier, epoch1));
    assertFalse(tracker.isNullifierUsed(nullifier, epoch2));
  }

  @Test
  void testStorageFormat_preservesEpochInformation() throws IOException {
    // Given: Nullifiers in different epochs
    tracker.checkAndMarkNullifier("0x1111", "epoch_A");
    tracker.checkAndMarkNullifier("0x2222", "epoch_B");

    // When: File content is written
    tracker.close(); // Force write

    // Then: File should contain epoch information
    List<String> lines = Files.readAllLines(nullifierFile);

    // Find data lines (skip comments)
    List<String> dataLines =
        lines.stream().filter(line -> !line.startsWith("#") && !line.trim().isEmpty()).toList();

    assertEquals(2, dataLines.size(), "Should have 2 nullifier entries");

    // Verify format: nullifier,timestamp,epoch
    for (String line : dataLines) {
      String[] parts = line.split(",");
      assertEquals(3, parts.length, "Each line should have 3 parts: nullifier,timestamp,epoch");
      assertFalse(parts[2].equals("epoch"), "Should not have hardcoded 'epoch' string");
      assertTrue(parts[2].startsWith("epoch_"), "Should preserve actual epoch ID");
    }
  }

  @Test
  void testReloadFromStorage_preservesEpochScoping() throws IOException {
    // Given: Nullifiers stored with epochs
    tracker.checkAndMarkNullifier("0x1111", "epoch_A");
    tracker.checkAndMarkNullifier("0x2222", "epoch_B");
    tracker.close();

    // When: Create new tracker instance
    NullifierTracker newTracker =
        new NullifierTracker("TestService", nullifierFile.toString(), 24L);

    // Then: Should preserve epoch scoping
    assertTrue(newTracker.isNullifierUsed("0x1111", "epoch_A"));
    assertFalse(newTracker.isNullifierUsed("0x1111", "epoch_B"));
    assertTrue(newTracker.isNullifierUsed("0x2222", "epoch_B"));
    assertFalse(newTracker.isNullifierUsed("0x2222", "epoch_A"));

    newTracker.close();
  }

  @Test
  void testInvalidInputs_shouldHandleGracefully() {
    // Test null nullifier
    assertFalse(tracker.checkAndMarkNullifier(null, "epoch1"));

    // Test empty nullifier
    assertFalse(tracker.checkAndMarkNullifier("", "epoch1"));

    // Test null epoch
    assertFalse(tracker.checkAndMarkNullifier("0x1234", null));

    // Test empty epoch
    assertFalse(tracker.checkAndMarkNullifier("0x1234", ""));

    // Test isNullifierUsed with invalid inputs
    assertFalse(tracker.isNullifierUsed(null, "epoch1"));
    assertFalse(tracker.isNullifierUsed("0x1234", null));
    assertFalse(tracker.isNullifierUsed("", "epoch1"));
    assertFalse(tracker.isNullifierUsed("0x1234", ""));
  }

  @Test
  void testConcurrentAccess_sameNullifierSameEpoch() throws InterruptedException {
    // Test concurrent access to prevent race conditions
    String nullifier = "0xdeadbeef";
    String epoch = "concurrent_test";

    Thread[] threads = new Thread[10];
    boolean[] results = new boolean[10];

    // Start multiple threads trying to use same nullifier
    for (int i = 0; i < 10; i++) {
      final int index = i;
      threads[i] =
          new Thread(
              () -> {
                results[index] = tracker.checkAndMarkNullifier(nullifier, epoch);
              });
    }

    // Start all threads
    for (Thread thread : threads) {
      thread.start();
    }

    // Wait for completion
    for (Thread thread : threads) {
      thread.join();
    }

    // Exactly one should succeed
    int successCount = 0;
    for (boolean result : results) {
      if (result) successCount++;
    }

    assertEquals(1, successCount, "Exactly one thread should succeed with concurrent access");
  }
}
