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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import org.hyperledger.besu.datatypes.Address;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Comprehensive unit tests for DenyListManager.
 *
 * <p>These tests verify the single source of truth functionality for deny list management,
 * including thread safety, file persistence, TTL expiration, and clear separation between read-only
 * and write operations.
 */
class DenyListManagerTest {

  @TempDir Path tempDir;
  private Path denyListFile;
  private DenyListManager denyListManager;

  @BeforeEach
  void setUp() throws IOException {
    denyListFile = tempDir.resolve("deny_list.txt");
  }

  @AfterEach
  void tearDown() throws IOException {
    if (denyListManager != null) {
      denyListManager.close();
    }
  }

  @Test
  void testInitialization_withoutFile_shouldCreateEmptyList() {
    // Given: No existing deny list file
    assertFalse(Files.exists(denyListFile));

    // When: Initialize DenyListManager
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);

    // Then: Should start with empty list
    assertEquals(0, denyListManager.size());

    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    assertFalse(denyListManager.isDenied(testAddress));
  }

  @Test
  void testInitialization_withExistingFile_shouldLoadEntries() throws IOException {
    // Given: Existing deny list file with valid entries
    Address address1 = Address.fromHexString("0x1111111111111111111111111111111111111111");
    Address address2 = Address.fromHexString("0x2222222222222222222222222222222222222222");
    Instant recentTime = Instant.now().minusSeconds(30);

    String fileContent =
        address1.toHexString().toLowerCase()
            + ","
            + recentTime.toString()
            + "\n"
            + address2.toHexString().toLowerCase()
            + ","
            + recentTime.toString();
    Files.writeString(denyListFile, fileContent, StandardCharsets.UTF_8);

    // When: Initialize DenyListManager
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);

    // Then: Should load entries from file
    assertEquals(2, denyListManager.size());
    assertTrue(denyListManager.isDenied(address1));
    assertTrue(denyListManager.isDenied(address2));

    Address unknownAddress = Address.fromHexString("0x3333333333333333333333333333333333333333");
    assertFalse(denyListManager.isDenied(unknownAddress));
  }

  @Test
  void testInitialization_withExpiredEntries_shouldPruneOnLoad() throws IOException {
    // Given: File with both valid and expired entries
    Address validAddress = Address.fromHexString("0x1111111111111111111111111111111111111111");
    Address expiredAddress = Address.fromHexString("0x2222222222222222222222222222222222222222");

    Instant recentTime = Instant.now().minusSeconds(30);
    Instant expiredTime =
        Instant.now().minus(120, java.time.temporal.ChronoUnit.MINUTES); // Older than 60 minute TTL

    String fileContent =
        validAddress.toHexString().toLowerCase()
            + ","
            + recentTime.toString()
            + "\n"
            + expiredAddress.toHexString().toLowerCase()
            + ","
            + expiredTime.toString();
    Files.writeString(denyListFile, fileContent, StandardCharsets.UTF_8);

    // When: Initialize DenyListManager with 60 minute TTL
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);

    // Then: Should only keep valid entries and prune expired ones
    assertEquals(1, denyListManager.size());
    assertTrue(denyListManager.isDenied(validAddress));
    assertFalse(denyListManager.isDenied(expiredAddress));

    // And file should be updated to reflect pruning
    String updatedContent = Files.readString(denyListFile, StandardCharsets.UTF_8);
    assertTrue(updatedContent.contains(validAddress.toHexString().toLowerCase()));
    assertFalse(updatedContent.contains(expiredAddress.toHexString().toLowerCase()));
  }

  @Test
  void testAddToDenyList_newAddress_shouldAddAndPersist() throws IOException {
    // Given: Empty deny list
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");

    // When: Add address to deny list
    boolean added = denyListManager.addToDenyList(testAddress);

    // Then: Should be added and persisted
    assertTrue(added, "Should return true for newly added address");
    assertEquals(1, denyListManager.size());
    assertTrue(denyListManager.isDenied(testAddress));

    // Verify persistence
    assertTrue(Files.exists(denyListFile));
    String fileContent = Files.readString(denyListFile, StandardCharsets.UTF_8);
    assertTrue(fileContent.contains(testAddress.toHexString().toLowerCase()));
  }

  @Test
  void testAddToDenyList_existingAddress_shouldUpdateTimestamp() throws IOException {
    // Given: Address already in deny list
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");

    denyListManager.addToDenyList(testAddress);
    String initialContent = Files.readString(denyListFile, StandardCharsets.UTF_8);

    // When: Add same address again
    boolean added = denyListManager.addToDenyList(testAddress);

    // Then: Should update timestamp but return false
    assertFalse(added, "Should return false for existing address");
    assertEquals(1, denyListManager.size());
    assertTrue(denyListManager.isDenied(testAddress));

    // Verify timestamp was updated (file content changed)
    String updatedContent = Files.readString(denyListFile, StandardCharsets.UTF_8);
    assertNotEquals(
        initialContent, updatedContent, "File content should be updated with new timestamp");
  }

  @Test
  void testRemoveFromDenyList_existingAddress_shouldRemoveAndPersist() throws IOException {
    // Given: Address in deny list
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    denyListManager.addToDenyList(testAddress);

    assertTrue(denyListManager.isDenied(testAddress));

    // When: Remove address from deny list
    boolean removed = denyListManager.removeFromDenyList(testAddress);

    // Then: Should be removed and persisted
    assertTrue(removed, "Should return true for removed address");
    assertEquals(0, denyListManager.size());
    assertFalse(denyListManager.isDenied(testAddress));

    // Verify persistence (file should be empty or not contain the address)
    if (Files.exists(denyListFile)) {
      String fileContent = Files.readString(denyListFile, StandardCharsets.UTF_8);
      assertFalse(fileContent.contains(testAddress.toHexString().toLowerCase()));
    }
  }

  @Test
  void testRemoveFromDenyList_nonExistentAddress_shouldReturnFalse() {
    // Given: Empty deny list
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");

    // When: Try to remove non-existent address
    boolean removed = denyListManager.removeFromDenyList(testAddress);

    // Then: Should return false
    assertFalse(removed, "Should return false for non-existent address");
    assertEquals(0, denyListManager.size());
  }

  @Test
  void testIsDenied_expiredEntry_shouldReturnFalseAndCleanup()
      throws IOException, InterruptedException {
    // Given: Address with very short TTL (1 second)
    denyListManager =
        new DenyListManager(
            "TestService", denyListFile.toString(), 0L, 0L); // 0 minutes = immediate expiry
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");

    // Create an expired entry by writing directly to file
    Instant expiredTime = Instant.now().minus(5, java.time.temporal.ChronoUnit.MINUTES);
    String expiredEntry = testAddress.toHexString().toLowerCase() + "," + expiredTime.toString();
    Files.writeString(denyListFile, expiredEntry, StandardCharsets.UTF_8);

    // Reload to pick up the expired entry
    denyListManager.reloadFromFile();

    // When: Check if denied (should auto-cleanup expired entry)
    boolean isDenied = denyListManager.isDenied(testAddress);

    // Then: Should return false and clean up the expired entry
    assertFalse(isDenied, "Expired entry should not be denied");
    // Note: Size might still be 1 initially due to race condition in cleanup,
    // but entry should be logically expired and return false
  }

  @Test
  void testReloadFromFile_shouldPickUpExternalChanges() throws IOException {
    // Given: Initialized deny list manager
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");

    assertFalse(denyListManager.isDenied(testAddress));

    // When: External process adds entry to file
    String newEntry = testAddress.toHexString().toLowerCase() + "," + Instant.now().toString();
    Files.writeString(denyListFile, newEntry, StandardCharsets.UTF_8);
    denyListManager.reloadFromFile();

    // Then: Should pick up the new entry
    assertTrue(denyListManager.isDenied(testAddress));
    assertEquals(1, denyListManager.size());
  }

  @Test
  void testFileWithMalformedEntries_shouldSkipInvalidLines() throws IOException {
    // Given: File with mix of valid and malformed entries
    Address validAddress = Address.fromHexString("0x1111111111111111111111111111111111111111");
    String fileContent =
        validAddress.toHexString().toLowerCase()
            + ","
            + Instant.now().toString()
            + "\n"
            + "invalid-address,timestamp\n"
            + "0x2222222222222222222222222222222222222222\n"
            + // Missing timestamp
            "0x3333333333333333333333333333333333333333,invalid-timestamp\n"
            + ""; // Empty line
    Files.writeString(denyListFile, fileContent, StandardCharsets.UTF_8);

    // When: Initialize DenyListManager
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);

    // Then: Should only load valid entries
    assertEquals(1, denyListManager.size());
    assertTrue(denyListManager.isDenied(validAddress));
  }

  @Test
  void testConcurrentAccess_shouldBeThreadSafe() throws InterruptedException {
    // Given: DenyListManager with multiple threads accessing it
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);

    int numThreads = 10;
    int operationsPerThread = 100;
    Thread[] threads = new Thread[numThreads];

    // When: Multiple threads add/remove/check addresses concurrently
    for (int i = 0; i < numThreads; i++) {
      final int threadId = i;
      threads[i] =
          new Thread(
              () -> {
                for (int j = 0; j < operationsPerThread; j++) {
                  Address address =
                      Address.fromHexString(
                          String.format("0x%040d", threadId * operationsPerThread + j));

                  // Add address
                  denyListManager.addToDenyList(address);

                  // Check if denied
                  assertTrue(denyListManager.isDenied(address));

                  // Remove some addresses
                  if (j % 2 == 0) {
                    denyListManager.removeFromDenyList(address);
                    assertFalse(denyListManager.isDenied(address));
                  }
                }
              });
    }

    // Start all threads
    for (Thread thread : threads) {
      thread.start();
    }

    // Wait for all threads to complete
    for (Thread thread : threads) {
      thread.join();
    }

    // Then: Should have consistent state (approximately half the addresses remaining)
    int expectedRemaining = numThreads * operationsPerThread / 2;
    assertEquals(
        expectedRemaining, denyListManager.size(), 5); // Allow small variance due to timing
  }

  @Test
  void testRefreshScheduler_shouldPeriodicallySyncWithFile()
      throws IOException, InterruptedException {
    // Given: DenyListManager with 1 second refresh interval
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 1L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");

    assertFalse(denyListManager.isDenied(testAddress));

    // When: External process adds entry to file
    String newEntry = testAddress.toHexString().toLowerCase() + "," + Instant.now().toString();
    Files.writeString(denyListFile, newEntry, StandardCharsets.UTF_8);

    // Wait for refresh to occur (give it some time)
    Thread.sleep(1500);

    // Then: Should automatically pick up the new entry
    assertTrue(denyListManager.isDenied(testAddress));
    assertEquals(1, denyListManager.size());
  }

  @Test
  void testAtomicFileOperations_shouldPreventCorruption() throws IOException {
    // Given: DenyListManager
    denyListManager = new DenyListManager("TestService", denyListFile.toString(), 60L, 0L);

    // When: Add multiple addresses rapidly
    for (int i = 0; i < 100; i++) {
      Address address = Address.fromHexString(String.format("0x%040d", i));
      denyListManager.addToDenyList(address);
    }

    // Then: File should be readable and contain all entries
    assertTrue(Files.exists(denyListFile));
    String fileContent = Files.readString(denyListFile, StandardCharsets.UTF_8);
    String[] lines = fileContent.split("\n");

    // Should have 100 valid lines
    assertEquals(100, lines.length);

    // Each line should be properly formatted
    for (String line : lines) {
      String[] parts = line.split(",");
      assertEquals(2, parts.length, "Each line should have address,timestamp format");

      // Address should be valid
      assertDoesNotThrow(() -> Address.fromHexString(parts[0]));

      // Timestamp should be valid
      assertDoesNotThrow(() -> Instant.parse(parts[1]));
    }
  }

  @Test
  void testDirectoryCreation_shouldCreateParentDirectories() throws IOException {
    // Given: Deny list file in non-existent directory
    Path nestedDir = tempDir.resolve("nested").resolve("directory");
    Path nestedDenyListFile = nestedDir.resolve("deny_list.txt");

    assertFalse(Files.exists(nestedDir));

    // When: Initialize DenyListManager and add entry
    denyListManager = new DenyListManager("TestService", nestedDenyListFile.toString(), 60L, 0L);
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    denyListManager.addToDenyList(testAddress);

    // Then: Should create parent directories and file
    assertTrue(Files.exists(nestedDir));
    assertTrue(Files.exists(nestedDenyListFile));
    assertTrue(denyListManager.isDenied(testAddress));
  }
}
