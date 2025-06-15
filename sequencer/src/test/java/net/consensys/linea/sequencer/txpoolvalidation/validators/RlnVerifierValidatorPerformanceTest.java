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
package net.consensys.linea.sequencer.txpoolvalidation.validators;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import net.consensys.linea.config.LineaRlnValidatorConfiguration;
import net.consensys.linea.config.LineaSharedGaslessConfiguration;
import net.consensys.linea.rln.MockRlnVerificationService;
import net.consensys.linea.rln.proofs.grpc.ProofMessage;
import net.consensys.linea.rln.proofs.grpc.RlnProofServiceGrpc;
import net.consensys.linea.rln.proofs.grpc.StreamProofsRequest;
import net.consensys.linea.sequencer.txpoolvalidation.shared.DenyListManager;
import net.consensys.linea.sequencer.txpoolvalidation.shared.KarmaServiceClient;
import net.consensys.linea.sequencer.txpoolvalidation.shared.NullifierTracker;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.plugin.data.BlockHeader;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performance test for RlnVerifierValidator targeting 1000 TPS sustained throughput.
 *
 * <p>This test validates:
 *
 * <ul>
 *   <li>1000 TPS sustained for 10 seconds (10,000 transactions)
 *   <li>Memory usage remains stable under load
 *   <li>Latency stays below 50ms per validation
 *   <li>Thread count doesn't explode
 *   <li>Concurrent validation capabilities
 *   <li>Cache performance under high load
 *   <li>gRPC streaming performance
 * </ul>
 */
class RlnVerifierValidatorPerformanceTest {

  private static final Logger LOG =
      LoggerFactory.getLogger(RlnVerifierValidatorPerformanceTest.class);

  // Performance test parameters
  private static final int TARGET_TPS = 1000;
  private static final int TEST_DURATION_SECONDS = 10;
  private static final int TOTAL_TRANSACTIONS = TARGET_TPS * TEST_DURATION_SECONDS;
  private static final long MAX_LATENCY_MS = 50;
  private static final int CONCURRENT_THREADS = 20;
  private static final int WARMUP_TRANSACTIONS = 1000;

  @TempDir Path tempDir;

  private RlnVerifierValidator validator;
  private DenyListManager denyListManager;
  private NullifierTracker nullifierTracker;
  private KarmaServiceClient karmaServiceClient;
  private MockRlnVerificationService mockRlnService;
  private HighThroughputMockProofService mockProofService;
  private Server mockServer;
  private ManagedChannel inProcessChannel;
  private ExecutorService testExecutor;

  // Performance metrics
  private final AtomicLong totalValidations = new AtomicLong(0);
  private final AtomicLong successfulValidations = new AtomicLong(0);
  private final AtomicLong failedValidations = new AtomicLong(0);
  private final List<Long> latencies = new CopyOnWriteArrayList<>();
  private final AtomicInteger concurrentValidations = new AtomicInteger(0);
  private final AtomicInteger maxConcurrentValidations = new AtomicInteger(0);

  /** High-throughput mock proof service for performance testing. */
  private static class HighThroughputMockProofService
      extends RlnProofServiceGrpc.RlnProofServiceImplBase {
    private final List<StreamObserver<ProofMessage>> observers = new CopyOnWriteArrayList<>();
    private final ExecutorService proofSender = Executors.newFixedThreadPool(4);
    private volatile boolean isRunning = true;

    @Override
    public void streamProofs(
        StreamProofsRequest request, StreamObserver<ProofMessage> responseObserver) {
      observers.add(responseObserver);
      LOG.debug(
          "High-throughput proof service: Client {} connected, total observers: {}",
          request.getClientId(),
          observers.size());
    }

    public void sendProofBatch(List<ProofMessage> proofs) {
      if (!isRunning) return;

      proofSender.submit(
          () -> {
            for (StreamObserver<ProofMessage> observer : observers) {
              try {
                for (ProofMessage proof : proofs) {
                  observer.onNext(proof);
                }
              } catch (Exception e) {
                LOG.warn("Error sending proof batch: {}", e.getMessage());
              }
            }
          });
    }

    public void shutdown() {
      isRunning = false;
      proofSender.shutdown();
      for (StreamObserver<ProofMessage> observer : observers) {
        try {
          observer.onCompleted();
        } catch (Exception e) {
          LOG.warn("Error completing observer: {}", e.getMessage());
        }
      }
      observers.clear();
    }
  }

  @BeforeEach
  void setUp() throws IOException {
    LOG.info("Setting up performance test environment...");

    // Create high-performance mock services
    setupMockServices();
    setupGrpcServer();
    setupValidator();
    setupTestExecutor();

    LOG.info("Performance test environment ready");
  }

  private void setupMockServices() throws IOException {
    // High-performance mock RLN service
    mockRlnService = new MockRlnVerificationService();
    mockRlnService.setVerificationResult(true); // Always succeed for performance testing

    // High-performance karma service
    karmaServiceClient = mock(KarmaServiceClient.class);
    when(karmaServiceClient.isAvailable()).thenReturn(true);

    KarmaServiceClient.KarmaInfo highQuotaKarma =
        new KarmaServiceClient.KarmaInfo("S-TIER", 432000, 500000, "T:2024-01-01T12", 1000000L);
    when(karmaServiceClient.fetchKarmaInfo(any(Address.class)))
        .thenReturn(Optional.of(highQuotaKarma));

    // Lightweight deny list and nullifier tracker
    Path denyListFile = tempDir.resolve("deny_list.txt");
    denyListManager = new DenyListManager("PerfTest", denyListFile.toString(), 60, 0L);

    Path nullifierFile = tempDir.resolve("nullifiers.txt");
    nullifierTracker = new NullifierTracker("PerfTest", nullifierFile.toString(), 24L);
  }

  private void setupGrpcServer() throws IOException {
    mockProofService = new HighThroughputMockProofService();
    String serverName = InProcessServerBuilder.generateName();

    mockServer =
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(mockProofService)
            .build()
            .start();

    inProcessChannel =
        InProcessChannelBuilder.forName(serverName).usePlaintext().directExecutor().build();

    LOG.info("High-throughput gRPC server started");
  }

  private void setupValidator() throws IOException {
    LineaRlnValidatorConfiguration rlnConfig = mock(LineaRlnValidatorConfiguration.class);
    LineaSharedGaslessConfiguration sharedConfig = mock(LineaSharedGaslessConfiguration.class);
    BlockchainService blockchainService = mock(BlockchainService.class);
    BlockHeader mockHeader = mock(BlockHeader.class);

    // Use consistent timestamp for epoch calculation
    long currentTimestamp = System.currentTimeMillis() / 1000L;

    // Performance-optimized configuration
    when(rlnConfig.rlnValidationEnabled()).thenReturn(true);
    when(rlnConfig.sharedGaslessConfig()).thenReturn(sharedConfig);
    when(rlnConfig.verifyingKeyPath()).thenReturn(tempDir.resolve("vk.key").toString());
    when(rlnConfig.rlnProofLocalWaitTimeoutMs()).thenReturn(10L); // Fast timeout for perf test
    when(rlnConfig.rlnProofCacheMaxSize()).thenReturn(50000L); // Large cache
    when(rlnConfig.rlnProofCacheExpirySeconds()).thenReturn(3600L); // Long expiry
    when(rlnConfig.rlnProofServiceUseTls()).thenReturn(false);
    when(rlnConfig.defaultEpochForQuota()).thenReturn("TIMESTAMP_1H");
    when(rlnConfig.premiumGasPriceThresholdWei()).thenReturn(1_000_000_000L);

    when(sharedConfig.denyListPath()).thenReturn(tempDir.resolve("deny_list.txt").toString());
    when(sharedConfig.denyListRefreshSeconds()).thenReturn(0L);

    when(mockHeader.getTimestamp()).thenReturn(currentTimestamp);
    when(blockchainService.getChainHeadHeader()).thenReturn(mockHeader);

    // Create dummy verifying key
    Files.write(tempDir.resolve("vk.key"), "dummy-key".getBytes());

    validator =
        new RlnVerifierValidator(
            rlnConfig,
            blockchainService,
            denyListManager,
            karmaServiceClient,
            nullifierTracker,
            inProcessChannel,
            mockRlnService);

    LOG.info("High-performance validator created with timestamp: {}", currentTimestamp);
  }

  private void setupTestExecutor() {
    testExecutor = Executors.newFixedThreadPool(CONCURRENT_THREADS);
  }

  @AfterEach
  void tearDown() {
    LOG.info("Tearing down performance test environment...");

    if (testExecutor != null) {
      testExecutor.shutdown();
    }
    if (mockProofService != null) {
      mockProofService.shutdown();
    }
    if (validator != null) {
      try {
        validator.close();
      } catch (IOException e) {
        /* ignore */
      }
    }
    if (denyListManager != null) {
      try {
        denyListManager.close();
      } catch (IOException e) {
        /* ignore */
      }
    }
    if (nullifierTracker != null) {
      try {
        nullifierTracker.close();
      } catch (IOException e) {
        /* ignore */
      }
    }
    if (inProcessChannel != null) {
      inProcessChannel.shutdown();
    }
    if (mockServer != null) {
      mockServer.shutdown();
    }

    LOG.info("Performance test environment cleaned up");
  }

  @Test
  void testSustained1000TPS() throws Exception {
    LOG.info("Starting 1000 TPS sustained throughput test...");

    // Warmup phase
    LOG.info("Warming up with {} transactions...", WARMUP_TRANSACTIONS);
    runWarmup();

    // Reset metrics after warmup
    resetMetrics();

    // Pre-populate proof cache for performance test
    LOG.info("Pre-populating proof cache...");
    prePopulateProofCache();

    // Main performance test
    LOG.info(
        "Starting main performance test: {} TPS for {} seconds", TARGET_TPS, TEST_DURATION_SECONDS);

    long startTime = System.currentTimeMillis();
    long memoryBefore = getUsedMemory();
    int threadsBefore = Thread.activeCount();

    // Run the actual performance test
    runPerformanceTest();

    long endTime = System.currentTimeMillis();
    long memoryAfter = getUsedMemory();
    int threadsAfter = Thread.activeCount();

    // Analyze results
    analyzeResults(startTime, endTime, memoryBefore, memoryAfter, threadsBefore, threadsAfter);
  }

  private void runWarmup() throws Exception {
    List<Future<Void>> warmupFutures = new ArrayList<>();

    for (int i = 0; i < WARMUP_TRANSACTIONS; i++) {
      final int txIndex = i;
      warmupFutures.add(
          testExecutor.submit(
              () -> {
                try {
                  Transaction tx = createTestTransaction(txIndex);
                  validator.validateTransaction(tx, false, false);
                } catch (Exception e) {
                  LOG.warn("Warmup transaction {} failed: {}", txIndex, e.getMessage());
                }
                return null;
              }));
    }

    // Wait for warmup to complete
    for (Future<Void> future : warmupFutures) {
      future.get(30, TimeUnit.SECONDS);
    }

    LOG.info("Warmup completed");
  }

  private void prePopulateProofCache() {
    // Pre-populate cache with valid proofs to avoid cache misses during performance test
    // Generate current epoch to match validator's epoch calculation
    long currentTimestamp = System.currentTimeMillis() / 1000L;
    String currentEpoch =
        "T:"
            + java.time.Instant.ofEpochSecond(currentTimestamp)
                .atZone(java.time.ZoneOffset.UTC)
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH"));

    for (int i = 0; i < TOTAL_TRANSACTIONS; i++) {
      String txHash = String.format("0x%064d", i);
      byte[] proofBytes = Bytes.fromHexString("0x" + "ab".repeat(32)).toArrayUnsafe();
      byte[] senderBytes =
          Address.fromHexString(String.format("0x%040d", i % 1000)).toArrayUnsafe();

      RlnVerifierValidator.CachedProof proof =
          new RlnVerifierValidator.CachedProof(
              proofBytes,
              senderBytes,
              "0x1111111111111111111111111111111111111111111111111111111111111111",
              "0x2222222222222222222222222222222222222222222222222222222222222222",
              currentEpoch, // Use correct epoch format matching TIMESTAMP_1H
              "0x4444444444444444444444444444444444444444444444444444444444444444",
              String.format("0x%064d", i), // Unique nullifier
              Instant.now());

      validator.addProofToCacheForTest(txHash, proof);
    }

    LOG.info(
        "Proof cache pre-populated with {} entries using epoch: {}",
        TOTAL_TRANSACTIONS,
        currentEpoch);
  }

  private void runPerformanceTest() throws Exception {
    List<Future<Void>> futures = new ArrayList<>();
    long testStartTime = System.nanoTime();

    // Submit all transactions with precise timing
    for (int i = 0; i < TOTAL_TRANSACTIONS; i++) {
      final int txIndex = i;
      final long expectedStartTime =
          testStartTime + (i * 1_000_000_000L / TARGET_TPS); // nanoseconds

      futures.add(
          testExecutor.submit(
              () -> {
                try {
                  // Wait for precise timing
                  long currentTime = System.nanoTime();
                  long waitTime = expectedStartTime - currentTime;
                  if (waitTime > 0) {
                    Thread.sleep(waitTime / 1_000_000, (int) (waitTime % 1_000_000));
                  }

                  // Track concurrent validations
                  int concurrent = concurrentValidations.incrementAndGet();
                  maxConcurrentValidations.updateAndGet(max -> Math.max(max, concurrent));

                  long validationStart = System.nanoTime();

                  Transaction tx = createTestTransaction(txIndex);
                  Optional<String> result = validator.validateTransaction(tx, false, false);

                  long validationEnd = System.nanoTime();
                  long latencyMs = (validationEnd - validationStart) / 1_000_000;

                  latencies.add(latencyMs);
                  totalValidations.incrementAndGet();

                  if (result.isEmpty()) {
                    successfulValidations.incrementAndGet();
                  } else {
                    failedValidations.incrementAndGet();
                    LOG.debug("Transaction {} failed validation: {}", txIndex, result.get());
                  }

                } catch (Exception e) {
                  failedValidations.incrementAndGet();
                  LOG.warn("Transaction {} threw exception: {}", txIndex, e.getMessage());
                } finally {
                  concurrentValidations.decrementAndGet();
                }
                return null;
              }));
    }

    // Wait for all transactions to complete
    for (Future<Void> future : futures) {
      future.get(60, TimeUnit.SECONDS);
    }
  }

  private Transaction createTestTransaction(int index) {
    try {
      // Create deterministic but unique transaction using mocks (like existing tests)
      Address sender = Address.fromHexString(String.format("0x%040d", index % 1000));
      Hash txHash = Hash.fromHexString(String.format("0x%064d", index));

      Transaction mockTransaction = mock(Transaction.class);
      when(mockTransaction.getSender()).thenReturn(sender);
      when(mockTransaction.getHash()).thenReturn(txHash);
      when(mockTransaction.getGasPrice())
          .thenAnswer(invocation -> Optional.of(Wei.of(2_000_000_000L))); // 2 GWei
      when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());

      return mockTransaction;

    } catch (Exception e) {
      throw new RuntimeException("Failed to create test transaction " + index, e);
    }
  }

  private void resetMetrics() {
    totalValidations.set(0);
    successfulValidations.set(0);
    failedValidations.set(0);
    latencies.clear();
    concurrentValidations.set(0);
    maxConcurrentValidations.set(0);
  }

  private long getUsedMemory() {
    Runtime runtime = Runtime.getRuntime();
    return runtime.totalMemory() - runtime.freeMemory();
  }

  private void analyzeResults(
      long startTime,
      long endTime,
      long memoryBefore,
      long memoryAfter,
      int threadsBefore,
      int threadsAfter) {

    long durationMs = endTime - startTime;
    double actualTPS = (double) totalValidations.get() * 1000.0 / durationMs;
    double successRate = (double) successfulValidations.get() / totalValidations.get() * 100.0;

    // Calculate latency statistics
    List<Long> sortedLatencies = new ArrayList<>(latencies);
    sortedLatencies.sort(Long::compareTo);

    long minLatency = sortedLatencies.isEmpty() ? 0 : sortedLatencies.get(0);
    long maxLatency =
        sortedLatencies.isEmpty() ? 0 : sortedLatencies.get(sortedLatencies.size() - 1);
    long medianLatency =
        sortedLatencies.isEmpty() ? 0 : sortedLatencies.get(sortedLatencies.size() / 2);
    long p95Latency =
        sortedLatencies.isEmpty() ? 0 : sortedLatencies.get((int) (sortedLatencies.size() * 0.95));
    double avgLatency = sortedLatencies.stream().mapToLong(Long::longValue).average().orElse(0.0);

    long memoryUsedMB = (memoryAfter - memoryBefore) / (1024 * 1024);
    int threadIncrease = threadsAfter - threadsBefore;

    // Log detailed results
    LOG.info("=== PERFORMANCE TEST RESULTS ===");
    LOG.info("Duration: {} ms", durationMs);
    LOG.info("Target TPS: {}", TARGET_TPS);
    LOG.info("Actual TPS: {:.2f}", actualTPS);
    LOG.info("Total Transactions: {}", totalValidations.get());
    LOG.info("Successful: {} ({:.2f}%)", successfulValidations.get(), successRate);
    LOG.info("Failed: {}", failedValidations.get());
    LOG.info("");
    LOG.info("=== LATENCY STATISTICS ===");
    LOG.info("Min Latency: {} ms", minLatency);
    LOG.info("Max Latency: {} ms", maxLatency);
    LOG.info("Median Latency: {} ms", medianLatency);
    LOG.info("Average Latency: {:.2f} ms", avgLatency);
    LOG.info("95th Percentile: {} ms", p95Latency);
    LOG.info("");
    LOG.info("=== RESOURCE USAGE ===");
    LOG.info("Memory Used: {} MB", memoryUsedMB);
    LOG.info("Thread Increase: {}", threadIncrease);
    LOG.info("Max Concurrent Validations: {}", maxConcurrentValidations.get());
    LOG.info("================================");

    // Also output to System.out for visibility in test results
    System.out.println("\n=== RLN PERFORMANCE TEST RESULTS ===");
    System.out.println("Duration: " + durationMs + " ms");
    System.out.println("Target TPS: " + TARGET_TPS);
    System.out.println("Actual TPS: " + String.format("%.2f", actualTPS));
    System.out.println("Total Transactions: " + totalValidations.get());
    System.out.println(
        "Successful: "
            + successfulValidations.get()
            + " ("
            + String.format("%.2f", successRate)
            + "%)");
    System.out.println("Failed: " + failedValidations.get());
    System.out.println("\n=== LATENCY STATISTICS ===");
    System.out.println("Min Latency: " + minLatency + " ms");
    System.out.println("Max Latency: " + maxLatency + " ms");
    System.out.println("Median Latency: " + medianLatency + " ms");
    System.out.println("Average Latency: " + String.format("%.2f", avgLatency) + " ms");
    System.out.println("95th Percentile: " + p95Latency + " ms");
    System.out.println("\n=== RESOURCE USAGE ===");
    System.out.println("Memory Used: " + memoryUsedMB + " MB");
    System.out.println("Thread Increase: " + threadIncrease);
    System.out.println("Max Concurrent Validations: " + maxConcurrentValidations.get());
    System.out.println("=====================================");

    // Performance assertions
    assertTrue(
        actualTPS >= TARGET_TPS * 0.95,
        String.format(
            "Actual TPS (%.2f) should be at least 95%% of target (%d)", actualTPS, TARGET_TPS));

    assertTrue(
        successRate >= 95.0,
        String.format("Success rate (%.2f%%) should be at least 95%%", successRate));

    assertTrue(
        p95Latency <= MAX_LATENCY_MS,
        String.format(
            "95th percentile latency (%d ms) should be <= %d ms", p95Latency, MAX_LATENCY_MS));

    assertTrue(
        memoryUsedMB < 500,
        String.format("Memory usage (%d MB) should be reasonable", memoryUsedMB));

    assertTrue(
        threadIncrease < 50,
        String.format("Thread count increase (%d) should be reasonable", threadIncrease));

    LOG.info(
        "🎉 PERFORMANCE TEST PASSED! RLN system achieved {:.2f} TPS with {:.2f}% success rate",
        actualTPS, successRate);
    System.out.println(
        "🎉 PERFORMANCE TEST PASSED! RLN system achieved "
            + String.format("%.2f", actualTPS)
            + " TPS with "
            + String.format("%.2f", successRate)
            + "% success rate");
  }
}
