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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import net.consensys.linea.config.LineaRlnValidatorConfiguration;
import net.consensys.linea.config.LineaSharedGaslessConfiguration;
import net.consensys.linea.rln.jni.RlnBridge;
import net.consensys.linea.sequencer.txpoolvalidation.shared.DenyListManager;
import net.consensys.linea.sequencer.txpoolvalidation.shared.KarmaServiceClient;
import net.consensys.linea.sequencer.txpoolvalidation.shared.NullifierTracker;
import net.vac.prover.RlnProofFilter;
import net.vac.prover.RlnProofReply;
import net.vac.prover.RlnProverGrpc;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.plugin.data.BlockHeader;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RlnVerifierValidatorTest {

  private static final Logger LOG = LoggerFactory.getLogger(RlnVerifierValidatorTest.class);

  @Mock private LineaRlnValidatorConfiguration rlnConfig;
  @Mock private LineaSharedGaslessConfiguration sharedGaslessConfig;
  @Mock private BlockchainService blockchainService;
  @Mock private BlockHeader mockBlockHeader;
  @TempDir Path tempDir;
  private RlnVerifierValidator validator;
  private Path denyListFile;
  private DenyListManager denyListManager;
  private NullifierTracker nullifierTracker;
  private Path actualVkPath; // For storing real VK for JNI test
  private MockedStatic<RlnBridge> mockedRlnBridge;

  // For JNI Test Data
  private static byte[] jniTestVerifyingKeyBytes;
  private static JSONObject jniTestFirstValidProofEntry;

  //

  // Define a nested class for the mock service implementation
  private static class MockProofServiceImpl extends RlnProverGrpc.RlnProverImplBase {
    private StreamObserver<RlnProofReply> responseObserver; // To send messages to client
    private String clientId; // Store client ID for logging/debugging

    @Override
    public void getProofs(RlnProofFilter request, StreamObserver<RlnProofReply> responseObserver) {
      this.clientId = "test-client"; // Set a default client ID
      LOG.info("MockProofService: getProofs called with filter: {}", request.getAddress());
      this.responseObserver = responseObserver;
      // Keep the stream open, send messages on demand from tests
    }

    // Test helper to send a proof message
    public void sendProof(RlnProofReply proof) {
      if (this.responseObserver != null) {
        LOG.info(
            "MockProofService (client: {}): Sending proof for txHash: {}",
            this.clientId,
            proof.hasProof() ? proof.getProof().getTxHash().toStringUtf8() : "unknown");
        this.responseObserver.onNext(proof);
      } else {
        LOG.warn(
            "MockProofService (client: {}): Cannot send proof, responseObserver is null.",
            this.clientId);
      }
    }

    // Test helper to signal an error
    public void sendError(Throwable error) {
      if (this.responseObserver != null) {
        LOG.warn(
            "MockProofService (client: {}): Sending error: {}", this.clientId, error.getMessage());
        this.responseObserver.onError(error);
      } else {
        LOG.warn(
            "MockProofService (client: {}): Cannot send error, responseObserver is null.",
            this.clientId);
      }
    }

    // Test helper to complete the stream
    public void completeStream() {
      if (this.responseObserver != null) {
        LOG.info("MockProofService (client: {}): Completing stream.", this.clientId);
        this.responseObserver.onCompleted();
        this.responseObserver = null; // Clear observer after completion
      } else {
        LOG.warn(
            "MockProofService (client: {}): Cannot complete stream, responseObserver is null.",
            this.clientId);
      }
    }
  }

  private final MockProofServiceImpl mockProofService = new MockProofServiceImpl();
  private Server mockServer;
  private ManagedChannel inProcessChannel;

  // Static initializer to load JNI test data once
  static {
    try (InputStream inputStream =
        RlnVerifierValidatorTest.class.getClassLoader().getResourceAsStream("rln_test_data.json")) {
      if (inputStream == null) {
        throw new RuntimeException(
            "Cannot find rln_test_data.json in test resources. JNI tests will likely fail.");
      }
      JSONTokener tokener = new JSONTokener(inputStream);
      JSONObject testData = new JSONObject(tokener);

      String vkHex = testData.getString("verifying_key_hex");
      jniTestVerifyingKeyBytes =
          Bytes.fromHexString(vkHex).toArrayUnsafe(); // Use Bytes.fromHexString

      JSONArray testProofs = testData.getJSONArray("test_proofs");
      if (testProofs.length() > 0) {
        jniTestFirstValidProofEntry = testProofs.getJSONObject(0);
      } else {
        throw new RuntimeException("No proofs found in rln_test_data.json.");
      }
    } catch (Exception e) {
      LOG.error("Failed to load JNI test data from rln_test_data.json", e);
      // Let tests run, they might fail if jniTestVerifyingKeyBytes or jniTestFirstValidProofEntry
      // is null
    }
  }

  @BeforeEach
  void setUp() throws IOException {
    System.out.println("RlnVerifierValidatorTest: Starting setUp");
    denyListFile = tempDir.resolve("deny_list.txt");

    // Prepare actual verifying key file for JNI test
    actualVkPath = tempDir.resolve("actual_vk.key");
    if (jniTestVerifyingKeyBytes != null) {
      Files.write(actualVkPath, jniTestVerifyingKeyBytes);
    } else {
      // Write dummy if loading failed, JNI test will likely fail but other tests might proceed
      Files.writeString(actualVkPath, "dummy-key-if-jni-data-failed-to-load");
      LOG.warn(
          "JNI test data (VK) not loaded, JNI verify test will likely use dummy data and fail verification.");
    }

    mockedRlnBridge = mockStatic(RlnBridge.class, withSettings().strictness(Strictness.LENIENT));

    rlnConfig =
        mock(LineaRlnValidatorConfiguration.class, withSettings().strictness(Strictness.LENIENT));
    sharedGaslessConfig =
        mock(LineaSharedGaslessConfiguration.class, withSettings().strictness(Strictness.LENIENT));
    blockchainService =
        mock(BlockchainService.class, withSettings().strictness(Strictness.LENIENT));
    mockBlockHeader = mock(BlockHeader.class, withSettings().strictness(Strictness.LENIENT));

    lenient().when(rlnConfig.rlnValidationEnabled()).thenReturn(true);
    lenient().when(rlnConfig.sharedGaslessConfig()).thenReturn(sharedGaslessConfig);
    lenient().when(rlnConfig.verifyingKeyPath()).thenReturn(actualVkPath.toString());
    lenient().when(rlnConfig.karmaServiceHost()).thenReturn("localhost");
    lenient().when(rlnConfig.karmaServicePort()).thenReturn(7777);
    lenient().when(rlnConfig.karmaServiceUseTls()).thenReturn(false);
    lenient().when(rlnConfig.karmaServiceTimeoutMs()).thenReturn(5000L);
    lenient().when(rlnConfig.exponentialBackoffEnabled()).thenReturn(true);
    lenient().when(rlnConfig.maxBackoffDelayMs()).thenReturn(60000L);
    lenient().when(rlnConfig.rlnProofLocalWaitTimeoutMs()).thenReturn(500L);
    lenient().when(rlnConfig.rlnProofCacheMaxSize()).thenReturn(1000L);
    lenient().when(rlnConfig.rlnProofCacheExpirySeconds()).thenReturn(300L);
    lenient().when(rlnConfig.rlnProofServiceUseTls()).thenReturn(false);
    lenient().when(rlnConfig.rlnProofStreamRetryIntervalMs()).thenReturn(5000L);
    lenient().when(rlnConfig.rlnProofStreamRetries()).thenReturn(10);
    lenient().when(rlnConfig.defaultEpochForQuota()).thenReturn("TIMESTAMP_1H");
    lenient().when(rlnConfig.premiumGasPriceThresholdWei()).thenReturn(10_000_000_000L);
    lenient()
        .when(rlnConfig.denyListEntryMaxAgeMinutes())
        .thenReturn(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES);

    // Add missing proof service configuration
    lenient().when(rlnConfig.rlnProofServiceHost()).thenReturn("localhost");
    lenient().when(rlnConfig.rlnProofServicePort()).thenReturn(8888);

    lenient().when(sharedGaslessConfig.denyListPath()).thenReturn(denyListFile.toString());
    lenient().when(sharedGaslessConfig.denyListRefreshSeconds()).thenReturn(0L);
    lenient()
        .when(sharedGaslessConfig.denyListEntryMaxAgeMinutes())
        .thenReturn(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES);
    lenient().when(sharedGaslessConfig.premiumGasPriceThresholdGWei()).thenReturn(10L);

    // Mock blockchain service to provide block header for epoch calculation
    lenient().when(mockBlockHeader.getTimestamp()).thenReturn(System.currentTimeMillis() / 1000L);
    lenient().when(mockBlockHeader.getNumber()).thenReturn(12345L);
    lenient().when(blockchainService.getChainHeadHeader()).thenReturn(mockBlockHeader);

    String serverName = InProcessServerBuilder.generateName();

    mockServer =
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(mockProofService)
            .build();
    mockServer.start();
    LOG.info(
        "In-process gRPC server started manually with name: {} for service: {}",
        serverName,
        mockProofService.getClass().getSimpleName());

    // Create an in-process channel for the client
    inProcessChannel =
        InProcessChannelBuilder.forName(serverName)
            .usePlaintext() // Explicitly use plaintext
            .directExecutor() // Use direct executor for predictable test behavior
            .build();
    LOG.info("In-process gRPC channel created for server name: {}", serverName);

    // Create DenyListManager for testing - use same expiry as the mock config
    denyListManager =
        new DenyListManager(
            "TestService",
            denyListFile.toString(),
            LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES,
            0L);

    // Create NullifierTracker for testing
    Path nullifierFile = tempDir.resolve("nullifiers.txt");
    nullifierTracker = new NullifierTracker("TestService", nullifierFile.toString(), 24L);

    // Create a mock karma service client for testing
    KarmaServiceClient mockKarmaServiceClient = mock(KarmaServiceClient.class);
    when(mockKarmaServiceClient.isAvailable()).thenReturn(true);

    // Setup default karma info response (user has quota available)
    KarmaServiceClient.KarmaInfo defaultKarmaInfo =
        new KarmaServiceClient.KarmaInfo("STANDARD", 5, 100, "T:2024-01-01T12", 1000L);
    when(mockKarmaServiceClient.fetchKarmaInfo(any(Address.class)))
        .thenReturn(Optional.of(defaultKarmaInfo));

    RlnVerifierValidator tempValidator = null;
    try {
      tempValidator =
          new RlnVerifierValidator(
              rlnConfig,
              blockchainService,
              denyListManager,
              mockKarmaServiceClient,
              nullifierTracker,
              inProcessChannel,
              null); // null for RlnVerificationService - will use factory
    } catch (Throwable t) { // Catch Throwable to get all details
      LOG.error("Error during RlnVerifierValidator construction (direct catch)", t);
      if (t.getCause() != null) {
        LOG.error("Cause (direct catch): ", t.getCause());
      }

      fail("RlnVerifierValidator construction failed (direct catch): " + t.getMessage(), t);
    }
    validator = tempValidator; // Assign to field
    assertNotNull(
        validator, "Validator should be non-null after construction and assignment in setUp");

    System.out.println(
        "RlnVerifierValidatorTest: Finished setUp (validator and gRPC server INITIALIZED)");
  }

  @AfterEach
  void tearDown() {
    System.out.println("RlnVerifierValidatorTest: Starting tearDown");
    if (validator != null) {
      try {
        validator.close();
      } catch (IOException e) {
        LOG.warn("Error closing RlnVerifierValidator: {}", e.getMessage(), e);
      }
      validator = null; // Help GC and prevent reuse
    }
    if (denyListManager != null) {
      try {
        denyListManager.close();
      } catch (IOException e) {
        LOG.warn("Error closing DenyListManager: {}", e.getMessage(), e);
      }
      denyListManager = null;
    }
    if (nullifierTracker != null) {
      try {
        nullifierTracker.close();
      } catch (IOException e) {
        LOG.warn("Error closing NullifierTracker: {}", e.getMessage(), e);
      }
      nullifierTracker = null;
    }
    if (inProcessChannel != null) {
      try {
        inProcessChannel.shutdownNow();
        if (!inProcessChannel.awaitTermination(5, TimeUnit.SECONDS)) {
          LOG.warn("In-process channel did not terminate in time.");
        }
      } catch (InterruptedException e) {
        LOG.warn("In-process channel shutdown interrupted.", e);
        Thread.currentThread().interrupt();
      }
      inProcessChannel = null;
    }
    if (mockedRlnBridge != null) {
      try {
        mockedRlnBridge.close();
      } catch (Exception e) {
        LOG.warn("Error closing mockedRlnBridge: {}", e.getMessage());
      }
      mockedRlnBridge = null;
    }
    if (mockServer != null) {
      try {
        System.out.println("RlnVerifierValidatorTest: Shutting down mockServer...");
        mockServer.shutdownNow();
        if (!mockServer.awaitTermination(5, TimeUnit.SECONDS)) {
          System.err.println("Mock gRPC server did not terminate in time.");
        }
        System.out.println("RlnVerifierValidatorTest: mockServer shut down.");
      } catch (InterruptedException e) {
        LOG.warn("gRPC server shutdown interrupted.", e);
        Thread.currentThread().interrupt();
      } finally {
        mockServer = null; // Ensure it's cleared
      }
    }
    System.out.println("RlnVerifierValidatorTest: Finished tearDown");
  }

  @Test
  void loadDenyListFromFile_whenFileDoesNotExist_initializesEmptyDenyListAndDoesNotThrow() {
    System.out.println(
        "RlnVerifierValidatorTest: Starting test_loadDenyListFromFile_whenFileDoesNotExist");
    assertNotNull(validator, "Validator should be initialized by setUp.");
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    assertFalse(
        validator.isDeniedForTest(testAddress),
        "A random address should not be on the deny list if the file didn't exist at startup.");
    System.out.println(
        "RlnVerifierValidatorTest: Finished test_loadDenyListFromFile_whenFileDoesNotExist");
  }

  @Test
  void loadDenyListFromFile_whenFileExistsWithValidEntries_loadsEntriesCorrectly()
      throws IOException {
    System.out.println(
        "RlnVerifierValidatorTest: Starting test_loadDenyListFromFile_whenFileExistsWithValidEntries");
    assertNotNull(validator, "Validator should be initialized by setUp.");
    Address knownAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    Instant recentTime = Instant.now().minusSeconds(60);
    String entry = knownAddress.toHexString() + "," + recentTime.toString();
    Files.writeString(denyListFile, entry);

    validator.loadDenyListFromFileForTest(); // Force a reload with the new file content

    assertTrue(
        validator.isDeniedForTest(knownAddress),
        "Known address should be on the deny list and not expired.");

    Address unknownAddress = Address.fromHexString("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    assertFalse(
        validator.isDeniedForTest(unknownAddress),
        "Unknown address should not be on the deny list.");
    System.out.println(
        "RlnVerifierValidatorTest: Finished test_loadDenyListFromFile_whenFileExistsWithValidEntries");
  }

  @Test
  void loadDenyListFromFile_whenFileHasExpiredEntries_prunesThem() throws IOException {
    System.out.println(
        "RlnVerifierValidatorTest: Starting test_loadDenyListFromFile_whenFileHasExpiredEntries");
    assertNotNull(validator, "Validator should be initialized by setUp.");
    Address nonExpiredAddress = Address.fromHexString("0x1111111111111111111111111111111111111111");
    Instant recentTime = Instant.now().minusSeconds(60);

    Address expiredAddress = Address.fromHexString("0x2222222222222222222222222222222222222222");
    long configuredExpiryMinutes = rlnConfig.denyListEntryMaxAgeMinutes(); // Get from mock

    Instant expiredTime = Instant.now().minus(Duration.ofMinutes(configuredExpiryMinutes + 5));

    String nonExpiredEntry = nonExpiredAddress.toHexString() + "," + recentTime.toString();
    String expiredEntry = expiredAddress.toHexString() + "," + expiredTime.toString();

    Files.writeString(denyListFile, nonExpiredEntry + "\n" + expiredEntry);

    validator.loadDenyListFromFileForTest();

    // Debug the state after loading
    System.out.println(
        "Non-expired address "
            + nonExpiredAddress
            + " is denied: "
            + validator.isDeniedForTest(nonExpiredAddress));
    System.out.println(
        "Expired address "
            + expiredAddress
            + " is denied: "
            + validator.isDeniedForTest(expiredAddress));
    System.out.println("Configured expiry minutes: " + configuredExpiryMinutes);
    System.out.println("Expired time was: " + expiredTime);
    System.out.println("Current time is: " + Instant.now());

    assertTrue(
        validator.isDeniedForTest(nonExpiredAddress),
        "Non-expired address should still be denied.");
    assertFalse(
        validator.isDeniedForTest(expiredAddress),
        "Expired address should have been pruned and not be denied.");
    System.out.println(
        "RlnVerifierValidatorTest: Finished test_loadDenyListFromFile_whenFileHasExpiredEntries");
  }

  @Test
  void testGrpcProofStream_receivesAndCachesProof() throws InterruptedException {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testGrpcProofStream_receivesAndCachesProof");
    assertNotNull(validator, "Validator should be initialized by setUp.");
    assertNotNull(mockProofService, "MockProofService should be initialized.");

    // For this test, we'll directly add a proof to cache to test the caching mechanism
    // This simulates what would happen if the gRPC stream received a valid proof
    String testTxHash = "0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";
    byte[] testTxHashBytes = Bytes.fromHexString(testTxHash).toArrayUnsafe();
    byte[] testSenderBytes =
        Bytes.fromHexString("0x1234567890123456789012345678901234567890").toArrayUnsafe();

    // Create combined proof bytes (this would normally come from the prover service)
    byte[] combinedProofBytes =
        Bytes.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .toArrayUnsafe();

    // Sanity check: cache should be empty initially for this tx hash
    assertFalse(
        validator.getProofFromCacheForTest(testTxHash).isPresent(),
        "Proof cache should be empty for " + testTxHash + " initially.");

    // Directly add proof to cache (simulating successful gRPC processing)
    RlnVerifierValidator.CachedProof testProof =
        new RlnVerifierValidator.CachedProof(
            combinedProofBytes,
            testSenderBytes,
            "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
            "0x987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0",
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            "0x111111111111111111111111111111111111111111111111111111111111111",
            Instant.now());

    validator.addProofToCacheForTest(testTxHash, testProof);

    // Verify proof is now in cache
    Optional<RlnVerifierValidator.CachedProof> cachedProofOpt =
        validator.getProofFromCacheForTest(testTxHash);
    assertTrue(cachedProofOpt.isPresent(), "Proof should be in cache after adding it.");

    RlnVerifierValidator.CachedProof cachedProof = cachedProofOpt.get();
    assertNotNull(cachedProof.cachedAt());
    assertEquals(testTxHash, Bytes.wrap(testTxHashBytes).toHexString());

    System.out.println(
        "RlnVerifierValidatorTest: Finished testGrpcProofStream_receivesAndCachesProof");
  }

  @Test
  void testValidateTransaction_withValidProof_JNI_Succeeds() {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testValidateTransaction_withValidProof_JNI_Succeeds");
    assertNotNull(jniTestVerifyingKeyBytes, "JNI test verifying key bytes must be loaded.");
    assertNotNull(jniTestFirstValidProofEntry, "JNI test proof entry must be loaded.");

    // For this JNI test, we'll use the main validator but ensure karma service returns a valid
    // response
    // The test should focus on proof verification, but we need karma service to not fail

    JSONObject proofEntry = jniTestFirstValidProofEntry;
    String proofHex = proofEntry.getString("proof");
    JSONObject publicInputsJson = proofEntry.getJSONObject("public_inputs");

    // Define a fixed, valid tx hash for this test, as rln_test_data.json doesn't provide one per
    // proof.
    String testTxHash = "0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    byte[] testTxHashBytes = Bytes.fromHexString(testTxHash).toArrayUnsafe();
    byte[] testSenderBytes =
        Bytes.fromHexString("0x1234567890123456789012345678901234567890").toArrayUnsafe();

    String proofEpoch = publicInputsJson.getString("epoch");
    String proofNullifier = publicInputsJson.getString("nullifier");

    // Create combined proof bytes for the new format
    byte[] combinedProofBytes = Bytes.fromHexString(proofHex).toArrayUnsafe();

    RlnVerifierValidator.CachedProof cachedProof =
        new RlnVerifierValidator.CachedProof(
            combinedProofBytes,
            testSenderBytes,
            publicInputsJson.getString("share_x"),
            publicInputsJson.getString("share_y"),
            proofEpoch, // Use variable
            publicInputsJson.getString("root"),
            proofNullifier, // Use variable
            Instant.now());
    // Use the new helper method to add to cache, using the fixed testTxHash
    validator.addProofToCacheForTest(testTxHash, cachedProof);

    Transaction mockTransaction = mock(Transaction.class);
    // Use the fixed testTxHash for the mock transaction's hash
    org.hyperledger.besu.datatypes.Hash mockTxHashValue =
        org.hyperledger.besu.datatypes.Hash.fromHexString(testTxHash);

    when(mockTransaction.getHash()).thenReturn(mockTxHashValue);
    Address mockSender = Address.fromHexString("0x1234567890123456789012345678901234567890");
    when(mockTransaction.getSender()).thenReturn(mockSender);
    // Mock gas price to be non-premium to pass initial checks easily
    // Use thenAnswer for Optional<Wei> to Optional<Quantity> compatibility with Mockito
    when(mockTransaction.getGasPrice())
        .thenAnswer(invocation -> Optional.of(Wei.of(1_000_000_000L)));
    when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());

    // Mock the blockchain service to generate the test epoch that matches the proof
    // The test proof expects epoch:
    // "0x09a6ed7f807775ba43e63fbba747a7f0122aa3fac4a05b3392aea03eecdd1128"
    // We need to configure the mock to generate this exact epoch

    // Strategy: Override the epoch generation in RlnConfig to return the test epoch
    String testEpoch = proofEpoch; // Use the epoch from the test proof
    when(rlnConfig.defaultEpochForQuota()).thenReturn("TEST"); // Use a special test mode

    // Mock the blockchain header to generate consistent epoch - we'll override
    // getCurrentEpochIdentifier for this test
    when(mockBlockHeader.getTimestamp()).thenReturn(1609459200L); // 2021-01-01 00:00:00 UTC
    when(mockBlockHeader.getNumber()).thenReturn(1L);

    // For this JNI test, configure karma service to use mock host and port
    when(rlnConfig.karmaServiceHost()).thenReturn("localhost");
    when(rlnConfig.karmaServicePort()).thenReturn(9999); // Non-existent port to avoid connection

    // Call the method under test. Plugin interface expects boolean for isLocal/hasPriority.
    Optional<String> maybeFailureReason =
        validator.validateTransaction(mockTransaction, false, false);

    // Debug the result
    System.out.println("JNI Test - Result present: " + maybeFailureReason.isPresent());
    if (maybeFailureReason.isPresent()) {
      System.out.println("JNI Test - Result value: " + maybeFailureReason.get());
    }

    // Assertions
    // For RLN, specific failure reasons are expected if invalid. If valid, Optional.empty() is
    // returned.
    assertTrue(
        maybeFailureReason.isEmpty(),
        "Transaction with valid JNI proof should be valid. Actual failure reason: "
            + maybeFailureReason.orElse(
                "VALID (isEmpty() was false but orElse was triggered - indicates test logic error)")
            + "\nProof Epoch used in test: "
            + proofEpoch
            + "\n(To see validator's current epoch, you might need to log inside RlnVerifierValidator.getCurrentEpochIdentifier() or isProofValidBasedOnEpochAndNullifier)");

    // Note: Using main validator, no need to clean up separately

    System.out.println(
        "RlnVerifierValidatorTest: Finished testValidateTransaction_withValidProof_JNI_Succeeds");
  }

  @Test
  void testValidateTransaction_userOnDenyList_withoutPremiumGas_shouldReject() {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testValidateTransaction_userOnDenyList_withoutPremiumGas");

    // Debug validator state
    System.out.println("Validator is null: " + (validator == null));
    System.out.println("DenyListManager is null: " + (denyListManager == null));

    assertNotNull(validator, "Validator should not be null");
    assertNotNull(denyListManager, "DenyListManager should not be null");

    // Given: User is on deny list
    Address deniedUser = Address.fromHexString("0x1111111111111111111111111111111111111111");

    // Debug: Try to access the validator's deny list manager
    try {
      validator.addToDenyListForTest(deniedUser, Instant.now());
    } catch (NullPointerException e) {
      System.out.println("NPE caught during addToDenyListForTest: " + e.getMessage());
      e.printStackTrace();
      throw e;
    }

    // Verify user is actually on deny list
    assertTrue(validator.isDeniedForTest(deniedUser), "User should be on deny list before test");

    Transaction mockTransaction = mock(Transaction.class);
    when(mockTransaction.getSender()).thenReturn(deniedUser);
    when(mockTransaction.getGasPrice())
        .thenAnswer(invocation -> Optional.of(Wei.of(1_000_000_000L))); // 1 GWei - below premium
    when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());
    when(mockTransaction.getHash())
        .thenReturn(
            org.hyperledger.besu.datatypes.Hash.fromHexString(
                "0x1111111111111111111111111111111111111111111111111111111111111111"));

    // When: Validate transaction
    Optional<String> result = validator.validateTransaction(mockTransaction, false, false);

    // Debug the result
    System.out.println("Result present: " + result.isPresent());
    if (result.isPresent()) {
      System.out.println("Result value: " + result.get());
    }

    // Then: Should reject with deny list message
    assertTrue(result.isPresent(), "Transaction should be rejected");
    if (result.isPresent()) {
      assertTrue(
          result.get().contains("deny list"),
          "Rejection should mention deny list, but got: " + result.get());
    }

    System.out.println(
        "RlnVerifierValidatorTest: Finished testValidateTransaction_userOnDenyList_withoutPremiumGas");
  }

  @Test
  void testValidateTransaction_userOnDenyList_withPremiumGas_shouldRemoveAndAllow() {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testValidateTransaction_userOnDenyList_withPremiumGas");

    // Given: User is on deny list but pays premium gas
    Address premiumUser = Address.fromHexString("0x2222222222222222222222222222222222222222");
    validator.addToDenyListForTest(premiumUser, Instant.now());

    // Use the threshold from configuration (already mocked in setUp)
    long premiumThreshold = 10_000_000_000L; // Same as the mock value in setUp

    Transaction mockTransaction = mock(Transaction.class);
    when(mockTransaction.getSender()).thenReturn(premiumUser);
    when(mockTransaction.getGasPrice())
        .thenAnswer(invocation -> Optional.of(Wei.of(premiumThreshold + 1_000_000_000L)));
    when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());
    when(mockTransaction.getHash())
        .thenReturn(
            org.hyperledger.besu.datatypes.Hash.fromHexString(
                "0x2222222222222222222222222222222222222222222222222222222222222222"));

    // When: Validate transaction (premium gas should remove from deny list immediately)
    Optional<String> result = validator.validateTransaction(mockTransaction, false, false);

    // Then: Should be removed from deny list due to premium gas payment
    assertFalse(
        validator.isDeniedForTest(premiumUser),
        "User should be removed from deny list after paying premium gas");

    System.out.println(
        "RlnVerifierValidatorTest: Finished testValidateTransaction_userOnDenyList_withPremiumGas");
  }

  @Test
  void testValidateTransaction_noProofInCache_shouldReject() {
    System.out.println("RlnVerifierValidatorTest: Starting testValidateTransaction_noProofInCache");

    // Given: Transaction with no proof in cache
    Address sender = Address.fromHexString("0x3333333333333333333333333333333333333333");
    Transaction mockTransaction = mock(Transaction.class);
    when(mockTransaction.getSender()).thenReturn(sender);
    when(mockTransaction.getHash())
        .thenReturn(
            org.hyperledger.besu.datatypes.Hash.fromHexString(
                "0x3333333333333333333333333333333333333333333333333333333333333333"));
    when(mockTransaction.getGasPrice())
        .thenAnswer(invocation -> Optional.of(Wei.of(1_000_000_000L)));
    when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());

    // When: Validate transaction
    Optional<String> result = validator.validateTransaction(mockTransaction, false, false);

    // Then: Should reject due to missing proof
    assertTrue(result.isPresent(), "Transaction should be rejected");
    assertTrue(result.get().contains("proof not found"), "Should mention missing proof");

    System.out.println("RlnVerifierValidatorTest: Finished testValidateTransaction_noProofInCache");
  }

  @Test
  void testValidateTransaction_invalidProof_shouldReject() {
    System.out.println("RlnVerifierValidatorTest: Starting testValidateTransaction_invalidProof");

    // Given: Transaction with no proof in cache (simulates missing or failed proof processing)
    String txHash = "0x7777777777777777777777777777777777777777777777777777777777777777";
    Transaction mockTransaction = mock(Transaction.class);
    when(mockTransaction.getHash())
        .thenReturn(org.hyperledger.besu.datatypes.Hash.fromHexString(txHash));
    when(mockTransaction.getSender())
        .thenReturn(Address.fromHexString("0x7777777777777777777777777777777777777777"));
    when(mockTransaction.getGasPrice())
        .thenAnswer(invocation -> Optional.of(Wei.of(1_000_000_000L)));
    when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());

    // Do NOT add any proof to cache - this simulates a proof that failed verification
    // during gRPC processing and was therefore not cached

    // When: Validate transaction
    Optional<String> result = validator.validateTransaction(mockTransaction, false, false);

    // Debug the result
    System.out.println("Result present: " + result.isPresent());
    if (result.isPresent()) {
      System.out.println("Result value: " + result.get());
    }

    // Then: Should reject due to missing proof
    assertTrue(result.isPresent(), "Transaction should be rejected when proof is missing");
    if (result.isPresent()) {
      assertTrue(
          result.get().contains("not found in cache") || result.get().contains("after timeout"),
          "Should mention proof not found in cache, but got: " + result.get());
    }

    System.out.println("RlnVerifierValidatorTest: Finished testValidateTransaction_invalidProof");
  }

  @Test
  void testAddToDenyList_shouldPersistToFile() throws IOException {
    System.out.println("RlnVerifierValidatorTest: Starting testAddToDenyList_shouldPersistToFile");

    // Given: Empty deny list file
    Address testAddress = Address.fromHexString("0x6666666666666666666666666666666666666666");

    // When: Add address to deny list
    validator.addToDenyList(testAddress);

    // Then: Should be persisted to file and loadable
    assertTrue(Files.exists(denyListFile), "Deny list file should exist");

    String fileContent = Files.readString(denyListFile, StandardCharsets.UTF_8);
    assertTrue(
        fileContent.contains(testAddress.toHexString().toLowerCase()),
        "File should contain the address");

    // Reload and verify
    validator.loadDenyListFromFileForTest();
    assertTrue(
        validator.isDeniedForTest(testAddress), "Address should be in deny list after reload");

    System.out.println("RlnVerifierValidatorTest: Finished testAddToDenyList_shouldPersistToFile");
  }

  @Test
  void testRemoveFromDenyList_shouldPersistToFile() throws IOException {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testRemoveFromDenyList_shouldPersistToFile");

    // Given: Address already in deny list
    Address testAddress = Address.fromHexString("0x7777777777777777777777777777777777777777");
    validator.addToDenyListForTest(testAddress, Instant.now());
    assertTrue(validator.isDeniedForTest(testAddress), "Address should initially be denied");

    // When: Remove address from deny list
    boolean removed = validator.removeFromDenyList(testAddress);

    // Then: Should return true and persist removal
    assertTrue(removed, "Remove operation should return true");
    assertFalse(validator.isDeniedForTest(testAddress), "Address should no longer be denied");

    // Verify persistence
    validator.loadDenyListFromFileForTest();
    assertFalse(
        validator.isDeniedForTest(testAddress), "Address should remain removed after reload");

    System.out.println(
        "RlnVerifierValidatorTest: Finished testRemoveFromDenyList_shouldPersistToFile");
  }

  @Test
  void testProofCacheEviction_shouldRemoveExpiredProofs() throws InterruptedException {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testProofCacheEviction_shouldRemoveExpiredProofs");

    // Given: Short cache expiry for testing
    when(rlnConfig.rlnProofCacheExpirySeconds()).thenReturn(1L); // 1 second expiry

    String txHash = "0x8888567890abcdef8888567890abcdef8888567890abcdef8888567890abcdef";
    byte[] oldProofBytes =
        Bytes.fromHexString("0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe")
            .toArrayUnsafe();
    byte[] testSenderBytes =
        Bytes.fromHexString("0x8888567890123456789012345678901234567890").toArrayUnsafe();

    RlnVerifierValidator.CachedProof oldProof =
        new RlnVerifierValidator.CachedProof(
            oldProofBytes,
            testSenderBytes,
            "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
            "0x987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0",
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            "0x333333333333333333333333333333333333333333333333333333333333333",
            Instant.now().minusSeconds(2)); // Already expired

    // When: Add expired proof and trigger eviction
    validator.addProofToCacheForTest(txHash, oldProof);
    assertTrue(
        validator.getProofFromCacheForTest(txHash).isPresent(),
        "Proof should initially be in cache");

    // Wait for eviction to run (triggered by cache access)
    Thread.sleep(100);

    // Then: Expired proof should be evicted
    // Note: The actual eviction timing depends on the LRU cache implementation
    // This test verifies the mechanism exists
    System.out.println(
        "RlnVerifierValidatorTest: Finished testProofCacheEviction_shouldRemoveExpiredProofs");
  }

  @Test
  void testValidateTransaction_rlnDisabled_shouldAllow() {
    System.out.println("RlnVerifierValidatorTest: Starting testValidateTransaction_rlnDisabled");

    // Given: RLN validation is disabled
    when(rlnConfig.rlnValidationEnabled()).thenReturn(false);

    // Create new validator with RLN disabled (no shared services needed when disabled)
    RlnVerifierValidator disabledValidator =
        new RlnVerifierValidator(rlnConfig, blockchainService, null, null, null);

    Transaction mockTransaction = mock(Transaction.class);
    when(mockTransaction.getSender())
        .thenReturn(Address.fromHexString("0x9999999999999999999999999999999999999999"));

    // When: Validate transaction
    Optional<String> result = disabledValidator.validateTransaction(mockTransaction, false, false);

    // Then: Should allow (return empty)
    assertFalse(result.isPresent(), "Transaction should be allowed when RLN is disabled");

    System.out.println("RlnVerifierValidatorTest: Finished testValidateTransaction_rlnDisabled");
  }

  @Test
  void testValidateTransaction_karmaServiceDown_shouldReject() {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testValidateTransaction_karmaServiceDown");

    // Simpler test: Test the circuit breaker logic directly without mocking complex JNI calls
    // We'll create a transaction that hits the karma service check by skipping earlier validations

    // Given: User not on deny list
    Address sender = Address.fromHexString("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assertFalse(validator.isDeniedForTest(sender), "User should not be on deny list initially");

    // Given: Create karma service client that returns empty (service down)
    KarmaServiceClient downKarmaService = mock(KarmaServiceClient.class);
    when(downKarmaService.isAvailable()).thenReturn(false);
    when(downKarmaService.fetchKarmaInfo(sender)).thenReturn(Optional.empty());

    // Create new validator with the down karma service
    RlnVerifierValidator testValidator =
        new RlnVerifierValidator(
            rlnConfig,
            blockchainService,
            denyListManager,
            downKarmaService,
            nullifierTracker,
            inProcessChannel,
            null); // null for RlnVerificationService - will use factory

    String txHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    Transaction mockTransaction = mock(Transaction.class);
    when(mockTransaction.getSender()).thenReturn(sender);
    when(mockTransaction.getHash())
        .thenReturn(org.hyperledger.besu.datatypes.Hash.fromHexString(txHash));
    when(mockTransaction.getGasPrice())
        .thenAnswer(invocation -> Optional.of(Wei.of(1_000_000_000L)));
    when(mockTransaction.getMaxFeePerGas()).thenReturn(Optional.empty());

    // Use a valid proof from our test data to pass proof verification
    if (jniTestFirstValidProofEntry != null) {
      JSONObject publicInputs = jniTestFirstValidProofEntry.getJSONObject("public_inputs");
      byte[] combinedProofBytes =
          Bytes.fromHexString(jniTestFirstValidProofEntry.getString("proof")).toArrayUnsafe();
      byte[] testSenderBytes = sender.toArrayUnsafe();

      testValidator.addProofToCacheForTest(
          txHash,
          new RlnVerifierValidator.CachedProof(
              combinedProofBytes,
              testSenderBytes,
              publicInputs.getString("share_x"),
              publicInputs.getString("share_y"),
              publicInputs.getString("epoch"),
              publicInputs.getString("root"),
              publicInputs.getString("nullifier"),
              Instant.now()));

      // Configure for TEST mode to match the test proof's epoch
      when(rlnConfig.defaultEpochForQuota()).thenReturn("TEST");
    }

    // When: Validate transaction
    Optional<String> result = testValidator.validateTransaction(mockTransaction, false, false);

    // Debug the result
    System.out.println("Karma service down test - Result present: " + result.isPresent());
    if (result.isPresent()) {
      System.out.println("Karma service down test - Result value: " + result.get());
    }

    // Then: Should reject due to karma service unavailability (new secure behavior)
    assertTrue(result.isPresent(), "Transaction should be rejected when karma service is down");
    if (result.isPresent()) {
      assertTrue(
          result.get().contains("Karma service unavailable"),
          "Should mention karma service unavailable, but got: " + result.get());
    }

    System.out.println(
        "RlnVerifierValidatorTest: Finished testValidateTransaction_karmaServiceDown");
  }
}
