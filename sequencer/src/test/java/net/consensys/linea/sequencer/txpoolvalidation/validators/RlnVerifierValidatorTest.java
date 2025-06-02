package net.consensys.linea.sequencer.txpoolvalidation.validators;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.io.InputStream;
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
import net.consensys.linea.rln.proofs.grpc.ProofMessage;
import net.consensys.linea.rln.proofs.grpc.RlnProofServiceGrpc;
import net.consensys.linea.rln.proofs.grpc.StreamProofsRequest;
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
  private Path actualVkPath; // For storing real VK for JNI test
  private MockedStatic<RlnBridge> mockedRlnBridge;

  // For JNI Test Data
  private static byte[] jniTestVerifyingKeyBytes;
  private static JSONObject jniTestFirstValidProofEntry;

  //

  // Define a nested class for the mock service implementation
  private static class MockProofServiceImpl extends RlnProofServiceGrpc.RlnProofServiceImplBase {
    private StreamObserver<ProofMessage> responseObserver; // To send messages to client
    private String clientId; // Store client ID for logging/debugging

    @Override
    public void streamProofs(
        StreamProofsRequest request, StreamObserver<ProofMessage> responseObserver) {
      this.clientId = request.getClientId();
      LOG.info("MockProofService: streamProofs called by client: {}", this.clientId);
      this.responseObserver = responseObserver;
      // Keep the stream open, send messages on demand from tests
    }

    // Test helper to send a proof message
    public void sendProof(ProofMessage proof) {
      if (this.responseObserver != null) {
        LOG.info(
            "MockProofService (client: {}): Sending proof for txHash: {}",
            this.clientId,
            proof.getTxHash());
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
    lenient()
        .when(rlnConfig.karmaServiceUrl())
        .thenReturn(Optional.of("http://localhost:7777/karma-test"));
    lenient().when(rlnConfig.rlnProofLocalWaitTimeoutMs()).thenReturn(500L);
    lenient().when(rlnConfig.rlnProofCacheMaxSize()).thenReturn(1000L);
    lenient().when(rlnConfig.rlnProofCacheExpirySeconds()).thenReturn(300L);
    lenient().when(rlnConfig.rlnProofServiceUseTls()).thenReturn(false);
    lenient().when(rlnConfig.rlnProofStreamRetryIntervalMs()).thenReturn(5000L);
    lenient().when(rlnConfig.defaultEpochForQuota()).thenReturn("TIMESTAMP_1H");
    lenient().when(rlnConfig.premiumGasPriceThresholdWei()).thenReturn(10_000_000_000L);
    lenient()
        .when(rlnConfig.denyListEntryMaxAgeMinutes())
        .thenReturn(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES);

    lenient().when(sharedGaslessConfig.denyListPath()).thenReturn(denyListFile.toString());
    lenient().when(sharedGaslessConfig.denyListRefreshSeconds()).thenReturn(0L);
    lenient()
        .when(sharedGaslessConfig.denyListEntryMaxAgeMinutes())
        .thenReturn(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES);
    lenient().when(sharedGaslessConfig.premiumGasPriceThresholdGWei()).thenReturn(10L);

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

    RlnVerifierValidator tempValidator = null;
    try {
      tempValidator = new RlnVerifierValidator(rlnConfig, blockchainService, inProcessChannel);
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

    String testTxHash = "0xtest_tx_hash_grpc";
    ProofMessage proofMsg =
        ProofMessage.newBuilder()
            .setTxHash(testTxHash)
            .setProofBytesHex("0x1234proof")
            .setShareXHex("0xshareX")
            .setShareYHex("0xshareY")
            .setEpochHex("0xepoch")
            .setRootHex("0xroot")
            .setNullifierHex("0xnullifier")
            .build();

    // Sanity check: cache should be empty initially for this tx hash
    assertFalse(
        validator.getProofFromCacheForTest(testTxHash).isPresent(),
        "Proof cache should be empty for " + testTxHash + " initially.");

    // Simulate server sending a proof
    mockProofService.sendProof(proofMsg);

    // Give a moment for the StreamObserver in the validator to process the message
    // Awaitility would be better here, but a short sleep is simpler for now if it works.
    Thread.sleep(200); // Adjust if needed, or use Awaitility for robustness

    Optional<RlnVerifierValidator.CachedProof> cachedProofOpt =
        validator.getProofFromCacheForTest(testTxHash);
    assertTrue(
        cachedProofOpt.isPresent(),
        "Proof should be in cache after server sends it via gRPC stream.");

    RlnVerifierValidator.CachedProof cachedProof = cachedProofOpt.get();
    assertEquals(proofMsg.getProofBytesHex(), cachedProof.proofBytesHex());
    assertEquals(proofMsg.getShareXHex(), cachedProof.shareXHex());
    assertEquals(proofMsg.getNullifierHex(), cachedProof.nullifierHex());
    assertNotNull(cachedProof.cachedAt());

    System.out.println(
        "RlnVerifierValidatorTest: Finished testGrpcProofStream_receivesAndCachesProof");
  }

  @Test
  void testValidateTransaction_withValidProof_JNI_Succeeds() {
    System.out.println(
        "RlnVerifierValidatorTest: Starting testValidateTransaction_withValidProof_JNI_Succeeds");
    assertNotNull(validator, "Validator should be initialized by setUp.");
    assertNotNull(jniTestVerifyingKeyBytes, "JNI test verifying key bytes must be loaded.");
    assertNotNull(jniTestFirstValidProofEntry, "JNI test proof entry must be loaded.");

    JSONObject proofEntry = jniTestFirstValidProofEntry;
    String proofHex = proofEntry.getString("proof");
    JSONObject publicInputsJson = proofEntry.getJSONObject("public_inputs");

    // Define a fixed, valid tx hash for this test, as rln_test_data.json doesn't provide one per
    // proof.
    String testTxHash = "0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    String proofEpoch = publicInputsJson.getString("epoch");
    String proofNullifier = publicInputsJson.getString("nullifier");

    RlnVerifierValidator.CachedProof cachedProof =
        new RlnVerifierValidator.CachedProof(
            proofHex,
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

    // Epoch: Mock defaultEpochForQuota on rlnConfig. RlnVerifierValidator uses this.
    when(rlnConfig.defaultEpochForQuota()).thenReturn(proofEpoch);

    // For this JNI test, disable Karma service interaction to isolate JNI proof validation
    when(rlnConfig.karmaServiceUrl()).thenReturn(Optional.empty());

    // Call the method under test. Plugin interface expects boolean for isLocal/hasPriority.
    Optional<String> maybeFailureReason =
        validator.validateTransaction(mockTransaction, false, false);

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

    System.out.println(
        "RlnVerifierValidatorTest: Finished testValidateTransaction_withValidProof_JNI_Succeeds");
  }
}
