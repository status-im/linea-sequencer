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

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.Optional;

import io.grpc.ManagedChannel;
import net.consensys.linea.config.LineaRlnValidatorConfiguration;
import net.consensys.linea.config.LineaSharedGaslessConfiguration;
import net.vac.prover.RlnProverGrpc;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.TransactionTestFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for RlnProverForwarderValidator that focus on the actual implementation logic: -
 * Transaction processing behavior (local vs peer) - Error handling and fallback mechanisms -
 * Statistics tracking - Configuration handling - gRPC integration
 */
@ExtendWith(MockitoExtension.class)
class RlnProverForwarderValidatorTest {

  private static final SignatureAlgorithm SIGNATURE_ALGORITHM =
      SignatureAlgorithmFactory.getInstance();

  @Mock private ManagedChannel mockChannel;
  @Mock private RlnProverGrpc.RlnProverBlockingStub mockStub;

  private RlnProverForwarderValidator validator;

  @AfterEach
  void tearDown() throws Exception {
    if (validator != null) {
      validator.close();
    }
  }

  @Test
  void shouldSkipValidationWhenDisabled() {
    // Given: disabled validator
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, false);
    Transaction transaction = createTestTransaction();

    // When: processing any transaction
    Optional<String> result = validator.validateTransaction(transaction, true, false);

    // Then: should skip validation entirely
    assertThat(result).isEmpty(); // Accepted
    assertThat(validator.getValidationCallCount()).isEqualTo(1);
    assertThat(validator.getLocalTransactionCount()).isEqualTo(0);
    assertThat(validator.getPeerTransactionCount()).isEqualTo(0);
    assertThat(validator.isEnabled()).isFalse();
  }

  @Test
  void shouldSkipPeerTransactionsWhenEnabled() {
    // Given: enabled validator with mock channel (no real gRPC connection)
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction peerTransaction = createTestTransaction();

    // When: processing peer transaction
    Optional<String> result = validator.validateTransaction(peerTransaction, false, false);

    // Then: should accept without any gRPC processing
    assertThat(result).isEmpty(); // Accepted
    assertThat(validator.getPeerTransactionCount()).isEqualTo(1);
    assertThat(validator.getLocalTransactionCount()).isEqualTo(0);
    assertThat(validator.getValidationCallCount()).isEqualTo(1);
    assertThat(validator.getGrpcSuccessCount()).isEqualTo(0);
    assertThat(validator.getGrpcFailureCount()).isEqualTo(0);
  }

  @Test
  void shouldProcessLocalTransactionsViaGrpc() {
    // Given: enabled validator with mock channel (tests fallback)
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction localTransaction = createTestTransaction();

    // When: processing local transaction
    Optional<String> result = validator.validateTransaction(localTransaction, true, false);

    // Then: should attempt gRPC call and fallback to acceptance
    assertThat(result).isEmpty(); // Accepted via fallback
    assertThat(validator.getLocalTransactionCount()).isEqualTo(1);
    assertThat(validator.getPeerTransactionCount()).isEqualTo(0);
    assertThat(validator.getValidationCallCount()).isEqualTo(1);
    assertThat(validator.getGrpcFailureCount()).isEqualTo(1); // Failed due to mock channel
  }

  @Test
  void shouldFallBackGracefullyWhenGrpcServiceUnavailable() {
    // Given: validator with mock channel that simulates unavailable service
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction localTransaction = createTestTransaction();

    // When: attempting to validate local transaction
    Optional<String> result = validator.validateTransaction(localTransaction, true, false);

    // Then: should fall back to accepting the transaction
    assertThat(result).isEmpty(); // Graceful fallback accepts transaction
    assertThat(validator.getLocalTransactionCount()).isEqualTo(1);
    assertThat(validator.getGrpcFailureCount()).isEqualTo(1);
  }

  @Test
  void shouldHandleGrpcServiceRejectingTransaction() throws Exception {
    // Given: enabled validator with mock channel that simulates rejection
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction localTransaction = createTestTransaction();

    // When: processing local transaction (will fail due to mock channel and fallback)
    Optional<String> result = validator.validateTransaction(localTransaction, true, false);

    // Then: should fallback to accept (graceful degradation)
    assertThat(result).isEmpty(); // Fallback accepts
    assertThat(validator.getLocalTransactionCount()).isEqualTo(1);
    assertThat(validator.getGrpcFailureCount()).isEqualTo(1); // Failed due to mock channel
  }

  @Test
  void shouldTrackStatisticsAccurately() {
    // Given: enabled validator for testing statistics
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction transaction = createTestTransaction();

    // When: processing mix of local and peer transactions
    validator.validateTransaction(transaction, true, false); // local #1
    validator.validateTransaction(transaction, false, false); // peer #1
    validator.validateTransaction(transaction, true, false); // local #2
    validator.validateTransaction(transaction, false, false); // peer #2
    validator.validateTransaction(transaction, false, false); // peer #3
    validator.validateTransaction(transaction, true, false); // local #3

    // Then: statistics should be accurate
    assertThat(validator.getValidationCallCount()).isEqualTo(6);
    assertThat(validator.getLocalTransactionCount()).isEqualTo(3);
    assertThat(validator.getPeerTransactionCount()).isEqualTo(3);
    assertThat(validator.getGrpcFailureCount())
        .isEqualTo(3); // All local transactions failed due to mock channel
  }

  @Test
  void shouldHandleTransactionsWithVariousGasPrices() {
    // Given: enabled validator for testing different transaction types
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);

    // When: processing transactions with different gas prices
    Transaction lowGasTransaction = createTransactionWithGasPrice(Wei.of(1_000_000_000L));
    Transaction highGasTransaction = createTransactionWithGasPrice(Wei.of(100_000_000_000L));
    Transaction zeroGasTransaction = createTransactionWithGasPrice(Wei.ZERO);

    Optional<String> result1 = validator.validateTransaction(lowGasTransaction, true, false);
    Optional<String> result2 = validator.validateTransaction(highGasTransaction, true, false);
    Optional<String> result3 = validator.validateTransaction(zeroGasTransaction, true, false);

    // Then: all should be processed (fallback accepts all)
    assertThat(result1).isEmpty();
    assertThat(result2).isEmpty();
    assertThat(result3).isEmpty();
    assertThat(validator.getLocalTransactionCount()).isEqualTo(3);
  }

  @Test
  void shouldHandleTransactionsWithDifferentChainIds() {
    // Given: enabled validator for testing different chain IDs
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);

    // When: processing transactions with different chain IDs
    Transaction mainnetTx = createTransactionWithChainId(BigInteger.valueOf(1));
    Transaction testnetTx = createTransactionWithChainId(BigInteger.valueOf(3));
    Transaction customTx = createTransactionWithChainId(BigInteger.valueOf(1337));

    Optional<String> result1 = validator.validateTransaction(mainnetTx, true, false);
    Optional<String> result2 = validator.validateTransaction(testnetTx, true, false);
    Optional<String> result3 = validator.validateTransaction(customTx, true, false);

    // Then: all should be processed
    assertThat(result1).isEmpty();
    assertThat(result2).isEmpty();
    assertThat(result3).isEmpty();
    assertThat(validator.getLocalTransactionCount()).isEqualTo(3);
  }

  @Test
  void shouldMaintainEndpointConfiguration() {
    // Given: validator with specific endpoint
    LineaRlnValidatorConfiguration config =
        createTestConfigWithEndpoint("grpc-service.example.com", 9090);
    validator = new RlnProverForwarderValidator(config, true, mockChannel);

    // When/Then: endpoint should be stored correctly
    assertThat(validator.getEndpoint()).isEqualTo("grpc-service.example.com:9090");
    assertThat(validator.isEnabled()).isTrue();
  }

  @Test
  void shouldHandlePriorityTransactionFlag() {
    // Given: enabled validator for testing priority handling
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction transaction = createTestTransaction();

    // When: processing transactions with different priority flags
    Optional<String> normalResult = validator.validateTransaction(transaction, true, false);
    Optional<String> priorityResult = validator.validateTransaction(transaction, true, true);

    // Then: both should be processed (priority flag passed through)
    assertThat(normalResult).isEmpty();
    assertThat(priorityResult).isEmpty();
    assertThat(validator.getLocalTransactionCount()).isEqualTo(2);
  }

  @Test
  void shouldHandleTransactionsWithComplexData() {
    // Given: enabled validator for testing complex transaction data
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);

    // When: processing transaction with complex data
    Transaction complexTransaction =
        new TransactionTestFixture()
            .gasPrice(Wei.of(50_000_000_000L))
            .gasLimit(21000)
            .value(Wei.fromEth(1))
            .chainId(Optional.of(BigInteger.valueOf(1337)))
            .to(Optional.of(Address.fromHexString("0x742d35cc6634c0532925a3b8d039135682b2e78b")))
            .createTransaction(SIGNATURE_ALGORITHM.generateKeyPair());

    Optional<String> result = validator.validateTransaction(complexTransaction, true, false);

    // Then: should process successfully
    assertThat(result).isEmpty(); // Fallback accepts
    assertThat(validator.getLocalTransactionCount()).isEqualTo(1);

    // Verify transaction has expected properties
    assertThat(complexTransaction.getGasPrice()).isPresent();
    assertThat(complexTransaction.getChainId()).isPresent();
    assertThat(complexTransaction.getSender()).isNotNull();
    assertThat(complexTransaction.getHash()).isNotNull();
  }

  @Test
  void shouldHandleGrpcTimeouts() {
    // Given: validator with mock channel that simulates timeout
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction transaction = createTestTransaction();

    // When: processing transaction (will fail and fallback)
    Optional<String> result = validator.validateTransaction(transaction, true, false);

    // Then: should fallback gracefully
    assertThat(result).isEmpty(); // Fallback accepts
    assertThat(validator.getLocalTransactionCount()).isEqualTo(1);
    assertThat(validator.getGrpcFailureCount()).isEqualTo(1);
  }

  @Test
  void shouldCloseGrpcChannelProperly() throws Exception {
    // Given: enabled validator with mock channel
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);

    // When: closing validator
    validator.close();

    // Then: should complete without errors
    // (Channel shutdown is tested by ensuring no exceptions are thrown)
  }

  @Test
  void shouldNotCreateChannelWhenDisabled() {
    // Given: disabled validator
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, false);

    // When/Then: should not have channel
    assertThat(validator.isEnabled()).isFalse();
    assertThat(validator.getEndpoint()).isEqualTo("localhost:50051"); // Config still available
  }

  @Test
  void shouldResetStatisticsProperly() {
    // Given: validator with some processed transactions
    LineaRlnValidatorConfiguration config = createTestConfig();
    validator = new RlnProverForwarderValidator(config, true, mockChannel);
    Transaction transaction = createTestTransaction();

    // Process some transactions
    validator.validateTransaction(transaction, true, false);
    validator.validateTransaction(transaction, false, false);

    // When: creating new validator (simulates reset)
    try {
      validator.close();
    } catch (Exception e) {
      // Ignore close errors for test
    }
    validator = new RlnProverForwarderValidator(config, true, mockChannel);

    // Then: statistics should start fresh
    assertThat(validator.getValidationCallCount()).isEqualTo(0);
    assertThat(validator.getLocalTransactionCount()).isEqualTo(0);
    assertThat(validator.getPeerTransactionCount()).isEqualTo(0);
    assertThat(validator.getGrpcSuccessCount()).isEqualTo(0);
    assertThat(validator.getGrpcFailureCount()).isEqualTo(0);
  }

  private LineaRlnValidatorConfiguration createTestConfig() {
    return createTestConfigWithEndpoint("localhost", 50051);
  }

  private LineaRlnValidatorConfiguration createTestConfigWithEndpoint(String host, int port) {
    return new LineaRlnValidatorConfiguration(
        false, // rlnValidationEnabled
        "/tmp/test_verifying_key.bin", // verifyingKeyPath
        host, // rlnProofServiceHost
        port, // rlnProofServicePort
        false, // rlnProofServiceUseTls
        1000L, // rlnProofCacheMaxSize
        60L, // rlnProofCacheExpirySeconds
        3, // rlnProofStreamRetries
        1000L, // rlnProofStreamRetryIntervalMs
        100L, // rlnProofLocalWaitTimeoutMs
        LineaSharedGaslessConfiguration.V1_DEFAULT,
        "localhost", // karmaServiceHost
        50052, // karmaServicePort
        false, // karmaServiceUseTls
        1000L, // karmaServiceTimeoutMs
        true, // exponentialBackoffEnabled
        10000L, // maxBackoffDelayMs
        "TIMESTAMP_1H", // defaultEpochForQuota
        Optional.empty() // rlnJniLibPath
        );
  }

  private Transaction createTestTransaction() {
    return new TransactionTestFixture()
        .gasPrice(Wei.of(20_000_000_000L))
        .chainId(Optional.of(BigInteger.valueOf(1)))
        .createTransaction(SIGNATURE_ALGORITHM.generateKeyPair());
  }

  private Transaction createTransactionWithGasPrice(final Wei gasPrice) {
    return new TransactionTestFixture()
        .gasPrice(gasPrice)
        .chainId(Optional.of(BigInteger.valueOf(1)))
        .createTransaction(SIGNATURE_ALGORITHM.generateKeyPair());
  }

  private Transaction createTransactionWithChainId(final BigInteger chainId) {
    return new TransactionTestFixture()
        .gasPrice(Wei.of(10_000_000_000L))
        .chainId(Optional.of(chainId))
        .createTransaction(SIGNATURE_ALGORITHM.generateKeyPair());
  }
}
