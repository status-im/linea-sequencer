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
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import net.consensys.linea.sequencer.txpoolvalidation.shared.KarmaServiceClient.KarmaInfo;
import net.vac.prover.GetUserTierInfoReply;
import net.vac.prover.GetUserTierInfoRequest;
import net.vac.prover.RlnProverGrpc;
import net.vac.prover.Tier;
import net.vac.prover.UserTierInfoError;
import net.vac.prover.UserTierInfoResult;
import org.hyperledger.besu.datatypes.Address;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unit tests for KarmaServiceClient.
 *
 * <p>Tests the shared gRPC client functionality including connection management, error handling,
 * and proper resource cleanup.
 */
@ExtendWith(MockitoExtension.class)
class KarmaServiceClientTest {

  private static final Logger LOG = LoggerFactory.getLogger(KarmaServiceClientTest.class);

  private static class MockRlnProverImpl extends RlnProverGrpc.RlnProverImplBase {
    private boolean shouldTimeout = false;
    private boolean shouldThrowNotFound = false;
    private boolean shouldThrowError = false;
    private GetUserTierInfoReply responseToReturn;

    public void setShouldTimeout(boolean shouldTimeout) {
      this.shouldTimeout = shouldTimeout;
    }

    public void setShouldThrowNotFound(boolean shouldThrowNotFound) {
      this.shouldThrowNotFound = shouldThrowNotFound;
    }

    public void setShouldThrowError(boolean shouldThrowError) {
      this.shouldThrowError = shouldThrowError;
    }

    public void setResponseToReturn(GetUserTierInfoReply response) {
      this.responseToReturn = response;
    }

    @Override
    public void getUserTierInfo(
        GetUserTierInfoRequest request, StreamObserver<GetUserTierInfoReply> responseObserver) {
      if (shouldTimeout) {
        // Simulate timeout by delaying longer than client timeout
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
        responseObserver.onError(Status.DEADLINE_EXCEEDED.asRuntimeException());
        return;
      }

      if (shouldThrowNotFound) {
        responseObserver.onError(Status.NOT_FOUND.asRuntimeException());
        return;
      }

      if (shouldThrowError) {
        responseObserver.onError(
            Status.INTERNAL.withDescription("Internal server error").asRuntimeException());
        return;
      }

      if (responseToReturn != null) {
        responseObserver.onNext(responseToReturn);
        responseObserver.onCompleted();
      } else {
        responseObserver.onError(
            Status.INTERNAL.withDescription("No response configured").asRuntimeException());
      }
    }
  }

  private MockRlnProverImpl mockRlnProver;
  private Server mockServer;
  private ManagedChannel inProcessChannel;
  private KarmaServiceClient karmaServiceClient;

  @BeforeEach
  void setUp() throws IOException {
    mockRlnProver = new MockRlnProverImpl();

    String serverName = InProcessServerBuilder.generateName();

    mockServer =
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(mockRlnProver)
            .build()
            .start();

    inProcessChannel =
        InProcessChannelBuilder.forName(serverName).usePlaintext().directExecutor().build();
  }

  @AfterEach
  void tearDown() throws IOException {
    if (karmaServiceClient != null) {
      karmaServiceClient.close();
      karmaServiceClient = null;
    }

    if (inProcessChannel != null) {
      inProcessChannel.shutdownNow();
      try {
        if (!inProcessChannel.awaitTermination(5, TimeUnit.SECONDS)) {
          LOG.warn("In-process channel did not terminate in time.");
        }
      } catch (InterruptedException e) {
        LOG.warn("In-process channel shutdown interrupted.", e);
        Thread.currentThread().interrupt();
      }
      inProcessChannel = null;
    }

    if (mockServer != null) {
      mockServer.shutdownNow();
      try {
        if (!mockServer.awaitTermination(5, TimeUnit.SECONDS)) {
          LOG.warn("Mock gRPC server did not terminate in time.");
        }
      } catch (InterruptedException e) {
        LOG.warn("gRPC server shutdown interrupted.", e);
        Thread.currentThread().interrupt();
      }
      mockServer = null;
    }
  }

  @Test
  void testSuccessfulKarmaFetch() {
    // Given: Mock service returns valid user tier info response
    Tier tier = Tier.newBuilder().setName("Active").setQuota(120L).build();

    UserTierInfoResult result =
        UserTierInfoResult.newBuilder()
            .setCurrentEpoch(1234567L)
            .setCurrentEpochSlice(10L)
            .setTxCount(5L)
            .setTier(tier)
            .build();

    GetUserTierInfoReply response = GetUserTierInfoReply.newBuilder().setRes(result).build();

    mockRlnProver.setResponseToReturn(response);

    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // When: Fetch karma info
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    Optional<KarmaInfo> karmaResult = karmaServiceClient.fetchKarmaInfo(testAddress);

    // Then: Should return karma info
    assertTrue(karmaResult.isPresent());
    KarmaInfo karmaInfo = karmaResult.get();
    assertEquals("Active", karmaInfo.tier());
    assertEquals(5, karmaInfo.epochTxCount());
    assertEquals(120, karmaInfo.dailyQuota());
    assertEquals("1234567", karmaInfo.epochId()); // epoch converted to string
    assertEquals(0L, karmaInfo.karmaBalance()); // karma balance set to 0 in new schema
  }

  @Test
  void testUserNotFound() {
    // Given: Service returns NOT_FOUND
    mockRlnProver.setShouldThrowNotFound(true);

    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // When: Fetch karma info for non-existent user
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    Optional<KarmaInfo> result = karmaServiceClient.fetchKarmaInfo(testAddress);

    // Then: Should return empty
    assertFalse(result.isPresent());
  }

  @Test
  void testServiceTimeout() {
    // Given: Service causes timeout
    mockRlnProver.setShouldTimeout(true);

    karmaServiceClient =
        new KarmaServiceClient(
            "TestClient", "localhost", 8080, false, 100L, inProcessChannel); // Short timeout

    // When: Fetch karma info
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    Optional<KarmaInfo> result = karmaServiceClient.fetchKarmaInfo(testAddress);

    // Then: Should return empty due to timeout
    assertFalse(result.isPresent());
  }

  @Test
  void testServiceError() {
    // Given: Service returns error response in oneof
    UserTierInfoError error =
        UserTierInfoError.newBuilder().setMessage("User not registered").build();

    GetUserTierInfoReply response = GetUserTierInfoReply.newBuilder().setError(error).build();

    mockRlnProver.setResponseToReturn(response);

    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // When: Fetch karma info
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    Optional<KarmaInfo> result = karmaServiceClient.fetchKarmaInfo(testAddress);

    // Then: Should return empty due to error
    assertFalse(result.isPresent());
  }

  @Test
  void testServiceGrpcError() {
    // Given: Service throws gRPC error
    mockRlnProver.setShouldThrowError(true);

    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // When: Fetch karma info
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    Optional<KarmaInfo> result = karmaServiceClient.fetchKarmaInfo(testAddress);

    // Then: Should return empty due to gRPC error
    assertFalse(result.isPresent());
  }

  @Test
  void testClientWithoutProvidedChannel() {
    // Given: Create client without pre-configured channel
    karmaServiceClient = new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L);

    // Then: Client should be available but not connected to our mock
    assertTrue(karmaServiceClient.isAvailable());
  }

  @Test
  void testClientAvailability() {
    // Given: Client with channel
    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // Then: Should be available
    assertTrue(karmaServiceClient.isAvailable());
  }

  @Test
  void testClientUnavailableAfterClose() throws IOException {
    // Given: Client with channel
    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // When: Close client
    karmaServiceClient.close();

    // Then: Should not be available
    assertFalse(karmaServiceClient.isAvailable());
  }

  @Test
  void testTlsConfiguration() {
    // Given: Create client with TLS enabled
    karmaServiceClient = new KarmaServiceClient("TestClient", "localhost", 8443, true, 500L);

    // Then: Client should be created successfully
    assertNotNull(karmaServiceClient);
    assertTrue(karmaServiceClient.isAvailable());
  }

  @Test
  void testClientWithShutdownChannel() {
    // Given: Shutdown channel first
    inProcessChannel.shutdown();

    // When: Create client with shutdown channel
    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // Then: Client should handle shutdown channel gracefully
    assertNotNull(karmaServiceClient);
  }

  @Test
  void testMultipleClose() throws IOException {
    // Given: Client with channel
    karmaServiceClient =
        new KarmaServiceClient("TestClient", "localhost", 8080, false, 500L, inProcessChannel);

    // When: Close multiple times
    karmaServiceClient.close();
    karmaServiceClient.close(); // Should not throw

    // Then: Should not be available
    assertFalse(karmaServiceClient.isAvailable());
  }
}
