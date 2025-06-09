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
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import net.consensys.linea.rln.proofs.grpc.GetKarmaRequest;
import net.consensys.linea.rln.proofs.grpc.KarmaResponse;
import net.consensys.linea.rln.proofs.grpc.KarmaServiceGrpc;
import org.hyperledger.besu.datatypes.Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared gRPC client for Karma Service operations.
 *
 * <p>This client encapsulates all karma-related gRPC communication, including:
 *
 * <ul>
 *   <li>Channel management with proper TLS configuration
 *   <li>Request timeout handling
 *   <li>Comprehensive error handling for various gRPC failure scenarios
 *   <li>Resource cleanup and connection lifecycle management
 * </ul>
 *
 * <p>Used by both RLN validation and gas estimation components to avoid code duplication in karma
 * service interactions.
 *
 * @author Status Network Development Team
 * @since 1.0
 */
public class KarmaServiceClient implements Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(KarmaServiceClient.class);

  /**
   * Represents user karma information retrieved from the Karma Service.
   *
   * @param tier User's karma tier (e.g., "Basic", "Active", "Regular")
   * @param epochTxCount Number of transactions used in current epoch
   * @param dailyQuota Daily transaction quota for this tier
   * @param epochId Current epoch identifier from karma service
   * @param karmaBalance User's total karma balance
   */
  public record KarmaInfo(
      String tier, int epochTxCount, int dailyQuota, String epochId, long karmaBalance) {}

  private final String serviceName;
  private ManagedChannel channel;
  private KarmaServiceGrpc.KarmaServiceBlockingStub stub;

  /**
   * Creates a new Karma Service client with the specified configuration.
   *
   * @param serviceName Name for logging and identification purposes
   * @param host Karma service host
   * @param port Karma service port
   * @param useTls Whether to use TLS for the connection
   * @param timeoutMs Request timeout in milliseconds
   */
  public KarmaServiceClient(
      String serviceName, String host, int port, boolean useTls, long timeoutMs) {
    this(serviceName, host, port, useTls, timeoutMs, null);
  }

  /**
   * Creates a new Karma Service client with optional pre-configured channel.
   *
   * <p>This constructor is primarily intended for testing scenarios where mock gRPC channels need
   * to be injected.
   *
   * @param serviceName Name for logging and identification purposes
   * @param host Karma service host (ignored if providedChannel is not null)
   * @param port Karma service port (ignored if providedChannel is not null)
   * @param useTls Whether to use TLS (ignored if providedChannel is not null)
   * @param timeoutMs Request timeout in milliseconds
   * @param providedChannel Optional pre-configured channel for testing
   */
  public KarmaServiceClient(
      String serviceName,
      String host,
      int port,
      boolean useTls,
      long timeoutMs,
      ManagedChannel providedChannel) {
    this.serviceName = serviceName;

    if (providedChannel != null && !providedChannel.isShutdown()) {
      LOG.info("{}: Using pre-configured ManagedChannel for Karma Service client.", serviceName);
      this.channel = providedChannel;
    } else {
      LOG.info(
          "{}: Creating new ManagedChannel for Karma Service client at {}:{}",
          serviceName,
          host,
          port);
      ManagedChannelBuilder<?> channelBuilder = ManagedChannelBuilder.forAddress(host, port);

      if (useTls) {
        channelBuilder.useTransportSecurity();
      } else {
        channelBuilder.usePlaintext();
      }

      this.channel = channelBuilder.build();
    }

    this.stub =
        KarmaServiceGrpc.newBlockingStub(this.channel)
            .withDeadlineAfter(timeoutMs, TimeUnit.MILLISECONDS);

    LOG.info("{}: Karma Service client initialized successfully", serviceName);
  }

  /**
   * Fetches karma information for a user via gRPC Karma Service.
   *
   * <p>Retrieves current karma status including tier, quota, and usage information for the
   * specified user address. Includes proper error handling for gRPC failures and timeouts.
   *
   * @param userAddress The user address to query karma information for
   * @return Optional containing karma info if successful, empty on failure
   */
  public Optional<KarmaInfo> fetchKarmaInfo(Address userAddress) {
    if (stub == null) {
      LOG.warn("{}: Karma service not configured. Cannot fetch karma info.", serviceName);
      return Optional.empty();
    }

    GetKarmaRequest request =
        GetKarmaRequest.newBuilder().setUserAddress(userAddress.toHexString()).build();

    try {
      LOG.debug(
          "{}: Fetching karma info for user {} via gRPC", serviceName, userAddress.toHexString());
      KarmaResponse response = stub.getKarma(request);

      LOG.debug(
          "{}: Karma service response for {}: tier={}, epochTxCount={}, dailyQuota={}, epochId={}, karmaBalance={}",
          serviceName,
          userAddress.toHexString(),
          response.getTier(),
          response.getEpochTxCount(),
          response.getDailyQuota(),
          response.getEpochId(),
          response.getKarmaBalance());

      return Optional.of(
          new KarmaInfo(
              response.getTier(),
              response.getEpochTxCount(),
              response.getDailyQuota(),
              response.getEpochId(),
              response.getKarmaBalance()));

    } catch (StatusRuntimeException e) {
      Status.Code code = e.getStatus().getCode();
      if (code == Status.Code.NOT_FOUND) {
        LOG.debug("{}: User {} not found in karma service", serviceName, userAddress.toHexString());
        return Optional.empty();
      } else if (code == Status.Code.DEADLINE_EXCEEDED) {
        LOG.warn("{}: Karma service timeout for user {}", serviceName, userAddress.toHexString());
        return Optional.empty();
      } else {
        LOG.error(
            "{}: Karma service gRPC error for user {}: {}",
            serviceName,
            userAddress.toHexString(),
            e.getMessage(),
            e);
        return Optional.empty();
      }
    } catch (Exception e) {
      LOG.error(
          "{}: Unexpected error calling karma service for user {}: {}",
          serviceName,
          userAddress.toHexString(),
          e.getMessage(),
          e);
      return Optional.empty();
    }
  }

  /**
   * Checks if the karma service client is available and properly configured.
   *
   * @return true if the client is ready to make requests, false otherwise
   */
  public boolean isAvailable() {
    return channel != null && !channel.isShutdown() && stub != null;
  }

  /**
   * Closes the gRPC channel and releases all resources.
   *
   * <p>This method should be called when the client is no longer needed to prevent resource leaks.
   *
   * @throws IOException if there are issues during resource cleanup
   */
  @Override
  public void close() throws IOException {
    if (channel != null && !channel.isShutdown()) {
      LOG.info("{}: Shutting down Karma Service gRPC channel", serviceName);
      channel.shutdown();
      try {
        if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
          channel.shutdownNow();
        }
      } catch (InterruptedException e) {
        channel.shutdownNow();
        Thread.currentThread().interrupt();
      }
      LOG.info("{}: Karma Service gRPC channel shut down", serviceName);
    }
  }
}
