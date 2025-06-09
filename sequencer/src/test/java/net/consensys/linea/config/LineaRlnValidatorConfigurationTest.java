/*
 * Copyright Consensys Software Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law-abiding or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package net.consensys.linea.config;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class LineaRlnValidatorConfigurationTest {

  private static final long DEFAULT_MAX_AGE_MINUTES =
      LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES;

  @Test
  void v1Default_shouldInitializeCorrectly() {
    LineaRlnValidatorConfiguration defaultConfig = LineaRlnValidatorConfiguration.V1_DEFAULT;

    assertFalse(defaultConfig.rlnValidationEnabled());
    assertEquals("/etc/linea/rln_verifying_key.bin", defaultConfig.verifyingKeyPath());
    assertEquals("localhost", defaultConfig.rlnProofServiceHost());
    assertEquals(50051, defaultConfig.rlnProofServicePort());
    assertFalse(defaultConfig.rlnProofServiceUseTls());
    assertEquals(10000L, defaultConfig.rlnProofCacheMaxSize());
    assertEquals(300L, defaultConfig.rlnProofCacheExpirySeconds());
    assertEquals(5, defaultConfig.rlnProofStreamRetries());
    assertEquals(5000L, defaultConfig.rlnProofStreamRetryIntervalMs());
    assertEquals(200L, defaultConfig.rlnProofLocalWaitTimeoutMs());
    assertNotNull(defaultConfig.sharedGaslessConfig());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_PATH, defaultConfig.denyListPath());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS,
        defaultConfig.denyListRefreshSeconds());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI * 1_000_000_000L,
        defaultConfig.premiumGasPriceThresholdWei());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES,
        defaultConfig.denyListEntryMaxAgeMinutes());
    assertEquals("localhost", defaultConfig.karmaServiceHost());
    assertEquals(50052, defaultConfig.karmaServicePort());
    assertFalse(defaultConfig.karmaServiceUseTls());
    assertEquals(5000L, defaultConfig.karmaServiceTimeoutMs());
    assertTrue(defaultConfig.exponentialBackoffEnabled());
    assertEquals(60000L, defaultConfig.maxBackoffDelayMs());
    assertEquals("TIMESTAMP_1H", defaultConfig.defaultEpochForQuota());
    assertEquals(Optional.empty(), defaultConfig.rlnJniLibPath());
  }

  @Test
  void constructor_withCustomSharedConfig_shouldUseIt() {
    String customPath = "/custom/deny.txt";
    long customRefreshSeconds = 600L;
    long customPremiumGwei = 50L;
    long customMaxAgeMinutes = 20L;

    LineaSharedGaslessConfiguration sharedConfig =
        new LineaSharedGaslessConfiguration(
            customPath, customRefreshSeconds, customPremiumGwei, customMaxAgeMinutes);

    LineaRlnValidatorConfiguration config =
        new LineaRlnValidatorConfiguration(
            true,
            "vk_path",
            "proof_host",
            12345,
            true,
            5000L,
            60L,
            3,
            2000L,
            100L,
            sharedConfig,
            "karma_host",
            8080,
            false,
            5000L,
            true,
            60000L,
            "TIMESTAMP_1H",
            Optional.of("/jni/path"));

    assertTrue(config.rlnValidationEnabled());
    assertEquals("vk_path", config.verifyingKeyPath());
    assertEquals("proof_host", config.rlnProofServiceHost());
    assertEquals(12345, config.rlnProofServicePort());
    assertTrue(config.rlnProofServiceUseTls());
    assertEquals(5000L, config.rlnProofCacheMaxSize());
    assertEquals(60L, config.rlnProofCacheExpirySeconds());
    assertEquals(3, config.rlnProofStreamRetries());
    assertEquals(2000L, config.rlnProofStreamRetryIntervalMs());
    assertEquals(100L, config.rlnProofLocalWaitTimeoutMs());
    assertSame(sharedConfig, config.sharedGaslessConfig());
    assertEquals(customPath, config.denyListPath());
    assertEquals(customRefreshSeconds, config.denyListRefreshSeconds());
    assertEquals(customPremiumGwei * 1_000_000_000L, config.premiumGasPriceThresholdWei());
    assertEquals(customMaxAgeMinutes, config.denyListEntryMaxAgeMinutes());
    assertEquals("karma_host", config.karmaServiceHost());
    assertEquals(8080, config.karmaServicePort());
    assertFalse(config.karmaServiceUseTls());
    assertEquals(5000L, config.karmaServiceTimeoutMs());
    assertTrue(config.exponentialBackoffEnabled());
    assertEquals(60000L, config.maxBackoffDelayMs());
    assertEquals("TIMESTAMP_1H", config.defaultEpochForQuota());
    assertEquals(Optional.of("/jni/path"), config.rlnJniLibPath());
  }

  @Test
  void denyListPath_accessor_shouldReturnPathFromSharedConfig() {
    String expectedPath = "/shared/path/to/deny.txt";
    long expectedRefresh = LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS;
    long expectedPremiumGwei =
        LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI;
    long expectedMaxAge = DEFAULT_MAX_AGE_MINUTES;

    LineaSharedGaslessConfiguration sharedConfig =
        new LineaSharedGaslessConfiguration(
            expectedPath, expectedRefresh, expectedPremiumGwei, expectedMaxAge);
    LineaRlnValidatorConfiguration config =
        new LineaRlnValidatorConfiguration(
            false,
            "",
            "host",
            0,
            false,
            0L,
            0L,
            0,
            0L,
            0L,
            sharedConfig,
            "localhost",
            50052,
            false,
            5000L,
            true,
            60000L,
            "",
            Optional.empty());
    assertEquals(expectedPath, config.denyListPath());
    assertEquals(expectedRefresh, config.denyListRefreshSeconds());
    assertEquals(expectedPremiumGwei * 1_000_000_000L, config.premiumGasPriceThresholdWei());
    assertEquals(expectedMaxAge, config.denyListEntryMaxAgeMinutes());
  }
}
