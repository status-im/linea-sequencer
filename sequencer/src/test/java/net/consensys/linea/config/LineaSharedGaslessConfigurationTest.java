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
package net.consensys.linea.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class LineaSharedGaslessConfigurationTest {

  private static final long DEFAULT_REFRESH =
      LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS;
  private static final long DEFAULT_THRESHOLD =
      LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI;
  private static final long DEFAULT_MAX_AGE =
      LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES;

  @Test
  void constructor_validPath_shouldStorePath() {
    String validPath = "/test/deny.txt";
    LineaSharedGaslessConfiguration config =
        new LineaSharedGaslessConfiguration(
            validPath, DEFAULT_REFRESH, DEFAULT_THRESHOLD, DEFAULT_MAX_AGE);
    assertEquals(validPath, config.denyListPath());
    assertEquals(DEFAULT_REFRESH, config.denyListRefreshSeconds());
    assertEquals(DEFAULT_THRESHOLD, config.premiumGasPriceThresholdGWei());
    assertEquals(DEFAULT_MAX_AGE, config.denyListEntryMaxAgeMinutes());
  }

  @Test
  void constructor_nullPath_shouldThrowIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new LineaSharedGaslessConfiguration(
              null, DEFAULT_REFRESH, DEFAULT_THRESHOLD, DEFAULT_MAX_AGE);
        });
  }

  @Test
  void constructor_blankPath_shouldThrowIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new LineaSharedGaslessConfiguration(
              "  ", DEFAULT_REFRESH, DEFAULT_THRESHOLD, DEFAULT_MAX_AGE);
        });
  }

  @Test
  void constructor_invalidRefresh_shouldThrowIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new LineaSharedGaslessConfiguration(
              "/test/path.txt", 0L, DEFAULT_THRESHOLD, DEFAULT_MAX_AGE);
        });
  }

  @Test
  void constructor_invalidThreshold_shouldThrowIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new LineaSharedGaslessConfiguration(
              "/test/path.txt", DEFAULT_REFRESH, -1L, DEFAULT_MAX_AGE);
        });
  }

  @Test
  void constructor_invalidMaxAge_shouldThrowIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new LineaSharedGaslessConfiguration(
              "/test/path.txt", DEFAULT_REFRESH, DEFAULT_THRESHOLD, 0L);
        });
  }

  @Test
  void v1Default_shouldReturnDefaultConfiguration() {
    LineaSharedGaslessConfiguration defaultConfig = LineaSharedGaslessConfiguration.V1_DEFAULT;
    assertNotNull(defaultConfig);
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_PATH, defaultConfig.denyListPath());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS,
        defaultConfig.denyListRefreshSeconds());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI,
        defaultConfig.premiumGasPriceThresholdGWei());
    assertEquals(
        LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES,
        defaultConfig.denyListEntryMaxAgeMinutes());
  }
}
