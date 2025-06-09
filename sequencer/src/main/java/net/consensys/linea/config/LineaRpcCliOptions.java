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

import java.math.BigDecimal;

import com.google.common.base.MoreObjects;
import net.consensys.linea.plugins.LineaCliOptions;
import picocli.CommandLine;

/** The Linea RPC CLI options. */
public class LineaRpcCliOptions implements LineaCliOptions {
  public static final String CONFIG_KEY = "rpc-config-sequencer";

  private static final String ESTIMATE_GAS_COMPATIBILITY_MODE_ENABLED =
      "--plugin-linea-estimate-gas-compatibility-mode-enabled";
  private static final boolean DEFAULT_ESTIMATE_GAS_COMPATIBILITY_MODE_ENABLED = false;
  private static final String ESTIMATE_GAS_COMPATIBILITY_MODE_MULTIPLIER =
      "--plugin-linea-estimate-gas-compatibility-mode-multiplier";
  private static final BigDecimal DEFAULT_ESTIMATE_GAS_COMPATIBILITY_MODE_MULTIPLIER =
      BigDecimal.valueOf(1.2);

  // CLI options for gasless features
  private static final String RPC_GASLESS_ENABLED = "--plugin-linea-rpc-gasless-enabled";
  private static final boolean DEFAULT_RPC_GASLESS_ENABLED = false;

  private static final String RPC_PREMIUM_GAS_MULTIPLIER =
      "--plugin-linea-rpc-premium-gas-multiplier";
  private static final double DEFAULT_RPC_PREMIUM_GAS_MULTIPLIER = 1.5; // Example default

  private static final String RPC_ALLOW_ZERO_GAS_ESTIMATION_GASLESS =
      "--plugin-linea-rpc-allow-zero-gas-estimation-gasless";
  private static final boolean DEFAULT_RPC_ALLOW_ZERO_GAS_ESTIMATION_GASLESS = false;

  // CLI options for karma service configuration
  private static final String RPC_KARMA_SERVICE_HOST = "--plugin-linea-rpc-karma-service-host";
  private static final String DEFAULT_RPC_KARMA_SERVICE_HOST = "localhost";

  private static final String RPC_KARMA_SERVICE_PORT = "--plugin-linea-rpc-karma-service-port";
  private static final int DEFAULT_RPC_KARMA_SERVICE_PORT = 50052;

  private static final String RPC_KARMA_SERVICE_USE_TLS =
      "--plugin-linea-rpc-karma-service-use-tls";
  private static final boolean DEFAULT_RPC_KARMA_SERVICE_USE_TLS = false;

  private static final String RPC_KARMA_SERVICE_TIMEOUT_MS =
      "--plugin-linea-rpc-karma-service-timeout-ms";
  private static final long DEFAULT_RPC_KARMA_SERVICE_TIMEOUT_MS = 5000L;

  @CommandLine.Option(
      names = {ESTIMATE_GAS_COMPATIBILITY_MODE_ENABLED},
      paramLabel = "<BOOLEAN>",
      description =
          "Set to true to return the min mineable gas price * multiplier, instead of the profitable price (default: ${DEFAULT-VALUE})")
  private boolean estimateGasCompatibilityModeEnabled =
      DEFAULT_ESTIMATE_GAS_COMPATIBILITY_MODE_ENABLED;

  @CommandLine.Option(
      names = {ESTIMATE_GAS_COMPATIBILITY_MODE_MULTIPLIER},
      paramLabel = "<FLOAT>",
      description =
          "Set to multiplier to apply to the min priority fee per gas when the compatibility mode is enabled (default: ${DEFAULT-VALUE})")
  private BigDecimal estimateGasCompatibilityMultiplier =
      DEFAULT_ESTIMATE_GAS_COMPATIBILITY_MODE_MULTIPLIER;

  @CommandLine.Option(
      names = {RPC_GASLESS_ENABLED},
      paramLabel = "<BOOLEAN>",
      description =
          "Enable gasless transaction features in RPC methods like linea_estimateGas (default: ${DEFAULT-VALUE})")
  private boolean gaslessTransactionsEnabled = DEFAULT_RPC_GASLESS_ENABLED;

  @CommandLine.Option(
      names = {RPC_PREMIUM_GAS_MULTIPLIER},
      paramLabel = "<DOUBLE>",
      description =
          "Multiplier for calculating premium gas price in estimateGas for denied users (default: ${DEFAULT-VALUE})")
  private double premiumGasMultiplier = DEFAULT_RPC_PREMIUM_GAS_MULTIPLIER;

  @CommandLine.Option(
      names = {RPC_ALLOW_ZERO_GAS_ESTIMATION_GASLESS},
      paramLabel = "<BOOLEAN>",
      description =
          "Allow linea_estimateGas to return 0 for gasless transactions if user is not on deny list (default: ${DEFAULT-VALUE})")
  private boolean allowZeroGasEstimationForGasless = DEFAULT_RPC_ALLOW_ZERO_GAS_ESTIMATION_GASLESS;

  @CommandLine.Option(
      names = {RPC_KARMA_SERVICE_HOST},
      paramLabel = "<STRING>",
      description =
          "Hostname for the Karma gRPC service used by linea_estimateGas (default: ${DEFAULT-VALUE})")
  private String karmaServiceHost = DEFAULT_RPC_KARMA_SERVICE_HOST;

  @CommandLine.Option(
      names = {RPC_KARMA_SERVICE_PORT},
      paramLabel = "<INTEGER>",
      description =
          "Port for the Karma gRPC service used by linea_estimateGas (default: ${DEFAULT-VALUE})")
  private int karmaServicePort = DEFAULT_RPC_KARMA_SERVICE_PORT;

  @CommandLine.Option(
      names = {RPC_KARMA_SERVICE_USE_TLS},
      paramLabel = "<BOOLEAN>",
      description =
          "Use TLS for gRPC connection to karma service in linea_estimateGas (default: ${DEFAULT-VALUE})")
  private boolean karmaServiceUseTls = DEFAULT_RPC_KARMA_SERVICE_USE_TLS;

  @CommandLine.Option(
      names = {RPC_KARMA_SERVICE_TIMEOUT_MS},
      paramLabel = "<LONG>",
      description =
          "Timeout for karma service requests in milliseconds for linea_estimateGas (default: ${DEFAULT-VALUE})")
  private long karmaServiceTimeoutMs = DEFAULT_RPC_KARMA_SERVICE_TIMEOUT_MS;

  private LineaRpcCliOptions() {}

  /**
   * Create Linea RPC CLI options.
   *
   * @return the Linea RPC CLI options
   */
  public static LineaRpcCliOptions create() {
    return new LineaRpcCliOptions();
  }

  /**
   * Linea RPC CLI options from config.
   *
   * @param config the config
   * @return the Linea RPC CLI options
   */
  public static LineaRpcCliOptions fromConfig(final LineaRpcConfiguration config) {
    final LineaRpcCliOptions options = create();
    options.estimateGasCompatibilityModeEnabled = config.estimateGasCompatibilityModeEnabled();
    options.estimateGasCompatibilityMultiplier = config.estimateGasCompatibilityMultiplier();
    options.gaslessTransactionsEnabled = config.gaslessTransactionsEnabled();
    options.premiumGasMultiplier = config.premiumGasMultiplier();
    options.allowZeroGasEstimationForGasless = config.allowZeroGasEstimationForGasless();
    options.karmaServiceHost = config.karmaServiceHost();
    options.karmaServicePort = config.karmaServicePort();
    options.karmaServiceUseTls = config.karmaServiceUseTls();
    options.karmaServiceTimeoutMs = config.karmaServiceTimeoutMs();
    return options;
  }

  /**
   * Converts CLI options to LineaRpcConfiguration, requiring shared gasless config.
   *
   * @param sharedConfig The shared configuration for gasless features.
   * @return The LineaRpcConfiguration domain object.
   */
  public LineaRpcConfiguration toDomainObject(LineaSharedGaslessConfiguration sharedConfig) {
    return LineaRpcConfiguration.builder()
        .estimateGasCompatibilityModeEnabled(estimateGasCompatibilityModeEnabled)
        .estimateGasCompatibilityMultiplier(estimateGasCompatibilityMultiplier)
        .gaslessTransactionsEnabled(gaslessTransactionsEnabled)
        .premiumGasMultiplier(premiumGasMultiplier)
        .allowZeroGasEstimationForGasless(allowZeroGasEstimationForGasless)
        .karmaServiceHost(karmaServiceHost)
        .karmaServicePort(karmaServicePort)
        .karmaServiceUseTls(karmaServiceUseTls)
        .karmaServiceTimeoutMs(karmaServiceTimeoutMs)
        .sharedGaslessConfig(sharedConfig) // Inject the shared config
        .build();
  }

  /**
   * This version of toDomainObject is not supported for LineaRpcCliOptions as it requires
   * LineaSharedGaslessConfiguration to be fully constructed.
   */
  @Override
  public LineaRpcConfiguration toDomainObject() {
    throw new UnsupportedOperationException(
        "LineaRpcCliOptions requires LineaSharedGaslessConfiguration. Call toDomainObject(LineaSharedGaslessConfiguration sharedConfig) instead.");
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add(ESTIMATE_GAS_COMPATIBILITY_MODE_ENABLED, estimateGasCompatibilityModeEnabled)
        .add(ESTIMATE_GAS_COMPATIBILITY_MODE_MULTIPLIER, estimateGasCompatibilityMultiplier)
        .add(RPC_GASLESS_ENABLED, gaslessTransactionsEnabled)
        .add(RPC_PREMIUM_GAS_MULTIPLIER, premiumGasMultiplier)
        .add(RPC_ALLOW_ZERO_GAS_ESTIMATION_GASLESS, allowZeroGasEstimationForGasless)
        .add(RPC_KARMA_SERVICE_HOST, karmaServiceHost)
        .add(RPC_KARMA_SERVICE_PORT, karmaServicePort)
        .add(RPC_KARMA_SERVICE_USE_TLS, karmaServiceUseTls)
        .add(RPC_KARMA_SERVICE_TIMEOUT_MS, karmaServiceTimeoutMs)
        .toString();
  }
}
