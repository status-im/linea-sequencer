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

import java.util.Optional;

import net.consensys.linea.plugins.LineaCliOptions;
import picocli.CommandLine;

public class LineaRlnValidatorCliOptions implements LineaCliOptions {
  public static final String CONFIG_KEY = "RLN_VALIDATOR_CONFIG";

  // === ESSENTIAL OPTIONS (what operators actually need to configure) ===
  
  @CommandLine.Option(
      names = "--plugin-linea-rln-enabled",
      description = "Enable RLN validation for gasless transactions (default: ${DEFAULT-VALUE})",
      arity = "1")
  private boolean rlnValidationEnabled =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnValidationEnabled();

  @CommandLine.Option(
      names = "--plugin-linea-rln-verifying-key",
      description = "Path to the RLN verifying key file (required when RLN is enabled)",
      arity = "1")
  private String verifyingKeyPath = LineaRlnValidatorConfiguration.V1_DEFAULT.verifyingKeyPath();

  @CommandLine.Option(
      names = "--plugin-linea-rln-proof-service",
      description = "RLN Proof service endpoint (host:port, default: ${DEFAULT-VALUE})",
      arity = "1")
  private String proofService = "localhost:50051";

  @CommandLine.Option(
      names = "--plugin-linea-rln-karma-service", 
      description = "Karma service endpoint (host:port, default: ${DEFAULT-VALUE})",
      arity = "1")
  private String karmaService = "localhost:50052";

  @CommandLine.Option(
      names = "--plugin-linea-rln-deny-list-path",
      description = "Path to the deny list file (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String denyListPath = "/var/lib/linea/deny_list.txt";

  // === ADVANCED OPTIONS (most users won't need to change these) ===
  
  @CommandLine.Option(
      names = "--plugin-linea-rln-use-tls",
      description = "Use TLS for gRPC services (default: auto-detect based on ports)",
      arity = "1")
  private Optional<Boolean> useTls = Optional.empty(); // Auto-detect: false for :505x, true for :443/8443

  @CommandLine.Option(
      names = "--plugin-linea-rln-premium-gas-threshold-gwei",
      description = "Premium gas threshold in GWei to bypass deny list (default: ${DEFAULT-VALUE})",
      arity = "1")  
  private long premiumGasThresholdGWei = 10L; // 10 GWei

  @CommandLine.Option(
      names = "--plugin-linea-rln-timeouts-ms",
      description = "Service timeout in milliseconds (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long timeoutsMs = 5000L; // 5 seconds

  private LineaRlnValidatorCliOptions() {}

  public static LineaRlnValidatorCliOptions create() {
    return new LineaRlnValidatorCliOptions();
  }

  @Override
  public LineaRlnValidatorConfiguration toDomainObject() {
    // Parse service endpoints
    String[] proofParts = proofService.split(":");
    String proofHost = proofParts[0];
    int proofPort = Integer.parseInt(proofParts[1]);
    
    String[] karmaParts = karmaService.split(":");
    String karmaHost = karmaParts[0];
    int karmaPort = Integer.parseInt(karmaParts[1]);
    
    // Auto-detect TLS based on ports if not explicitly set
    boolean shouldUseTls = useTls.orElse(proofPort == 443 || proofPort == 8443 || karmaPort == 443 || karmaPort == 8443);
    
    // Create shared gasless config with simplified settings
    LineaSharedGaslessConfiguration sharedConfig = new LineaSharedGaslessConfiguration(
        denyListPath,
        60L, // 1 minute refresh interval (good default)
        premiumGasThresholdGWei,
        60L // 1 hour expiry (good default)
    );
    
    return new LineaRlnValidatorConfiguration(
        rlnValidationEnabled,
        verifyingKeyPath,
        proofHost,
        proofPort,
        shouldUseTls, // rlnProofServiceUseTls
        10000L, // rlnProofCacheMaxSize (good default)
        300L, // rlnProofCacheExpirySeconds (5 min, good default)
        5, // rlnProofStreamRetries (good default)
        5000L, // rlnProofStreamRetryIntervalMs (good default)
        200L, // rlnProofLocalWaitTimeoutMs (good default)
        sharedConfig,
        karmaHost,
        karmaPort,
        shouldUseTls, // karmaServiceUseTls
        timeoutsMs, // karmaServiceTimeoutMs
        true, // exponentialBackoffEnabled (good default)
        60000L, // maxBackoffDelayMs (1 min, good default)
        "TIMESTAMP_1H", // defaultEpochForQuota (good default)
        Optional.empty() // rlnJniLibPath (use system path)
    );
  }
}
