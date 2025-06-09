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
import picocli.CommandLine;

class LineaRlnValidatorCliOptionsTest {

  @Test
  void toDomainObject_withDefaultCliOptions_shouldReturnDefaultConfiguration() {
    LineaRlnValidatorCliOptions cliOptions = LineaRlnValidatorCliOptions.create();
    // Parse with no arguments to ensure defaults are used
    new CommandLine(cliOptions).parseArgs();

    LineaRlnValidatorConfiguration actualConfig = cliOptions.toDomainObject();

    // Test essential options with defaults
    assertFalse(actualConfig.rlnValidationEnabled()); // Disabled by default
    assertEquals("/etc/linea/rln_verifying_key.bin", actualConfig.verifyingKeyPath());
    assertEquals("localhost", actualConfig.rlnProofServiceHost());
    assertEquals(50051, actualConfig.rlnProofServicePort());
    assertEquals("localhost", actualConfig.karmaServiceHost());
    assertEquals(50052, actualConfig.karmaServicePort());
    assertEquals("/var/lib/linea/deny_list.txt", actualConfig.denyListPath());

    // Test auto-detected values
    assertFalse(actualConfig.rlnProofServiceUseTls()); // Should be false for default ports
    assertFalse(actualConfig.karmaServiceUseTls());
    assertEquals(5000L, actualConfig.karmaServiceTimeoutMs());

    // Test reasonable defaults for advanced options
    assertEquals(10000L, actualConfig.rlnProofCacheMaxSize());
    assertEquals(300L, actualConfig.rlnProofCacheExpirySeconds());
    assertEquals(5, actualConfig.rlnProofStreamRetries());
    assertTrue(actualConfig.exponentialBackoffEnabled());
    assertEquals("TIMESTAMP_1H", actualConfig.defaultEpochForQuota());
    assertTrue(actualConfig.rlnJniLibPath().isEmpty());
  }

  @Test
  void toDomainObject_withSpecificCliOptions_shouldReturnMatchingConfiguration() {
    LineaRlnValidatorCliOptions cliOptions = LineaRlnValidatorCliOptions.create();
    String[] args = {
      "--plugin-linea-rln-enabled=true",
      "--plugin-linea-rln-verifying-key=/custom/vk.key",
      "--plugin-linea-rln-proof-service=testhost:9999",
      "--plugin-linea-rln-karma-service=custom.karma:8080",
      "--plugin-linea-rln-deny-list-path=/custom/deny.txt",
      "--plugin-linea-rln-use-tls=true",
      "--plugin-linea-rln-premium-gas-threshold-gwei=20",
      "--plugin-linea-rln-timeouts-ms=10000"
    };
    new CommandLine(cliOptions).parseArgs(args);

    LineaRlnValidatorConfiguration actualConfig = cliOptions.toDomainObject();

    // Test essential options
    assertTrue(actualConfig.rlnValidationEnabled());
    assertEquals("/custom/vk.key", actualConfig.verifyingKeyPath());
    assertEquals("testhost", actualConfig.rlnProofServiceHost());
    assertEquals(9999, actualConfig.rlnProofServicePort());
    assertEquals("custom.karma", actualConfig.karmaServiceHost());
    assertEquals(8080, actualConfig.karmaServicePort());
    assertEquals("/custom/deny.txt", actualConfig.denyListPath());

    // Test explicitly set values
    assertTrue(actualConfig.rlnProofServiceUseTls());
    assertTrue(actualConfig.karmaServiceUseTls());
    assertEquals(10000L, actualConfig.karmaServiceTimeoutMs());
    assertEquals(
        20L, actualConfig.premiumGasPriceThresholdWei() / 1_000_000_000L); // Convert back to GWei
  }

  @Test
  void toDomainObject_shouldAutoDetectTlsForStandardPorts() {
    LineaRlnValidatorCliOptions cliOptions = LineaRlnValidatorCliOptions.create();
    String[] args = {
      "--plugin-linea-rln-proof-service=secure.example.com:443",
      "--plugin-linea-rln-karma-service=karma.example.com:8443"
    };
    new CommandLine(cliOptions).parseArgs(args);

    LineaRlnValidatorConfiguration actualConfig = cliOptions.toDomainObject();

    // Should auto-detect TLS for standard secure ports
    assertTrue(actualConfig.rlnProofServiceUseTls());
    assertTrue(actualConfig.karmaServiceUseTls());
    assertEquals("secure.example.com", actualConfig.rlnProofServiceHost());
    assertEquals(443, actualConfig.rlnProofServicePort());
    assertEquals("karma.example.com", actualConfig.karmaServiceHost());
    assertEquals(8443, actualConfig.karmaServicePort());
  }

  @Test
  void toDomainObject_shouldParseHostPortCorrectly() {
    LineaRlnValidatorCliOptions cliOptions = LineaRlnValidatorCliOptions.create();
    String[] args = {
      "--plugin-linea-rln-proof-service=proof.linea.build:50051",
      "--plugin-linea-rln-karma-service=karma.linea.build:50052"
    };
    new CommandLine(cliOptions).parseArgs(args);

    LineaRlnValidatorConfiguration actualConfig = cliOptions.toDomainObject();

    assertEquals("proof.linea.build", actualConfig.rlnProofServiceHost());
    assertEquals(50051, actualConfig.rlnProofServicePort());
    assertEquals("karma.linea.build", actualConfig.karmaServiceHost());
    assertEquals(50052, actualConfig.karmaServicePort());
  }
}
