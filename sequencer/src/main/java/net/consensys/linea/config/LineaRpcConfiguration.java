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

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import net.consensys.linea.plugins.LineaOptionsConfiguration;

/** The Linea RPC configuration. */
@Builder(toBuilder = true)
@Accessors(fluent = true)
@Getter
@ToString
public class LineaRpcConfiguration implements LineaOptionsConfiguration {
  @Builder.Default @Setter private volatile boolean estimateGasCompatibilityModeEnabled = false;

  @Builder.Default private BigDecimal estimateGasCompatibilityMultiplier = BigDecimal.valueOf(1.2);

  @Builder.Default private final boolean gaslessTransactionsEnabled = false;

  @Builder.Default private final boolean rlnProverForwarderEnabled = false;

  @Builder.Default private final double premiumGasMultiplier = 1.5;

  @Builder.Default private final boolean allowZeroGasEstimationForGasless = false;

  @NonNull private final LineaSharedGaslessConfiguration sharedGaslessConfig;

  // Karma service configuration for gasless transaction quota validation
  @Builder.Default private final String karmaServiceHost = "localhost";

  @Builder.Default private final int karmaServicePort = 50052;

  @Builder.Default private final boolean karmaServiceUseTls = false;

  @Builder.Default private final long karmaServiceTimeoutMs = 5000L;
}
