package net.consensys.linea.config;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigDecimal;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class LineaRpcCliOptionsTest {

  private LineaSharedGaslessConfiguration getDefaultSharedConfig() {
    return LineaSharedGaslessConfiguration.V1_DEFAULT;
  }

  @Test
  void toDomainObject_withDefaultCliOptions_shouldReturnDefaultConfiguration() {
    LineaRpcCliOptions cliOptions = LineaRpcCliOptions.create();
    new CommandLine(cliOptions).parseArgs(); // Parse with no args for defaults

    LineaSharedGaslessConfiguration sharedConfig = getDefaultSharedConfig();
    LineaRpcConfiguration actualConfig = cliOptions.toDomainObject(sharedConfig);

    // Expected default RPC config
    LineaRpcConfiguration expectedDefaultConfig =
        LineaRpcConfiguration.builder()
            .estimateGasCompatibilityModeEnabled(false)
            .estimateGasCompatibilityMultiplier(BigDecimal.valueOf(1.2))
            .gaslessTransactionsEnabled(false)
            .premiumGasMultiplier(1.5)
            .allowZeroGasEstimationForGasless(false)
            .sharedGaslessConfig(sharedConfig)
            .build();

    assertEquals(
        expectedDefaultConfig.estimateGasCompatibilityModeEnabled(),
        actualConfig.estimateGasCompatibilityModeEnabled());
    assertEquals(
        expectedDefaultConfig.estimateGasCompatibilityMultiplier(),
        actualConfig.estimateGasCompatibilityMultiplier());
    assertEquals(
        expectedDefaultConfig.gaslessTransactionsEnabled(),
        actualConfig.gaslessTransactionsEnabled());
    assertEquals(
        expectedDefaultConfig.premiumGasMultiplier(), actualConfig.premiumGasMultiplier(), 0.001);
    assertEquals(
        expectedDefaultConfig.allowZeroGasEstimationForGasless(),
        actualConfig.allowZeroGasEstimationForGasless());
    assertSame(sharedConfig, actualConfig.sharedGaslessConfig());
  }

  @Test
  void toDomainObject_withSpecificCliOptions_shouldReturnMatchingConfiguration() {
    LineaRpcCliOptions cliOptions = LineaRpcCliOptions.create();
    String[] args = {
      "--plugin-linea-estimate-gas-compatibility-mode-enabled=true",
      "--plugin-linea-estimate-gas-compatibility-mode-multiplier=1.5",
      "--linea-rpc-gasless-enabled=true",
      "--linea-rpc-premium-gas-multiplier=2.5",
      "--linea-rpc-allow-zero-gas-estimation-gasless=true"
    };
    new CommandLine(cliOptions).parseArgs(args);

    LineaSharedGaslessConfiguration sharedConfig =
        getDefaultSharedConfig(); // Can use default or a custom one
    LineaRpcConfiguration actualConfig = cliOptions.toDomainObject(sharedConfig);

    assertTrue(actualConfig.estimateGasCompatibilityModeEnabled());
    assertEquals(BigDecimal.valueOf(1.5), actualConfig.estimateGasCompatibilityMultiplier());
    assertTrue(actualConfig.gaslessTransactionsEnabled());
    assertEquals(2.5, actualConfig.premiumGasMultiplier(), 0.001);
    assertTrue(actualConfig.allowZeroGasEstimationForGasless());
    assertSame(sharedConfig, actualConfig.sharedGaslessConfig());
  }

  @Test
  void fromConfig_shouldSetCliOptionsCorrectly() {
    LineaSharedGaslessConfiguration sharedConfig = getDefaultSharedConfig();
    LineaRpcConfiguration sourceConfig =
        LineaRpcConfiguration.builder()
            .estimateGasCompatibilityModeEnabled(true)
            .estimateGasCompatibilityMultiplier(BigDecimal.TEN)
            .gaslessTransactionsEnabled(true)
            .premiumGasMultiplier(3.0)
            .allowZeroGasEstimationForGasless(true)
            .sharedGaslessConfig(sharedConfig)
            .build();

    LineaRpcCliOptions cliOptions = LineaRpcCliOptions.fromConfig(sourceConfig);
    LineaRpcConfiguration convertedConfig = cliOptions.toDomainObject(sharedConfig);

    assertEquals(
        sourceConfig.estimateGasCompatibilityModeEnabled(),
        convertedConfig.estimateGasCompatibilityModeEnabled());
    assertEquals(
        sourceConfig.estimateGasCompatibilityMultiplier(),
        convertedConfig.estimateGasCompatibilityMultiplier());
    assertEquals(
        sourceConfig.gaslessTransactionsEnabled(), convertedConfig.gaslessTransactionsEnabled());
    assertEquals(
        sourceConfig.premiumGasMultiplier(), convertedConfig.premiumGasMultiplier(), 0.001);
    assertEquals(
        sourceConfig.allowZeroGasEstimationForGasless(),
        convertedConfig.allowZeroGasEstimationForGasless());
  }

  @Test
  void toDomainObject_noArg_shouldThrowUnsupportedOperationException() {
    LineaRpcCliOptions cliOptions = LineaRpcCliOptions.create();
    assertThrows(UnsupportedOperationException.class, cliOptions::toDomainObject);
  }
}
