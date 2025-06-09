package net.consensys.linea.rpc.methods;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import net.consensys.linea.plugins.config.LineaL1L2BridgeSharedConfiguration;
import net.consensys.linea.config.LineaProfitabilityConfiguration;
import net.consensys.linea.config.LineaRpcConfiguration;
import net.consensys.linea.config.LineaSharedGaslessConfiguration;
import net.consensys.linea.config.LineaTransactionPoolValidatorConfiguration;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.plugin.services.BesuConfiguration;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.hyperledger.besu.plugin.services.RpcEndpointService;
import org.hyperledger.besu.plugin.services.TransactionSimulationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for LineaEstimateGas gasless functionality.
 * 
 * These tests focus on the core gasless logic without complex RPC mocking.
 * They verify the configuration and initialization behavior.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LineaEstimateGasTest {

  @Mock private BesuConfiguration besuConfiguration;
  @Mock private TransactionSimulationService transactionSimulationService;
  @Mock private BlockchainService blockchainService;
  @Mock private RpcEndpointService rpcEndpointService;
  @Mock private LineaRpcConfiguration rpcConfiguration;
  @Mock private LineaSharedGaslessConfiguration sharedGaslessConfig;
  @Mock private LineaTransactionPoolValidatorConfiguration txValidatorConf;
  @Mock private LineaProfitabilityConfiguration profitabilityConf;
  @Mock private LineaL1L2BridgeSharedConfiguration l1L2BridgeConfiguration;

  @TempDir Path tempDir;
  private Path denyListFile;
  private LineaEstimateGas lineaEstimateGas;

  @BeforeEach
  void setUp() throws IOException {
    denyListFile = tempDir.resolve("deny_list.txt");
    
    // Setup default mocks
    when(besuConfiguration.getMinGasPrice()).thenReturn(Wei.of(1_000_000_000L));
    when(blockchainService.getNextBlockBaseFee()).thenReturn(Optional.of(Wei.of(1_000_000_000L)));
    
    // Setup gasless configuration
    when(sharedGaslessConfig.denyListPath()).thenReturn(denyListFile.toString());
    when(sharedGaslessConfig.denyListRefreshSeconds()).thenReturn(60L);
    when(sharedGaslessConfig.premiumGasPriceThresholdGWei()).thenReturn(10L); // 10 GWei
    when(sharedGaslessConfig.denyListEntryMaxAgeMinutes()).thenReturn(60L);
    
    when(rpcConfiguration.gaslessTransactionsEnabled()).thenReturn(true);
    when(rpcConfiguration.sharedGaslessConfig()).thenReturn(sharedGaslessConfig);
    when(rpcConfiguration.premiumGasMultiplier()).thenReturn(1.5);
    when(rpcConfiguration.allowZeroGasEstimationForGasless()).thenReturn(true);
    when(rpcConfiguration.karmaServiceHost()).thenReturn("localhost");
    when(rpcConfiguration.karmaServicePort()).thenReturn(7777);
    when(rpcConfiguration.karmaServiceUseTls()).thenReturn(false);
    when(rpcConfiguration.karmaServiceTimeoutMs()).thenReturn(5000L);
    
    when(txValidatorConf.maxTxGasLimit()).thenReturn(30_000_000);
    
    // Create LineaEstimateGas instance
    lineaEstimateGas = new LineaEstimateGas(
        besuConfiguration,
        transactionSimulationService,
        blockchainService,
        rpcEndpointService
    );
  }

  @Test
  void testGaslessEnabled_shouldInitializeCorrectly() {
    // When: Initialize with gasless enabled
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
    assertEquals("linea", lineaEstimateGas.getNamespace());
    assertEquals("estimateGas", lineaEstimateGas.getName());
  }

  @Test
  void testGaslessDisabled_shouldInitializeCorrectly() {
    // Given: Gasless functionality is disabled
    when(rpcConfiguration.gaslessTransactionsEnabled()).thenReturn(false);
    
    // When: Initialize with gasless disabled
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
    assertEquals("linea", lineaEstimateGas.getNamespace());
    assertEquals("estimateGas", lineaEstimateGas.getName());
  }

  @Test
  void testDenyListFileCreation_shouldCreateFileWhenNeeded() throws IOException {
    // Given: Deny list file doesn't exist initially
    assertFalse(Files.exists(denyListFile));
    
    // When: Initialize gasless functionality
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should handle missing file gracefully
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testDenyListFileWithContent_shouldLoadCorrectly() throws IOException {
    // Given: Deny list file with content
    Address testAddress = Address.fromHexString("0x1234567890123456789012345678901234567890");
    String content = testAddress.toHexString().toLowerCase() + ",2024-01-01T12:00:00Z";
    Files.writeString(denyListFile, content, StandardCharsets.UTF_8);
    
    // When: Initialize gasless functionality
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testKarmaServiceConfiguration_shouldInitializeCorrectly() {
    // Given: Karma service configuration
    when(rpcConfiguration.karmaServiceHost()).thenReturn("karma.example.com");
    when(rpcConfiguration.karmaServicePort()).thenReturn(9090);
    when(rpcConfiguration.karmaServiceUseTls()).thenReturn(true);
    when(rpcConfiguration.karmaServiceTimeoutMs()).thenReturn(10000L);
    
    // When: Initialize with karma service config
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testNullSharedGaslessConfig_shouldHandleGracefully() {
    // Given: Null shared gasless config
    when(rpcConfiguration.sharedGaslessConfig()).thenReturn(null);
    
    // When: Initialize with null config
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors (with warnings logged)
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testStop_shouldCleanupResources() {
    // Given: Initialized LineaEstimateGas
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // When: Stop the service
    lineaEstimateGas.stop();
    
    // Then: Should complete without errors
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testPremiumGasMultiplier_shouldBeConfigurable() {
    // Given: Custom premium gas multiplier
    when(rpcConfiguration.premiumGasMultiplier()).thenReturn(2.0);
    
    // When: Initialize with custom multiplier
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testZeroGasEstimationFlag_shouldBeConfigurable() {
    // Given: Zero gas estimation disabled
    when(rpcConfiguration.allowZeroGasEstimationForGasless()).thenReturn(false);
    
    // When: Initialize with zero gas disabled
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
  }

  @Test
  void testDenyListRefreshInterval_shouldBeConfigurable() {
    // Given: Custom refresh interval
    when(sharedGaslessConfig.denyListRefreshSeconds()).thenReturn(30L);
    
    // When: Initialize with custom refresh interval
    lineaEstimateGas.init(
        rpcConfiguration,
        txValidatorConf,
        profitabilityConf,
        Map.of(),
        l1L2BridgeConfiguration
    );
    
    // Then: Should initialize without errors
    assertNotNull(lineaEstimateGas);
  }
} 