package net.consensys.linea.config;

import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import static org.junit.jupiter.api.Assertions.*;

class LineaRpcConfigurationTest {

    private LineaSharedGaslessConfiguration getDefaultSharedConfig() {
        return LineaSharedGaslessConfiguration.V1_DEFAULT;
    }

    @Test
    void builder_withDefaultValues_shouldBuildCorrectly() {
        LineaSharedGaslessConfiguration sharedConfig = getDefaultSharedConfig();
        LineaRpcConfiguration config = LineaRpcConfiguration.builder()
            .sharedGaslessConfig(sharedConfig) // Minimum required for builder
            .build();

        assertFalse(config.estimateGasCompatibilityModeEnabled(), "Default estimateGasCompatibilityModeEnabled should be false");
        assertEquals(BigDecimal.valueOf(1.2), config.estimateGasCompatibilityMultiplier(), "Default estimateGasCompatibilityMultiplier");
        assertFalse(config.gaslessTransactionsEnabled(), "Default gaslessTransactionsEnabled should be false");
        assertEquals(1.5, config.premiumGasMultiplier(), 0.001, "Default premiumGasMultiplier");
        assertFalse(config.allowZeroGasEstimationForGasless(), "Default allowZeroGasEstimationForGasless should be false");
        assertSame(sharedConfig, config.sharedGaslessConfig(), "Shared config should be the one provided");
    }

    @Test
    void builder_withSpecificValues_shouldBuildCorrectly() {
        LineaSharedGaslessConfiguration sharedConfig = new LineaSharedGaslessConfiguration("/custom/deny.list", 120L, 20L, 30L);
        LineaRpcConfiguration config = LineaRpcConfiguration.builder()
            .estimateGasCompatibilityModeEnabled(true)
            .estimateGasCompatibilityMultiplier(BigDecimal.valueOf(2.0))
            .gaslessTransactionsEnabled(true)
            .premiumGasMultiplier(3.5)
            .allowZeroGasEstimationForGasless(true)
            .sharedGaslessConfig(sharedConfig)
            .build();

        assertTrue(config.estimateGasCompatibilityModeEnabled());
        assertEquals(BigDecimal.valueOf(2.0), config.estimateGasCompatibilityMultiplier());
        assertTrue(config.gaslessTransactionsEnabled());
        assertEquals(3.5, config.premiumGasMultiplier(), 0.001);
        assertTrue(config.allowZeroGasEstimationForGasless());
        LineaSharedGaslessConfiguration actualSharedConfig = config.sharedGaslessConfig();
        assertSame(sharedConfig, actualSharedConfig);
        assertEquals("/custom/deny.list", actualSharedConfig.denyListPath()); // Check pass-through by accessing shared config first
    }

    @Test
    void builder_missingSharedConfig_shouldThrowNullPointerException() {
        assertThrows(NullPointerException.class, () -> {
            LineaRpcConfiguration.builder()
                .estimateGasCompatibilityModeEnabled(true)
                // Missing .sharedGaslessConfig(sharedConfig)
                .build();
        });
    }

    // Test accessor methods that delegate to sharedGaslessConfig
    @Test
    void denyListPath_accessor_shouldReturnPathFromSharedConfig() {
        String expectedPath = "/shared/path/to/deny.txt";
        LineaSharedGaslessConfiguration shared = new LineaSharedGaslessConfiguration(expectedPath, 60L, 10L, 10L);
        LineaRpcConfiguration config = LineaRpcConfiguration.builder().sharedGaslessConfig(shared).build();
        assertEquals(expectedPath, config.sharedGaslessConfig().denyListPath());
    }

    @Test
    void denyListRefreshSeconds_accessor_shouldReturnRefreshFromSharedConfig() {
        long expectedRefresh = 120L;
        LineaSharedGaslessConfiguration shared = new LineaSharedGaslessConfiguration("path", expectedRefresh, 10L, 10L);
        LineaRpcConfiguration config = LineaRpcConfiguration.builder().sharedGaslessConfig(shared).build();
        assertEquals(expectedRefresh, config.sharedGaslessConfig().denyListRefreshSeconds());
    }

    @Test
    void premiumGasPriceThresholdGWei_accessor_shouldReturnThresholdFromSharedConfig() {
        long expectedThreshold = 25L;
        LineaSharedGaslessConfiguration shared = new LineaSharedGaslessConfiguration("path", 60L, expectedThreshold, 10L);
        LineaRpcConfiguration config = LineaRpcConfiguration.builder().sharedGaslessConfig(shared).build();
        assertEquals(expectedThreshold, config.sharedGaslessConfig().premiumGasPriceThresholdGWei());
    }

    @Test
    void denyListEntryMaxAgeMinutes_accessor_shouldReturnMaxAgeFromSharedConfig() {
        long expectedMaxAge = 45L;
        LineaSharedGaslessConfiguration shared = new LineaSharedGaslessConfiguration("path", 60L, 10L, expectedMaxAge);
        LineaRpcConfiguration config = LineaRpcConfiguration.builder().sharedGaslessConfig(shared).build();
        assertEquals(expectedMaxAge, config.sharedGaslessConfig().denyListEntryMaxAgeMinutes());
    }
} 