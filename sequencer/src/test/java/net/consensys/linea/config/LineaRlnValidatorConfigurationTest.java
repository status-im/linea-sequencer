package net.consensys.linea.config;

import org.junit.jupiter.api.Test;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class LineaRlnValidatorConfigurationTest {

    private static final long DEFAULT_MAX_AGE_MINUTES = LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES;

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
        assertEquals(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_PATH, defaultConfig.denyListPath());
        assertEquals(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS, defaultConfig.denyListRefreshSeconds());
        assertEquals(LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI * 1_000_000_000L, defaultConfig.premiumGasPriceThresholdWei());
        assertEquals(LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES, defaultConfig.denyListEntryMaxAgeMinutes());
        assertEquals(Optional.empty(), defaultConfig.karmaServiceUrl());
        assertEquals("TIMESTAMP_1H", defaultConfig.defaultEpochForQuota());
        assertEquals(Optional.empty(), defaultConfig.rlnJniLibPath());
    }

    @Test
    void constructor_withCustomSharedConfig_shouldUseIt() {
        String customPath = "/custom/deny.txt";
        long customRefreshSeconds = 600L;
        long customPremiumGwei = 50L;
        long customMaxAgeMinutes = 20L;

        LineaSharedGaslessConfiguration sharedConfig = new LineaSharedGaslessConfiguration(
            customPath,
            customRefreshSeconds,
            customPremiumGwei,
            customMaxAgeMinutes
        );

        LineaRlnValidatorConfiguration config = new LineaRlnValidatorConfiguration(
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
                Optional.of("karma_url"),
                "TIMESTAMP_1H",
                Optional.of("/jni/path")
        );

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
        assertEquals(Optional.of("karma_url"), config.karmaServiceUrl());
        assertEquals("TIMESTAMP_1H", config.defaultEpochForQuota());
        assertEquals(Optional.of("/jni/path"), config.rlnJniLibPath());
    }

    @Test
    void denyListPath_accessor_shouldReturnPathFromSharedConfig() {
        String expectedPath = "/shared/path/to/deny.txt";
        long expectedRefresh = LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS;
        long expectedPremiumGwei = LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI;
        long expectedMaxAge = DEFAULT_MAX_AGE_MINUTES;

        LineaSharedGaslessConfiguration sharedConfig = new LineaSharedGaslessConfiguration(
            expectedPath,
            expectedRefresh,
            expectedPremiumGwei,
            expectedMaxAge
        );
        LineaRlnValidatorConfiguration config = new LineaRlnValidatorConfiguration(
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
                Optional.empty(),
                "",
                Optional.empty()
        );
        assertEquals(expectedPath, config.denyListPath());
        assertEquals(expectedRefresh, config.denyListRefreshSeconds());
        assertEquals(expectedPremiumGwei * 1_000_000_000L, config.premiumGasPriceThresholdWei());
        assertEquals(expectedMaxAge, config.denyListEntryMaxAgeMinutes());
    }
} 