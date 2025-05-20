package net.consensys.linea.config;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class LineaRlnValidatorCliOptionsTest {

    @Test
    void toDomainObject_withDefaultCliOptions_shouldReturnDefaultConfiguration() {
        LineaRlnValidatorCliOptions cliOptions = LineaRlnValidatorCliOptions.create();
        // Parse with no arguments to ensure defaults are used
        new CommandLine(cliOptions).parseArgs();

        LineaRlnValidatorConfiguration defaultConfig = LineaRlnValidatorConfiguration.V1_DEFAULT;
        LineaRlnValidatorConfiguration actualConfig = cliOptions.toDomainObject();

        assertEquals(defaultConfig.rlnValidationEnabled(), actualConfig.rlnValidationEnabled());
        assertEquals(defaultConfig.verifyingKeyPath(), actualConfig.verifyingKeyPath());
        assertEquals(defaultConfig.rlnProofServiceHost(), actualConfig.rlnProofServiceHost());
        assertEquals(defaultConfig.rlnProofServicePort(), actualConfig.rlnProofServicePort());
        assertEquals(defaultConfig.rlnProofServiceUseTls(), actualConfig.rlnProofServiceUseTls());
        assertEquals(defaultConfig.rlnProofCacheMaxSize(), actualConfig.rlnProofCacheMaxSize());
        assertEquals(defaultConfig.rlnProofCacheExpirySeconds(), actualConfig.rlnProofCacheExpirySeconds());
        assertEquals(defaultConfig.rlnProofStreamRetries(), actualConfig.rlnProofStreamRetries());
        assertEquals(defaultConfig.rlnProofStreamRetryIntervalMs(), actualConfig.rlnProofStreamRetryIntervalMs());
        assertEquals(defaultConfig.rlnProofLocalWaitTimeoutMs(), actualConfig.rlnProofLocalWaitTimeoutMs());
        assertEquals(defaultConfig.karmaServiceUrl(), actualConfig.karmaServiceUrl());
        assertEquals(defaultConfig.defaultEpochForQuota(), actualConfig.defaultEpochForQuota());
        assertEquals(defaultConfig.rlnJniLibPath(), actualConfig.rlnJniLibPath());

        // Check shared gasless configuration defaults
        LineaSharedGaslessConfiguration defaultSharedConfig = LineaSharedGaslessConfiguration.V1_DEFAULT;
        LineaSharedGaslessConfiguration actualSharedConfig = actualConfig.sharedGaslessConfig();
        assertNotNull(actualSharedConfig, "Shared gasless configuration should not be null");
        assertEquals(defaultSharedConfig.denyListPath(), actualSharedConfig.denyListPath());
        assertEquals(defaultSharedConfig.denyListRefreshSeconds(), actualSharedConfig.denyListRefreshSeconds());
        assertEquals(defaultSharedConfig.denyListEntryMaxAgeMinutes(), actualSharedConfig.denyListEntryMaxAgeMinutes());
        assertEquals(defaultSharedConfig.premiumGasPriceThresholdGWei(), actualSharedConfig.premiumGasPriceThresholdGWei());
    }

    @Test
    void toDomainObject_withSpecificCliOptions_shouldReturnMatchingConfiguration() {
        LineaRlnValidatorCliOptions cliOptions = LineaRlnValidatorCliOptions.create();
        String[] args = {
            "--linea-rln-validation-enabled=false",
            "--linea-rln-verifying-key-path=/custom/vk.key",
            "--linea-rln-proof-service-host=testhost",
            "--linea-rln-proof-service-port=9999",
            "--linea-rln-proof-service-use-tls=true",
            "--linea-rln-proof-cache-max-size=500",
            "--linea-rln-proof-cache-expiry-seconds=60",
            "--linea-rln-proof-stream-retries=10",
            "--linea-rln-proof-stream-retry-interval-ms=10000",
            "--linea-rln-proof-local-wait-timeout-ms=200",
            "--linea-rln-karma-service-url=http://custom.karma/api",
            "--linea-rln-default-epoch-for-quota=BLOCK_NUMBER_100",
            "--linea-rln-jni-lib-path=/custom/lib/rln.so"
            // Shared options Temporarily Removed for diagnostics
            // "--linea-shared-deny-list-path=/custom/deny.txt",
            // "--linea-shared-deny-list-refresh-seconds=120",
            // "--linea-shared-deny-list-entry-max-age-minutes=30",
            // "--linea-shared-premium-gas-price-threshold-gwei=5000"
        };
        new CommandLine(cliOptions).parseArgs(args);

        LineaRlnValidatorConfiguration actualConfig = cliOptions.toDomainObject();

        assertFalse(actualConfig.rlnValidationEnabled());
        assertEquals("/custom/vk.key", actualConfig.verifyingKeyPath());
        assertEquals("testhost", actualConfig.rlnProofServiceHost());
        assertEquals(9999, actualConfig.rlnProofServicePort());
        assertTrue(actualConfig.rlnProofServiceUseTls());
        assertEquals(500L, actualConfig.rlnProofCacheMaxSize());
        assertEquals(60L, actualConfig.rlnProofCacheExpirySeconds());
        assertEquals(10, actualConfig.rlnProofStreamRetries());
        assertEquals(10000L, actualConfig.rlnProofStreamRetryIntervalMs());
        assertEquals(200L, actualConfig.rlnProofLocalWaitTimeoutMs());
        assertEquals(Optional.of("http://custom.karma/api"), actualConfig.karmaServiceUrl());
        assertEquals("BLOCK_NUMBER_100", actualConfig.defaultEpochForQuota());
        assertEquals(Optional.of("/custom/lib/rln.so"), actualConfig.rlnJniLibPath());

        // Since shared options are removed from args, the shared config should have defaults.
        LineaSharedGaslessConfiguration actualSharedConfig = actualConfig.sharedGaslessConfig();
        assertNotNull(actualSharedConfig);
        LineaSharedGaslessConfiguration defaultSharedConfig = LineaSharedGaslessConfiguration.V1_DEFAULT;
        assertEquals(defaultSharedConfig.denyListPath(), actualSharedConfig.denyListPath());
        assertEquals(defaultSharedConfig.denyListRefreshSeconds(), actualSharedConfig.denyListRefreshSeconds());
        assertEquals(defaultSharedConfig.denyListEntryMaxAgeMinutes(), actualSharedConfig.denyListEntryMaxAgeMinutes());
        assertEquals(defaultSharedConfig.premiumGasPriceThresholdGWei(), actualSharedConfig.premiumGasPriceThresholdGWei());
    }
} 