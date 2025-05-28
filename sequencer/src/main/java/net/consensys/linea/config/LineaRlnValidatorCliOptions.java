package net.consensys.linea.config;

import java.util.Optional;

import net.consensys.linea.plugins.LineaCliOptions;
import picocli.CommandLine;

public class LineaRlnValidatorCliOptions implements LineaCliOptions {
  public static final String CONFIG_KEY = "RLN_VALIDATOR_CONFIG";

  @CommandLine.Option(
      names = "--linea-rln-validation-enabled",
      description = "Enable RLN validation (default: ${DEFAULT-VALUE})",
      arity = "1")
  private boolean rlnValidationEnabled =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnValidationEnabled();

  @CommandLine.Option(
      names = "--linea-rln-verifying-key-path",
      description = "Path to the RLN verifying key file (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String verifyingKeyPath = LineaRlnValidatorConfiguration.V1_DEFAULT.verifyingKeyPath();

  @CommandLine.Option(
      names = "--linea-rln-proof-service-host",
      description = "Hostname for the RLN Proof gRPC service (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String rlnProofServiceHost =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofServiceHost();

  @CommandLine.Option(
      names = "--linea-rln-proof-service-port",
      description = "Port for the RLN Proof gRPC service (default: ${DEFAULT-VALUE})",
      arity = "1")
  private int rlnProofServicePort = LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofServicePort();

  @CommandLine.Option(
      names = "--linea-rln-proof-service-use-tls",
      description = "Use TLS for gRPC connection to proof service (default: ${DEFAULT-VALUE})",
      arity = "1")
  private boolean rlnProofServiceUseTls =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofServiceUseTls();

  @CommandLine.Option(
      names = "--linea-rln-proof-cache-max-size",
      description = "Maximum number of proofs in the in-memory cache (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long rlnProofCacheMaxSize =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofCacheMaxSize();

  @CommandLine.Option(
      names = "--linea-rln-proof-cache-expiry-seconds",
      description =
          "Time-to-live for proofs in the in-memory cache (seconds) (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long rlnProofCacheExpirySeconds =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofCacheExpirySeconds();

  @CommandLine.Option(
      names = "--linea-rln-proof-stream-retries",
      description = "Max retries for gRPC stream connection (default: ${DEFAULT-VALUE})",
      arity = "1")
  private int rlnProofStreamRetries =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofStreamRetries();

  @CommandLine.Option(
      names = "--linea-rln-proof-stream-retry-interval-ms",
      description = "Interval for gRPC stream retry attempts (ms) (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long rlnProofStreamRetryIntervalMs =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofStreamRetryIntervalMs();

  @CommandLine.Option(
      names = "--linea-rln-proof-local-wait-timeout-ms",
      description = "Timeout for waiting for proof in local cache (ms) (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long rlnProofLocalWaitTimeoutMs =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnProofLocalWaitTimeoutMs();

  @CommandLine.Option(
      names = "--linea-rln-karma-service-url",
      description =
          "Optional URL to an HTTP service that provides user karma/tier information (default: none, overrides DB if specified)",
      arity = "1")
  private Optional<String> karmaServiceUrl =
      LineaRlnValidatorConfiguration.V1_DEFAULT.karmaServiceUrl();

  @CommandLine.Option(
      names = "--linea-rln-default-epoch-for-quota",
      description = "Default epoch identifier strategy (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String defaultEpochForQuota =
      LineaRlnValidatorConfiguration.V1_DEFAULT.defaultEpochForQuota();

  @CommandLine.Option(
      names = "--linea-rln-jni-lib-path",
      description =
          "Optional explicit path to the rln_jni native library (default: system path lookup)",
      arity = "1")
  private Optional<String> rlnJniLibPath =
      LineaRlnValidatorConfiguration.V1_DEFAULT.rlnJniLibPath();

  @CommandLine.Mixin
  private LineaSharedGaslessCliOptions sharedGaslessCliOptions =
      LineaSharedGaslessCliOptions.create();

  private LineaRlnValidatorCliOptions() {}

  public static LineaRlnValidatorCliOptions create() {
    return new LineaRlnValidatorCliOptions();
  }

  @Override
  public LineaRlnValidatorConfiguration toDomainObject() {
    return new LineaRlnValidatorConfiguration(
        rlnValidationEnabled,
        verifyingKeyPath,
        rlnProofServiceHost,
        rlnProofServicePort,
        rlnProofServiceUseTls,
        rlnProofCacheMaxSize,
        rlnProofCacheExpirySeconds,
        rlnProofStreamRetries,
        rlnProofStreamRetryIntervalMs,
        rlnProofLocalWaitTimeoutMs,
        sharedGaslessCliOptions.toDomainObject(),
        karmaServiceUrl,
        defaultEpochForQuota,
        rlnJniLibPath);
  }
}
