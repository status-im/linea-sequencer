package net.consensys.linea.config;

import net.consensys.linea.plugins.LineaCliOptions;
import picocli.CommandLine;

public class LineaSharedGaslessCliOptions implements LineaCliOptions {
  public static final String CONFIG_KEY = "SHARED_GASLESS_CONFIG";

  @CommandLine.Option(
      names = "--linea-shared-deny-list-path",
      description = "Path to the shared deny list file (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String denyListPath = LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_PATH;

  @CommandLine.Option(
      names = "--linea-shared-deny-list-refresh-seconds",
      description = "Interval in seconds for reloading the deny list (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long denyListRefreshSeconds =
      LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_REFRESH_SECONDS;

  @CommandLine.Option(
      names = "--linea-shared-premium-gas-threshold-gwei",
      description =
          "Premium gas price threshold in GWei for bypassing deny list (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long premiumGasPriceThresholdGWei =
      LineaSharedGaslessConfiguration.DEFAULT_PREMIUM_GAS_PRICE_THRESHOLD_GWEI;

  @CommandLine.Option(
      names = "--linea-shared-deny-list-max-age-minutes",
      description =
          "Maximum age in minutes for a deny list entry before it expires (default: ${DEFAULT-VALUE})",
      arity = "1")
  private long denyListEntryMaxAgeMinutes =
      LineaSharedGaslessConfiguration.DEFAULT_DENY_LIST_ENTRY_MAX_AGE_MINUTES;

  private LineaSharedGaslessCliOptions() {}

  public static LineaSharedGaslessCliOptions create() {
    return new LineaSharedGaslessCliOptions();
  }

  @Override
  public LineaSharedGaslessConfiguration toDomainObject() {
    return new LineaSharedGaslessConfiguration(
        denyListPath,
        denyListRefreshSeconds,
        premiumGasPriceThresholdGWei,
        denyListEntryMaxAgeMinutes);
  }
}
