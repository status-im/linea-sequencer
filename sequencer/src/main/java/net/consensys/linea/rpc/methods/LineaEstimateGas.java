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

package net.consensys.linea.rpc.methods;

import static net.consensys.linea.sequencer.modulelimit.ModuleLineCountValidator.ModuleLineCountResult.MODULE_NOT_DEFINED;
import static net.consensys.linea.sequencer.modulelimit.ModuleLineCountValidator.ModuleLineCountResult.TX_MODULE_LINE_COUNT_OVERFLOW;
import static net.consensys.linea.zktracer.Fork.LONDON;
import static org.hyperledger.besu.ethereum.api.jsonrpc.internal.results.Quantity.create;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import lombok.extern.slf4j.Slf4j;
import net.consensys.linea.bl.TransactionProfitabilityCalculator;
import net.consensys.linea.config.LineaProfitabilityConfiguration;
import net.consensys.linea.config.LineaRpcConfiguration;
import net.consensys.linea.config.LineaSharedGaslessConfiguration;
import net.consensys.linea.config.LineaTransactionPoolValidatorConfiguration;
import net.consensys.linea.plugins.config.LineaL1L2BridgeSharedConfiguration;
import net.consensys.linea.sequencer.modulelimit.ModuleLimitsValidationResult;
import net.consensys.linea.sequencer.modulelimit.ModuleLineCountValidator;
import net.consensys.linea.zktracer.ZkTracer;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.StateOverrideMap;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.exception.InvalidJsonRpcParameters;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.exception.InvalidJsonRpcRequestException;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.parameters.JsonRpcParameter;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcError;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.RpcErrorType;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.transaction.CallParameter;
import org.hyperledger.besu.plugin.data.ProcessableBlockHeader;
import org.hyperledger.besu.plugin.services.BesuConfiguration;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.hyperledger.besu.plugin.services.RpcEndpointService;
import org.hyperledger.besu.plugin.services.TransactionSimulationService;
import org.hyperledger.besu.plugin.services.exception.PluginRpcEndpointException;
import org.hyperledger.besu.plugin.services.rpc.PluginRpcRequest;
import org.hyperledger.besu.plugin.services.rpc.RpcMethodError;
import org.hyperledger.besu.plugin.services.rpc.RpcResponseType;

@Slf4j
public class LineaEstimateGas {
  @VisibleForTesting public static final SECPSignature FAKE_SIGNATURE_FOR_SIZE_CALCULATION;

  private static final AtomicInteger LOG_SEQUENCE = new AtomicInteger();

  static {
    final X9ECParameters params = SECNamedCurves.getByName("secp256k1");
    final ECDomainParameters curve =
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    FAKE_SIGNATURE_FOR_SIZE_CALCULATION =
        SECPSignature.create(
            new BigInteger(
                "66397251408932042429874251838229702988618145381408295790259650671563847073199"),
            new BigInteger(
                "24729624138373455972486746091821238755870276413282629437244319694880507882088"),
            (byte) 0,
            curve.getN());
  }

  private final JsonRpcParameter parameterParser = new JsonRpcParameter();
  private final BesuConfiguration besuConfiguration;
  private final TransactionSimulationService transactionSimulationService;
  private final BlockchainService blockchainService;
  private final RpcEndpointService rpcEndpointService;
  private LineaRpcConfiguration rpcConfiguration;
  private LineaTransactionPoolValidatorConfiguration txValidatorConf;
  private LineaProfitabilityConfiguration profitabilityConf;
  private TransactionProfitabilityCalculator txProfitabilityCalculator;
  private LineaL1L2BridgeSharedConfiguration l1L2BridgeConfiguration;
  private ModuleLineCountValidator moduleLineCountValidator;

  // New fields for gasless/deny list features
  private boolean gaslessTransactionsEnabled;
  private Optional<String> denyListPathOpt;
  private LineaSharedGaslessConfiguration sharedGaslessConfig;
  private double premiumGasMultiplier;
  private boolean allowZeroGasEstimationForGasless;
  private final Set<Address> denyListCache = ConcurrentHashMap.newKeySet();
  private ScheduledExecutorService denyListRefreshScheduler;

  public LineaEstimateGas(
      final BesuConfiguration besuConfiguration,
      final TransactionSimulationService transactionSimulationService,
      final BlockchainService blockchainService,
      final RpcEndpointService rpcEndpointService) {
    this.besuConfiguration = besuConfiguration;
    this.transactionSimulationService = transactionSimulationService;
    this.blockchainService = blockchainService;
    this.rpcEndpointService = rpcEndpointService;
  }

  public void init(
      final LineaRpcConfiguration rpcConfig,
      final LineaTransactionPoolValidatorConfiguration transactionValidatorConfiguration,
      final LineaProfitabilityConfiguration profitabilityConf,
      final Map<String, Integer> limitsMap,
      final LineaL1L2BridgeSharedConfiguration l1L2BridgeConfiguration) {
    this.rpcConfiguration = rpcConfig;
    this.txValidatorConf = transactionValidatorConfiguration;
    this.profitabilityConf = profitabilityConf;
    this.txProfitabilityCalculator = new TransactionProfitabilityCalculator(profitabilityConf);
    this.l1L2BridgeConfiguration = l1L2BridgeConfiguration;
    this.moduleLineCountValidator = new ModuleLineCountValidator(limitsMap);
    this.maxTxGasLimit = UInt256.valueOf(txValidatorConf.maxTxGasLimit());

    // Initialize new gasless config fields
    this.gaslessTransactionsEnabled = rpcConfig.gaslessTransactionsEnabled();
    if (this.gaslessTransactionsEnabled) {
      this.sharedGaslessConfig = rpcConfig.sharedGaslessConfig();
      if (this.sharedGaslessConfig != null) {
        this.denyListPathOpt = Optional.ofNullable(this.sharedGaslessConfig.denyListPath());
      } else {
        this.denyListPathOpt = Optional.empty();
        log.warn(
            "LineaRpcConfiguration provided null sharedGaslessConfig while gasless transactions are enabled.");
      }
      this.premiumGasMultiplier = rpcConfig.premiumGasMultiplier();
      this.allowZeroGasEstimationForGasless = rpcConfig.allowZeroGasEstimationForGasless();
      long refreshInterval = 0L;
      if (this.sharedGaslessConfig != null) {
        refreshInterval = this.sharedGaslessConfig.denyListRefreshSeconds();
      } else {
        // This case should ideally not happen if gaslessTransactionsEnabled is true
        // and sharedGaslessConfig was intended to be mandatory.
        // However, to prevent NullPointerException if logic changes or there's an oversight:
        log.warn(
            "sharedGaslessConfig is null even though gaslessTransactionsEnabled is true. Deny list refresh will be disabled.");
      }

      if (this.denyListPathOpt.isEmpty()) {
        log.warn(
            "Gasless transactions enabled, but deny list path is not configured. Deny list checks will be skipped.");
      } else {
        loadDenyListFromFile();
        if (refreshInterval > 0) {
          denyListRefreshScheduler =
              Executors.newSingleThreadScheduledExecutor(
                  r -> new Thread(r, "linea-estimate-gas-deny-list-refresher"));
          denyListRefreshScheduler.scheduleAtFixedRate(
              this::loadDenyListFromFile, refreshInterval, refreshInterval, TimeUnit.SECONDS);
          log.info(
              "Scheduled deny list refresh every {} seconds from {}.",
              refreshInterval,
              denyListPathOpt.get());
        }
      }
    } else {
      log.info("Gasless transaction features for linea_estimateGas are DISABLED.");
    }
  }

  private void loadDenyListFromFile() {
    denyListPathOpt.ifPresent(
        path -> {
          if (!Files.exists(Paths.get(path))) {
            log.warn("Deny list file not found at {}, clearing cache.", path);
            denyListCache.clear();
            return;
          }
          Set<Address> newDenyList = new HashSet<>();
          try (BufferedReader reader =
              Files.newBufferedReader(Paths.get(path), StandardCharsets.UTF_8)) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null) {
              try {
                newDenyList.add(Address.fromHexString(line.trim()));
                count++;
              } catch (IllegalArgumentException e) {
                log.warn("Invalid address format in deny list file '{}': '{}'", path, line.trim());
              }
            }
            denyListCache.clear();
            denyListCache.addAll(newDenyList);
            log.info("Deny list reloaded successfully from {}. {} addresses cached.", path, count);
          } catch (IOException e) {
            log.error("Error loading deny list from {}: {}", path, e.getMessage(), e);
          }
        });
  }

  public String getNamespace() {
    return "linea";
  }

  public String getName() {
    return "estimateGas";
  }

  public LineaEstimateGas.Response execute(final PluginRpcRequest request) {
    try {
      final long logId;
      if (log.isDebugEnabled()) {
        // no matter if it overflows, since it is only used to correlate logs for this request,
        // so we only print callParameters once at the beginning, and we can reference them using
        // the logId.
        logId = LOG_SEQUENCE.incrementAndGet();
      } else {
        logId = 0;
      }

      final var callParameters = parseCallParameters(request.getParams());
      final var maybeStateOverrides = getStateOverrideMap(request.getParams());
      final var minGasPrice = besuConfiguration.getMinGasPrice();

      // --- Linea Gasless Logic Start ---
      if (gaslessTransactionsEnabled && callParameters.getFrom() != null) {
        Address sender = callParameters.getFrom();
        boolean isOnDenyList = denyListPathOpt.isPresent() && denyListCache.contains(sender);

        if (isOnDenyList) {
          log.info(
              "[{}] Sender {} is on the deny list. Applying premium gas multiplier of {}.",
              logId,
              sender.toHexString(),
              premiumGasMultiplier);
          // Proceed to estimate gas, then multiply.
          final long originalGasEstimate =
              estimateOriginalGas(callParameters, maybeStateOverrides, minGasPrice, logId);
          final long premiumGasEstimate = (long) (originalGasEstimate * premiumGasMultiplier);

          // Fees are determined by the market, but the gas limit is inflated.
          final Wei baseFee = blockchainService.getNextBlockBaseFee().orElse(Wei.ZERO);
          final Transaction tempTxForFeeEstimation =
              createTransactionForSimulation(callParameters, premiumGasEstimate, baseFee, logId);
          final Wei estimatedPriorityFee =
              getEstimatedPriorityFee(
                  tempTxForFeeEstimation, baseFee, minGasPrice, premiumGasEstimate);

          log.info(
              "[{}] Deny list sender {}: Original estimate {}, Premium estimate {}.",
              logId,
              sender.toHexString(),
              originalGasEstimate,
              premiumGasEstimate);
          return new Response(
              create(premiumGasEstimate), create(baseFee), create(estimatedPriorityFee));
        }

        // Not on deny list, and gasless mode is on for RPC
        if (allowZeroGasEstimationForGasless) {
          // User is eligible for gasless, return 0 for gas fields
          // Actual gas will be calculated by backend, but user sees 0.
          log.info(
              "[{}] Sender {} is eligible for gasless estimation (not on deny list). Returning 0 gas.",
              logId,
              sender.toHexString());
          return new Response(create(0L), create(Wei.ZERO), create(Wei.ZERO));
        }
        // If !allowZeroGasEstimationForGasless, proceed to normal estimation below even if not on
        // deny list.
      }
      // --- Linea Gasless Logic End ---

      // Original estimation logic (also used as fallback or if gasless mode disabled)
      final long estimatedGasUsed =
          estimateOriginalGas(callParameters, maybeStateOverrides, minGasPrice, logId);
      final Wei baseFee =
          blockchainService
              .getNextBlockBaseFee()
              .orElseThrow(
                  () ->
                      new PluginRpcEndpointException(
                          RpcErrorType.INVALID_REQUEST, "Not on a baseFee market"));
      final Transaction transaction =
          createTransactionForSimulation(callParameters, estimatedGasUsed, baseFee, logId);
      final Wei estimatedPriorityFee =
          getEstimatedPriorityFee(transaction, baseFee, minGasPrice, gasEstimation);

      final var response =
          new Response(create(gasEstimation), create(baseFee), create(estimatedPriorityFee));
      log.atDebug()
          .setMessage("[{}] Response for call params {} is {}")
          .addArgument(logId)
          .addArgument(callParameters)
          .addArgument(response)
          .log();

      return response;
    } catch (PluginRpcEndpointException | InvalidJsonRpcRequestException e) {
      throw e;
    } catch (Exception e) {
      throw new PluginRpcEndpointException(new EstimateGasError(e.getMessage()), null, e);
    }
  }

  private long estimateOriginalGas(
      final JsonCallParameter callParameters,
      final Optional<StateOverrideMap> maybeStateOverrides,
      final Wei minGasPrice,
      final long logId) {
    final long gasLimitUpperBound = calculateGasLimitUpperBound(callParameters, logId);
    final Wei baseFee = blockchainService.getNextBlockBaseFee().orElse(Wei.ZERO);
    final Transaction transaction =

    return estimateGasUsed(callParameters, maybeStateOverrides, transaction, baseFee, logId);
  }

  private long calculateGasLimitUpperBound(
      final JsonCallParameter callParameters, final long logId) {
    if (callParameters.getFrom() != null) {
      final var sender = callParameters.getFrom();
      final var maxGasPrice = calculateTxMaxGasPrice(callParameters);
      log.atTrace()
          .setMessage("[{}] Calculated max gas price {}")
          .addArgument(logId)
          .addArgument(maxGasPrice)
          .log();
      if (maxGasPrice != null) {
        final Wei balance = getSenderBalance(sender, logId);
        if (balance.greaterThan(Wei.ZERO)) {
          final var value = callParameters.getValue();
          final var balanceForGas = value == null ? balance : balance.subtract(value);
          final var gasLimitForBalance = balanceForGas.divide(maxGasPrice).toUInt256();
          if (gasLimitForBalance.lessThan(maxTxGasLimit)) {
            final var gasLimitUpperBound = gasLimitForBalance.toLong();
            log.atTrace()
                .setMessage(
                    "[{}] Calculated gasLimitUpperBound {}; gasLimitForBalance {}, balance {}, value {}, balanceForGas {}, maxGasPrice {}")
                .addArgument(logId)
                .addArgument(gasLimitUpperBound)
                .addArgument(gasLimitForBalance::toDecimalString)
                .addArgument(balance::toHumanReadableString)
                .addArgument(value::toHumanReadableString)
                .addArgument(balanceForGas::toHumanReadableString)
                .addArgument(maxGasPrice::toHumanReadableString)
                .log();
            return gasLimitUpperBound;
          }
        }
      }
    }

    final var resp = rpcEndpointService.call("eth_estimateGas", params);
    if (!resp.getType().equals(RpcResponseType.SUCCESS)) {
      var errorResponse = (JsonRpcError) resp.getResult();
      throw new PluginRpcEndpointException(
          new EstimateGasError(errorResponse.getCode(), errorResponse.getMessage()),
          errorResponse.getData());
    }

    final Long gasEstimation = Long.decode((String) resp.getResult());
    log.atTrace()
        .setMessage("[{}] eth_estimateGas response is {}")
        .addArgument(logId)
        .addArgument(gasEstimation)
        .log();
    return gasEstimation;
  }
  private Wei getEstimatedPriorityFee(
      final Transaction transaction,
      final Wei baseFee,
      final Wei minGasPrice,
      final long estimatedGasUsed) {
    final Wei priorityFeeLowerBound = minGasPrice.subtract(baseFee);

    if (rpcConfiguration.estimateGasCompatibilityModeEnabled()) {
      return Wei.of(
          rpcConfiguration
              .estimateGasCompatibilityMultiplier()
              .multiply(new BigDecimal(priorityFeeLowerBound.getAsBigInteger()))
              .setScale(0, RoundingMode.CEILING)
              .toBigInteger());
    }

    return txProfitabilityCalculator.profitablePriorityFeePerGas(
        transaction, profitabilityConf.estimateGasMinMargin(), estimatedGasUsed, minGasPrice);
  }

  private void validateLineCounts(
      final Optional<StateOverrideMap> maybeStateOverrides,
      final Transaction transaction,
      final long logId) {

    final var pendingBlockHeader = transactionSimulationService.simulatePendingBlockHeader();
    final var zkTracer = createZkTracer(pendingBlockHeader, blockchainService.getChainId().get());

    final var maybeSimulationResults =
        transactionSimulationService.simulate(
            transaction, maybeStateOverrides, pendingBlockHeader, zkTracer, false, true);

    ModuleLimitsValidationResult moduleLimit =
        moduleLineCountValidator.validate(zkTracer.getModulesLineCount());

    if (moduleLimit.getResult() != ModuleLineCountValidator.ModuleLineCountResult.VALID) {
      handleModuleOverLimit(moduleLimit);
    }

    maybeSimulationResults.ifPresentOrElse(
        r -> {
          // if the transaction is invalid or doesn't have enough gas with the max it never will
          if (r.isInvalid()) {
            log.atDebug()
                .setMessage("[{}] Invalid transaction {}, reason {}")
                .addArgument(logId)
                .addArgument(transaction::toTraceLog)
                .addArgument(r.result())
                .log();
            throw new PluginRpcEndpointException(
                new EstimateGasError(r.result().getInvalidReason().orElse("")));
          }
          if (!r.isSuccessful()) {
            log.atDebug()
                .setMessage("[{}] Failed transaction {}, reason {}")
                .addArgument(logId)
                .addArgument(transaction::toTraceLog)
                .addArgument(r.result())
                .log();
            r.getRevertReason()
                .ifPresent(
                    rr -> {
                      throw new PluginRpcEndpointException(
                          RpcErrorType.REVERT_ERROR, rr.toHexString());
                    });
            final var invalidReason = r.result().getInvalidReason();
            throw new PluginRpcEndpointException(
                new EstimateGasError(
                    "Failed transaction" + invalidReason.map(ir -> ", reason: " + ir).orElse("")));
          }
        },
        () ->
            new PluginRpcEndpointException(
                RpcErrorType.PLUGIN_INTERNAL_ERROR, "Empty result from simulation"));
  }

  private CallParameter parseCallParameters(final Object[] params) {
    final CallParameter callParameters;
    try {
      callParameters = parameterParser.required(params, 0, CallParameter.class);
    } catch (JsonRpcParameter.JsonRpcParameterException e) {
      throw new InvalidJsonRpcParameters(
          "Invalid call parameters (index 0)", RpcErrorType.INVALID_CALL_PARAMS);
    }
    validateCallParameters(callParameters);
    return callParameters;
  }

  private void validateCallParameters(final CallParameter callParameters) {
    if (callParameters.getGasPrice().isPresent() && isBaseFeeTransaction(callParameters)) {
      throw new InvalidJsonRpcParameters(
          "gasPrice cannot be used with maxFeePerGas or maxPriorityFeePerGas or maxFeePerBlobGas");
    }

    final var gasLimit = callParameters.getGas().orElse(0L);
    if (gasLimit > txValidatorConf.maxTxGasLimit()) {
      throw new InvalidJsonRpcParameters(
          "gasLimit above maximum of: " + txValidatorConf.maxTxGasLimit());
    }
  }

  protected Optional<StateOverrideMap> getStateOverrideMap(final Object[] params) {
    try {
      return parameterParser.optional(params, 1, StateOverrideMap.class);
    } catch (JsonRpcParameter.JsonRpcParameterException e) {
      throw new InvalidJsonRpcRequestException(
          "Invalid account overrides parameter (index 1)", RpcErrorType.INVALID_CALL_PARAMS, e);
    }
  }

  private boolean isBaseFeeTransaction(final CallParameter callParameters) {
    return (callParameters.getMaxFeePerGas().isPresent()
        || callParameters.getMaxPriorityFeePerGas().isPresent()
        || callParameters.getMaxFeePerBlobGas().isPresent());
  }

  private Transaction createTransactionForSimulation(
      final CallParameter callParameters,
      final long gasEstimation,
      final Wei baseFee,
      final long logId) {

    final var txBuilder =
        Transaction.builder()
            .sender(callParameters.getSender().orElse(Address.ZERO))
            .nonce(callParameters.getNonce().orElseGet(() -> getSenderNonce(callParameters, logId)))
            .gasLimit(gasEstimation)
            .payload(callParameters.getPayload().orElse(Bytes.EMPTY))
            .value(callParameters.getValue().orElse(Wei.ZERO))
            .signature(FAKE_SIGNATURE_FOR_SIZE_CALCULATION);

    callParameters.getTo().ifPresent(txBuilder::to);

    if (isBaseFeeTransaction(callParameters)) {
      txBuilder.maxFeePerGas(callParameters.getMaxFeePerGas().orElse(Wei.ZERO));
      txBuilder.maxPriorityFeePerGas(callParameters.getMaxPriorityFeePerGas().orElse(Wei.ZERO));
    } else {
      txBuilder.gasPrice(callParameters.getGasPrice().orElse(baseFee));
    }

    callParameters.getAccessList().ifPresent(txBuilder::accessList);

    final var txType = txBuilder.guessType().getTransactionType();

    if (txType.supportsBlob()) {
      txBuilder.maxFeePerBlobGas(callParameters.getMaxFeePerBlobGas().orElse(Wei.ZERO));
    }

    callParameters
        .getChainId()
        .ifPresentOrElse(
            txBuilder::chainId,
            () -> {
              if (txType.requiresChainId()) {
                blockchainService.getChainId().ifPresent(txBuilder::chainId);
              }
            });

    return txBuilder.build();
  }

  private long getSenderNonce(final CallParameter callParameters, final long logId) {

    return callParameters
        .getSender()
        .map(
            sender -> {
              final var resp =
                  rpcEndpointService.call(
                      "eth_getTransactionCount", new Object[] {sender.toHexString(), "latest"});

              if (!resp.getType().equals(RpcResponseType.SUCCESS)) {
                throw new PluginRpcEndpointException(
                    new EstimateGasError("Unable to query sender nonce"));
              }

              final Long nonce = Long.decode((String) resp.getResult());

              log.atTrace()
                  .setMessage("[{}] eth_getTransactionCount response for {} is {}, nonce {}")
                  .addArgument(logId)
                  .addArgument(sender)
                  .addArgument(resp::getResult)
                  .addArgument(nonce)
                  .log();

              return nonce;
            })
        .orElse(0L);
  }

  private ZkTracer createZkTracer(
      final ProcessableBlockHeader pendingBlockHeader, final BigInteger chainId) {
    var zkTracer = new ZkTracer(LONDON, l1L2BridgeConfiguration, chainId);
    zkTracer.traceStartConflation(1L);
    zkTracer.traceStartBlock(pendingBlockHeader, pendingBlockHeader.getCoinbase());
    return zkTracer;
  }

  private void handleModuleOverLimit(ModuleLimitsValidationResult moduleLimitResult) {
    // Throw specific exceptions based on the type of limit exceeded
    if (moduleLimitResult.getResult() == MODULE_NOT_DEFINED) {
      String moduleNotDefinedMsg =
          String.format(
              "Module %s does not exist in the limits file.", moduleLimitResult.getModuleName());
      log.error(moduleNotDefinedMsg);
      throw new PluginRpcEndpointException(new EstimateGasError(moduleNotDefinedMsg));
    }
    if (moduleLimitResult.getResult() == TX_MODULE_LINE_COUNT_OVERFLOW) {
      String txOverflowMsg =
          String.format(
              "Transaction line count for module %s=%s is above the limit %s",
              moduleLimitResult.getModuleName(),
              moduleLimitResult.getModuleLineCount(),
              moduleLimitResult.getModuleLineLimit());
      log.warn(txOverflowMsg);
      throw new PluginRpcEndpointException(new EstimateGasError(txOverflowMsg));
    }

    final String internalErrorMsg =
        String.format("Do not know what to do with result %s", moduleLimitResult.getResult());
    log.error(internalErrorMsg);
    throw new PluginRpcEndpointException(RpcErrorType.PLUGIN_INTERNAL_ERROR, internalErrorMsg);
  }

  public record Response(
      @JsonProperty String gasLimit,
      @JsonProperty String baseFeePerGas,
      @JsonProperty String priorityFeePerGas) {}

  private record EstimateGasError(int errorCode, String errorReason) implements RpcMethodError {
    public EstimateGasError(String errorReason) {
      this(-32000, errorReason);
    }

    @Override
    public int getCode() {
      return errorCode;
    }

    @Override
    public String getMessage() {
      return errorReason;
    }
  }

  private static class EstimateGasOperationTracer implements OperationTracer {

    private int maxDepth = 0;

    private long sStoreStipendNeeded = 0L;

    /** Default constructor. */
    public EstimateGasOperationTracer() {}

    @Override
    public void tracePostExecution(
        final MessageFrame frame, final Operation.OperationResult operationResult) {
      if (frame.getCurrentOperation() instanceof SStoreOperation sStoreOperation
          && sStoreStipendNeeded == 0L) {
        sStoreStipendNeeded = sStoreOperation.getMinimumGasRemaining();
      }
      if (maxDepth < frame.getDepth()) {
        maxDepth = frame.getDepth();
      }
    }

    /**
     * Gets max depth.
     *
     * @return the max depth
     */
    public int getMaxDepth() {
      return maxDepth;
    }

    /**
     * Gets stipend needed.
     *
     * @return the stipend needed
     */
    public long getStipendNeeded() {
      return sStoreStipendNeeded;
    }
  }

  // Method to stop the scheduler when the plugin stops (needs to be called from plugin's stop
  // lifecycle)
  public void stop() {
    if (denyListRefreshScheduler != null) {
      denyListRefreshScheduler.shutdown();
      try {
        if (!denyListRefreshScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
          denyListRefreshScheduler.shutdownNow();
        }
      } catch (InterruptedException e) {
        denyListRefreshScheduler.shutdownNow();
        Thread.currentThread().interrupt();
      }
      log.info("Deny list refresh scheduler stopped.");
    }
  }
}
