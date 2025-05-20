package net.consensys.linea.sequencer.txpoolvalidation.validators;

import net.consensys.linea.config.LineaRlnValidatorConfiguration;
import net.consensys.linea.rln.jni.RlnBridge;

import net.consensys.linea.rln.proofs.grpc.ProofMessage;
import net.consensys.linea.rln.proofs.grpc.RlnProofServiceGrpc;
import net.consensys.linea.rln.proofs.grpc.StreamProofsRequest;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.hyperledger.besu.plugin.services.txvalidator.PluginTransactionPoolValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import com.google.common.annotations.VisibleForTesting;
import org.apache.tuweni.bytes.Bytes;

public class RlnVerifierValidator implements PluginTransactionPoolValidator, Closeable {
    private static final Logger LOG = LoggerFactory.getLogger(RlnVerifierValidator.class);
    private static final String RLN_VALIDATION_FAILED_MESSAGE = "RLN validation failed";
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private static final Pattern KARMA_TIER_JSON_PATTERN = Pattern.compile("\"tier\"\s*:\s*\"([^\"]*)\"");
    private static final Pattern KARMA_EPOCH_TX_COUNT_JSON_PATTERN = Pattern.compile("\"epochTxCount\"\s*:\s*(\\d+)");
    private static final Pattern KARMA_DAILY_QUOTA_JSON_PATTERN = Pattern.compile("\"dailyQuota\"\s*:\s*(\\d+)");
    private static final Pattern KARMA_EPOCH_ID_JSON_PATTERN = Pattern.compile("\"epochId\"\s*:\s*\"([^\"]*)\"");

    private final LineaRlnValidatorConfiguration rlnConfig;
    private final BlockchainService blockchainService;
    private final byte[] rlnVerifyingKeyBytes;
    private final Map<Address, Instant> denyList = new ConcurrentHashMap<>();
    private final Path denyListFilePath;
    private ScheduledExecutorService denyListRefreshScheduler;
    private ScheduledExecutorService proofCacheEvictionScheduler;

    // In-memory cache for RLN proofs
    record CachedProof(
            String proofBytesHex,
            String shareXHex, String shareYHex,
            String epochHex, String rootHex, String nullifierHex,
            Instant cachedAt) {}
    private final Map<String, CachedProof> rlnProofCache = new ConcurrentHashMap<>();

    // gRPC client members for proof service
    private ManagedChannel proofServiceChannel;
    private RlnProofServiceGrpc.RlnProofServiceStub asyncProofStub;
    private ScheduledExecutorService grpcReconnectionScheduler;

    // New record for Karma Information
    private record KarmaInfo(String tier, int epochTxCount, int dailyQuota, String epochId) {}

    public RlnVerifierValidator(LineaRlnValidatorConfiguration rlnConfig, BlockchainService blockchainService) {
        this(rlnConfig, blockchainService, null);
    }

    /**
     * Constructor for testing purposes, allowing injection of a ManagedChannel.
     * If providedChannel is null, a new channel will be created based on configuration.
     */
    @VisibleForTesting
    RlnVerifierValidator(
            LineaRlnValidatorConfiguration rlnConfig,
            BlockchainService blockchainService,
            ManagedChannel providedChannel) {
        this.rlnConfig = rlnConfig;
        this.blockchainService = blockchainService;
        this.proofServiceChannel = providedChannel;

        String pathString = rlnConfig.sharedGaslessConfig().denyListPath();
        if (pathString == null) {
            LOG.error("CRITICAL: rlnConfig.sharedGaslessConfig().denyListPath() returned null during RlnVerifierValidator construction!");
            throw new IllegalStateException("denyListPath from sharedGaslessConfig cannot be null, check rlnConfig stubbing in tests or real configuration.");
        }
        this.denyListFilePath = Paths.get(pathString);

        if (rlnConfig.rlnValidationEnabled()) {
            LOG.info("RLN Validator is ENABLED.");
            try {
                this.rlnVerifyingKeyBytes = Files.readAllBytes(Paths.get(rlnConfig.verifyingKeyPath()));
                LOG.info("RLN Verifying Key loaded successfully from {}.", rlnConfig.verifyingKeyPath());
            } catch (IOException e) {
                LOG.error("Failed to load RLN verifying key from {}: {}", rlnConfig.verifyingKeyPath(), e.getMessage(), e);
                throw new IllegalStateException("Failed to initialize RlnVerifierValidator: Cannot load verifying key", e);
            } catch (UnsatisfiedLinkError | RuntimeException e) { 
                LOG.error("Failed to initialize RLN JNI RlnBridge: {}", e.getMessage(), e);
                throw new IllegalStateException("Failed to initialize RlnVerifierValidator: JNI linkage error", e);
            }
            loadDenyListFromFile();

            long refreshIntervalSeconds = rlnConfig.denyListRefreshSeconds();
            if (refreshIntervalSeconds > 0) {
                denyListRefreshScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = Executors.defaultThreadFactory().newThread(r);
                    t.setName("RlnVerifierValidator-DenyListRefresh");
                    t.setDaemon(true);
                    return t;
                });
                denyListRefreshScheduler.scheduleAtFixedRate(
                        this::loadDenyListFromFile,
                        refreshIntervalSeconds,
                        refreshIntervalSeconds,
                        TimeUnit.SECONDS);
                LOG.info("Scheduled RLN deny list refresh every {} seconds from {}.", refreshIntervalSeconds, denyListFilePath);
            } else {
                LOG.info("RLN deny list auto-refresh is DISABLED (refresh interval <= 0).");
            }

            // Re-enable gRPC client and scheduler initialization
            initializeProofServiceClient();
            startProofStreamSubscription();

            // Schedule proof cache eviction
            proofCacheEvictionScheduler = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "RlnProofCacheEviction"));
            proofCacheEvictionScheduler.scheduleAtFixedRate(this::evictExpiredProofs,
                    this.rlnConfig.rlnProofCacheExpirySeconds() / 2,
                    this.rlnConfig.rlnProofCacheExpirySeconds() / 2,
                    TimeUnit.SECONDS);

        } else {
            this.rlnVerifyingKeyBytes = null;
            LOG.info("RLN Validator is DISABLED.");
        }
    }

    private void initializeProofServiceClient() {
        boolean wasChannelProvided = (this.proofServiceChannel != null && !this.proofServiceChannel.isShutdown());

        if (wasChannelProvided) {
            LOG.info("Using pre-configured ManagedChannel for RLN Proof Service client.");
        } else {
            LOG.info("Creating new ManagedChannel for RLN Proof Service client based on configuration.");
            ManagedChannelBuilder<?> channelBuilder = ManagedChannelBuilder
                    .forAddress(rlnConfig.rlnProofServiceHost(), rlnConfig.rlnProofServicePort());
            
            if (rlnConfig.rlnProofServiceUseTls()) {
                channelBuilder.useTransportSecurity();
            } else {
                channelBuilder.usePlaintext();
            }
            this.proofServiceChannel = channelBuilder.build();
        }
        
        this.asyncProofStub = RlnProofServiceGrpc.newStub(this.proofServiceChannel);

        if (wasChannelProvided) {
            LOG.info("RLN Proof Service client initialized with injected ManagedChannel.");
        } else {
            LOG.info("RLN Proof Service client initialized for target: {}:{}", rlnConfig.rlnProofServiceHost(), rlnConfig.rlnProofServicePort());
        }
    }

    private void startProofStreamSubscription() {
        if (asyncProofStub == null) {
            LOG.error("Cannot start RLN proof stream: gRPC stub not initialized.");
            return;
        }
        LOG.info("Attempting to subscribe to RLN proof stream...");
        StreamProofsRequest request = StreamProofsRequest.newBuilder().setClientId("linea-sequencer-rln-validator").build();

        asyncProofStub.streamProofs(request, new StreamObserver<>() {
            @Override
            public void onNext(ProofMessage proofMessage) {
                LOG.debug("Received proof from gRPC stream for txHash: {}", proofMessage.getTxHash());
                CachedProof cachedProof = new CachedProof(
                        proofMessage.getProofBytesHex(),
                        proofMessage.getShareXHex(), proofMessage.getShareYHex(),
                        proofMessage.getEpochHex(), proofMessage.getRootHex(),
                        proofMessage.getNullifierHex(),
                        Instant.now()
                );
                if (rlnProofCache.size() < rlnConfig.rlnProofCacheMaxSize()) {
                    rlnProofCache.put(proofMessage.getTxHash(), cachedProof);
                } else {
                    LOG.warn("RLN proof cache full (size {}). Discarding proof for tx {}. Consider increasing rlnProofCacheMaxSize.",
                            rlnProofCache.size(), proofMessage.getTxHash());
                    // Optionally, could implement LRU eviction here on put if cache is full
                }
            }

            @Override
            public void onError(Throwable t) {
                LOG.error("RLN proof stream error: {}. Attempting to reconnect...", t.getMessage(), t);
                scheduleReconnection();
            }

            @Override
            public void onCompleted() {
                LOG.info("RLN proof stream completed by server. Attempting to reconnect...");
                scheduleReconnection();
            }
        });
    }
    
    private void scheduleReconnection() {
        if (grpcReconnectionScheduler == null || grpcReconnectionScheduler.isShutdown()) {
            grpcReconnectionScheduler = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "RlnGrpcReconnect"));
        }
        // Simple fixed delay reconnection. Could be made more sophisticated (e.g. exponential backoff)
        // and use rlnConfig.rlnProofStreamRetries()
        grpcReconnectionScheduler.schedule(this::startProofStreamSubscription, rlnConfig.rlnProofStreamRetryIntervalMs(), TimeUnit.MILLISECONDS);
        LOG.info("Scheduled gRPC proof stream reconnection in {} ms.", rlnConfig.rlnProofStreamRetryIntervalMs());
    }

    private void evictExpiredProofs() {
        LOG.debug("Running RLN proof cache eviction. Current size: {}", rlnProofCache.size());
        Instant expiryThreshold = Instant.now().minusSeconds(rlnConfig.rlnProofCacheExpirySeconds());
        rlnProofCache.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().cachedAt().isBefore(expiryThreshold);
            if (expired) {
                LOG.trace("Evicting expired proof for txHash: {} (cached at {})", entry.getKey(), entry.getValue().cachedAt());
            }
            return expired;
        });
        LOG.debug("RLN proof cache eviction finished. Size after eviction: {}", rlnProofCache.size());
    }

    private void loadDenyListFromFile() {
        if (!Files.exists(denyListFilePath)) {
            LOG.info("Deny list file not found at {}, starting with an empty list.", denyListFilePath);
            denyList.clear();
            return;
        }
        Map<Address, Instant> newDenyListCache = new ConcurrentHashMap<>();
        Instant now = Instant.now();
        long maxAgeMillis = TimeUnit.MINUTES.toMillis(rlnConfig.denyListEntryMaxAgeMinutes());
        boolean entriesPruned = false;

        try (BufferedReader reader = Files.newBufferedReader(denyListFilePath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",", 2);
                if (parts.length == 2) {
                    try {
                        Address address = Address.fromHexString(parts[0].trim());
                        Instant timestamp = Instant.parse(parts[1].trim());
                        if (now.toEpochMilli() - timestamp.toEpochMilli() < maxAgeMillis) {
                            newDenyListCache.put(address, timestamp);
                        } else {
                            entriesPruned = true;
                            LOG.debug("Expired deny list entry for {} (added at {}) removed during load.", address, timestamp);
                        }
                    } catch (IllegalArgumentException | DateTimeParseException e) {
                        LOG.warn("Invalid entry in deny list file: '{}'. Skipping. Error: {}", line, e.getMessage());
                    }
                } else {
                    LOG.warn("Malformed line in deny list file (expected 'address,timestamp'): '{}'", line);
                }
            }
            denyList.clear();
            denyList.putAll(newDenyListCache);
            LOG.info("Deny list loaded successfully from {}. {} active entries.", denyListFilePath, denyList.size());
            if (entriesPruned) {
                saveDenyListToFile();
            }
        } catch (IOException e) {
            LOG.error("Error loading deny list from {}: {}", denyListFilePath, e.getMessage(), e);
        }
    }

    private void saveDenyListToFile() {
        Map<Address, Instant> denyListSnapshot = new HashMap<>(denyList);
        List<String> entriesAsString = denyListSnapshot.entrySet().stream()
                .map(entry -> entry.getKey().toHexString().toLowerCase() + "," + entry.getValue().toString())
                .sorted()
                .collect(Collectors.toList());
        try {
            Path tempFilePath = denyListFilePath.getParent().resolve(denyListFilePath.getFileName().toString() + ".tmp_save");
            Files.write(tempFilePath, entriesAsString, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tempFilePath, denyListFilePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            LOG.debug("Deny list saved to file {} with {} entries.", denyListFilePath, entriesAsString.size());
        } catch (IOException e) {
            LOG.error("Error saving deny list to file {}: {}", denyListFilePath, e.getMessage(), e);
        }
    }

    void addToDenyList(final Address address) {
        if (denyList.put(address, Instant.now()) == null) {
            saveDenyListToFile();
            LOG.info("Address {} added to deny list at {}. Cache size: {}", address.toHexString(), denyList.get(address), denyList.size());
        }
    }

    boolean removeFromDenyList(final Address address) {
        if (denyList.remove(address) != null) {
            saveDenyListToFile();
            LOG.info("Address {} removed from deny list. Cache size: {}", address.toHexString(), denyList.size());
            return true;
        }
        return false;
    }

    void addToDenyListForTest(Address user, Instant addedAt) {
        denyList.put(user, addedAt);
        saveDenyListToFile();
    }

    boolean isDeniedForTest(Address user) {
        Instant addedAt = denyList.get(user);
        if (addedAt == null) return false;
        long maxAgeMillis = TimeUnit.MINUTES.toMillis(rlnConfig.denyListEntryMaxAgeMinutes());
        return (Instant.now().toEpochMilli() - addedAt.toEpochMilli()) < maxAgeMillis;
    }

    void loadDenyListFromFileForTest() {
        this.loadDenyListFromFile();
    }

    private String getCurrentEpochIdentifier() {
        var currentHeader = blockchainService.getChainHeadHeader();
        long timestamp = currentHeader.getTimestamp();
        long blockNumber = currentHeader.getNumber();

        return switch (rlnConfig.defaultEpochForQuota().toUpperCase()) {
            case "BLOCK" -> "B:" + blockNumber;
            case "TIMESTAMP_1H" -> "T:" + Instant.ofEpochSecond(timestamp).atZone(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH"));
            default -> {
                LOG.warn("Unknown defaultEpochForQuota: '{}'. Defaulting to block number.", rlnConfig.defaultEpochForQuota());
                yield "B:" + blockNumber;
            }
        };
    }
    
    private Optional<KarmaInfo> fetchKarmaInfoFromService(Address userAddress) {
        if (rlnConfig.karmaServiceUrl().isEmpty()) {
            LOG.warn("Karma service URL not configured. Cannot fetch karma info.");
            return Optional.empty();
        }
        String baseUrl = rlnConfig.karmaServiceUrl().get();
        // Ensure no double slashes if baseUrl ends with / and query starts with /
        String fullUrl = baseUrl.endsWith("/") ? baseUrl + "karma?userAddress=" : baseUrl + "/karma?userAddress=";
        fullUrl += userAddress.toHexString();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fullUrl))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(5)) // Per-request timeout
                .GET()
                .build();

        try {
            LOG.debug("Fetching karma info for user {} from {}", userAddress.toHexString(), fullUrl);
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String responseBody = response.body();
                LOG.debug("Karma service response for {}: {}", userAddress.toHexString(), responseBody);

                Matcher tierMatcher = KARMA_TIER_JSON_PATTERN.matcher(responseBody);
                Matcher countMatcher = KARMA_EPOCH_TX_COUNT_JSON_PATTERN.matcher(responseBody);
                Matcher quotaMatcher = KARMA_DAILY_QUOTA_JSON_PATTERN.matcher(responseBody);
                Matcher epochIdMatcher = KARMA_EPOCH_ID_JSON_PATTERN.matcher(responseBody);

                if (tierMatcher.find() && countMatcher.find() && quotaMatcher.find() && epochIdMatcher.find()) {
                    String tier = tierMatcher.group(1);
                    int epochTxCount = Integer.parseInt(countMatcher.group(1));
                    int dailyQuota = Integer.parseInt(quotaMatcher.group(1));
                    String epochId = epochIdMatcher.group(1);
                    return Optional.of(new KarmaInfo(tier, epochTxCount, dailyQuota, epochId));
                } else {
                    LOG.error("Failed to parse all required fields from Karma service response for user {}. Body: {}", userAddress.toHexString(), responseBody);
                    return Optional.empty();
                }
            } else {
                LOG.error("Karma service request for user {} failed with status code: {} and body: {}", userAddress.toHexString(), response.statusCode(), response.body());
                return Optional.empty();
            }
        } catch (IOException | InterruptedException e) {
            LOG.error("Error calling Karma service for user {}: {}", userAddress.toHexString(), e.getMessage(), e);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return Optional.empty();
        } catch (NumberFormatException e) {
            LOG.error("Failed to parse numeric value from Karma service response for user {}: {}", userAddress.toHexString(), e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> validateTransaction(Transaction transaction, boolean isLocal, boolean hasPriority) {
        if (!rlnConfig.rlnValidationEnabled()) {
            return Optional.empty(); // RLN validation is disabled
        }

        final Address sender = transaction.getSender();
        final org.hyperledger.besu.datatypes.Hash txHash = transaction.getHash();
        final String txHashString = txHash.toHexString();

        // 1. Deny List Check
        Instant deniedUntil = denyList.get(sender);
        if (deniedUntil != null) {
            if (Instant.now().isAfter(deniedUntil)) {
                denyList.remove(sender);
                saveDenyListToFile(); // Persist removal
                LOG.info("Removed expired deny list entry for sender: {}", sender.toHexString());
            } else {
                // User is actively denied. Check for premium gas.
                // Using convenience accessor from LineaRlnValidatorConfiguration for premiumGasPriceThresholdWei
                long premiumThresholdWei = rlnConfig.premiumGasPriceThresholdWei();
                Wei effectiveGasPrice = transaction.getGasPrice().map(q -> Wei.of(q.getAsBigInteger()))
                    .orElseGet(() -> transaction.getMaxFeePerGas().map(q -> Wei.of(q.getAsBigInteger())).orElse(Wei.ZERO));

                if (effectiveGasPrice.getAsBigInteger().compareTo(BigInteger.valueOf(premiumThresholdWei)) >= 0) {
                    denyList.remove(sender);
                    saveDenyListToFile(); // Persist removal
                    LOG.info("Sender {} was on deny list but paid premium gas ({} Wei >= {} Wei). Allowing and removing from deny list.",
                            sender.toHexString(), effectiveGasPrice, premiumThresholdWei);
                } else {
                    LOG.warn("Sender {} is on deny list. Transaction {} rejected. Effective gas price {} Wei < {} Wei.",
                            sender.toHexString(), txHashString, effectiveGasPrice, premiumThresholdWei);
                    return Optional.of("Sender on deny list, premium gas not met.");
                }
            }
        }

        // 2. RLN Proof Verification (via gRPC Cache)
        LOG.debug("Attempting to fetch RLN proof for txHash: {} from cache.", txHashString);
        CachedProof proof = rlnProofCache.get(txHashString);
        long proofWaitStartTime = System.currentTimeMillis();

        while (proof == null && (System.currentTimeMillis() - proofWaitStartTime) < rlnConfig.rlnProofLocalWaitTimeoutMs()) {
            try {
                Thread.sleep(50); // Poll moderately
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOG.warn("Proof polling interrupted for tx {}", txHashString, e);
                return Optional.of("Proof polling interrupted.");
            }
            proof = rlnProofCache.get(txHashString);
        }

        if (proof == null) {
            LOG.warn("RLN proof not found in cache after timeout for txHash: {}. Timeout: {}ms", txHashString, rlnConfig.rlnProofLocalWaitTimeoutMs());
            // Do not add to deny list here, this is a missing proof, not a failed proof or quota issue.
            return Optional.of("RLN proof not found in cache after timeout.");
        }
        LOG.debug("RLN proof found in cache for txHash: {}", txHashString);

        // Assemble public inputs from the cached proof
        String[] publicInputsHexArray = {
                proof.shareXHex(), proof.shareYHex(), proof.epochHex(), proof.rootHex(), proof.nullifierHex()
        };

        // Verify the proof using RlnBridge (JNI call)
        boolean rlnProofValid;
        try {
            rlnProofValid = RlnBridge.verifyRlnProof(rlnVerifyingKeyBytes, Bytes.fromHexString(proof.proofBytesHex()).toArrayUnsafe(), publicInputsHexArray);
        } catch (Exception e) { // Catch broader exceptions from JNI if any
            LOG.error("RLN JNI call to verifyRlnProof failed for tx {}: {}", txHashString, e.getMessage(), e);
            return Optional.of(RLN_VALIDATION_FAILED_MESSAGE + ": JNI exception - " + e.getMessage());
        }

        if (!rlnProofValid) {
            LOG.warn("RLN proof verification failed for tx: {}", txHashString);
            // Potentially add to deny list if a specific policy dictates (e.g., repeated invalid proofs).
            // For now, just reject.
            return Optional.of(RLN_VALIDATION_FAILED_MESSAGE + ": Proof invalid.");
        }
        LOG.info("RLN proof verified successfully for tx: {}", txHashString);

        // 3. Karma / Quota Check (via Karma Service API)
        if (rlnConfig.karmaServiceUrl().isPresent()) {
            Optional<KarmaInfo> karmaInfoOpt = fetchKarmaInfoFromService(sender);

            if (karmaInfoOpt.isEmpty()) {
                LOG.warn("Failed to retrieve karma information for sender {} from Karma Service. Transaction {} rejected.", sender.toHexString(), txHashString);
                // Fail-closed: if karma service is configured but fails to provide info, reject.
                return Optional.of("Karma service interaction failed.");
            }

            KarmaInfo karmaInfo = karmaInfoOpt.get();
            LOG.debug("Karma info for sender {}: Tier={}, EpochTxCount={}, DailyQuota={}, EpochId={}",
                    sender.toHexString(), karmaInfo.tier(), karmaInfo.epochTxCount(), karmaInfo.dailyQuota(), karmaInfo.epochId());
            
            String currentChainEpochId = getCurrentEpochIdentifier();
            LOG.debug("Current chain epoch identifier: {}", currentChainEpochId);

            // Note: The Karma service is the source of truth for epochTxCount relative to *its* reported epochId.
            // If karmaInfo.epochId() does not match currentChainEpochId, the Karma service might need to handle epoch transitions itself.
            // For the validator, we trust the counts and quota provided by the service for the user.
            // A more advanced check might involve comparing karmaInfo.epochId() with currentChainEpochId and acting if they mismatch,
            // but that depends on the agreed contract with the Karma service.
            // For now, we directly use the epochTxCount and dailyQuota provided by the service.

            if (karmaInfo.epochTxCount() >= karmaInfo.dailyQuota()) {
                LOG.warn("User {} (Tier: {}) has exceeded their transaction quota for epoch {}. Count: {}, Quota: {}. Transaction {} rejected.",
                        sender.toHexString(), karmaInfo.tier(), karmaInfo.epochId(), karmaInfo.epochTxCount(), karmaInfo.dailyQuota(), txHashString);
                addToDenyList(sender); // Add to deny list due to quota exceeded
                return Optional.of("User transaction quota exceeded for current epoch. Added to deny list.");
            } else {
                LOG.info("User {} (Tier: {}) is within transaction quota. Count: {}, Quota: {}. Transaction {} allowed by karma check.",
                        sender.toHexString(), karmaInfo.tier(), karmaInfo.epochTxCount(), karmaInfo.dailyQuota(), txHashString);
                // No need to increment count locally, Karma service manages this.
            }
        } else {
            LOG.info("Karma service URL not configured. Skipping karma/quota check for transaction {}.", txHashString);
            // If Karma service is not configured, we proceed without a quota check.
            // RLN proof verification itself is the primary gate.
        }

        LOG.info("Transaction {} from sender {} passed all RLN validations.", txHashString, sender.toHexString());
        return Optional.empty(); // Transaction is valid from RLN perspective
    }

    @Override
    public void close() throws IOException {
        LOG.info("Closing RlnVerifierValidator resources...");
        // Re-enable gRPC client and scheduler shutdown
        if (proofServiceChannel != null && !proofServiceChannel.isShutdown()) {
            proofServiceChannel.shutdown();
            try {
                if (!proofServiceChannel.awaitTermination(5, TimeUnit.SECONDS)) {
                    proofServiceChannel.shutdownNow();
                }
            } catch (InterruptedException e) {
                proofServiceChannel.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        if (denyListRefreshScheduler != null && !denyListRefreshScheduler.isShutdown()) {
            denyListRefreshScheduler.shutdownNow();
        }
        if (proofCacheEvictionScheduler != null && !proofCacheEvictionScheduler.isShutdown()) {
            proofCacheEvictionScheduler.shutdownNow();
        }
        if (grpcReconnectionScheduler != null && !grpcReconnectionScheduler.isShutdown()) {
            grpcReconnectionScheduler.shutdownNow();
        }
        LOG.info("RlnVerifierValidator resources closed.");
    }

    // Test-only helper to access the proof cache
    Optional<CachedProof> getProofFromCacheForTest(String txHash) {
        return Optional.ofNullable(rlnProofCache.get(txHash));
    }

    // Test-only helper to add to the proof cache
    void addProofToCacheForTest(String txHash, CachedProof proof) {
        if (rlnProofCache.size() < rlnConfig.rlnProofCacheMaxSize()) {
            rlnProofCache.put(txHash, proof);
        } else {
            LOG.warn("RLN proof cache full during test add. Consider increasing size or evicting.");
            // Potentially evict one to make space if really needed for a complex test scenario
            // For now, simple put or log warning.
             rlnProofCache.put(txHash, proof); // Allow overwrite or put if eviction not implemented here
        }
    }
} 