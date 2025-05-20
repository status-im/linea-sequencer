package net.consensys.linea.rln.jni;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

// These tests require the native library to be compiled and accessible.
// They might be disabled by default in CI if the native lib isn't built there.
// Use a system property, e.g., -Drln.native.tests.enabled=true to run them.
@EnabledIfSystemProperty(named = "rln.native.tests.enabled", matches = "true", disabledReason = "RLN Native tests are disabled. Set -Drln.native.tests.enabled=true")
public class RlnBridgeTest {

    private static byte[] verifyingKeyBytes;
    private static JSONArray testProofs;

    @BeforeAll
    static void setUpClass() throws Exception {
        // Ensure RlnBridge class is loaded, which loads the native library.
        // This might throw UnsatisfiedLinkError if the library is not found.
        try {
            Class.forName(RlnBridge.class.getName());
            System.out.println("RlnBridge class loaded, native library should be loaded.");
        } catch (ClassNotFoundException e) {
            fail("RlnBridge class not found: " + e.getMessage());
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native library for RlnBridge not found. Skipping tests. Error: " + e.getMessage());
            // Rethrow or handle in a way that Junit understands the tests should be skipped if not using @EnabledIf... based on this.
            throw e;
        }

        // Load test data from JSON file in resources
        try (InputStream inputStream = RlnBridgeTest.class.getClassLoader().getResourceAsStream("rln_test_data.json")) {
            if (inputStream == null) {
                fail("Cannot find rln_test_data.json in test resources.");
            }
            JSONTokener tokener = new JSONTokener(inputStream);
            JSONObject testData = new JSONObject(tokener);

            String vkHex = testData.getString("verifying_key_hex");
            verifyingKeyBytes = hexToBytes(vkHex);
            assertNotNull(verifyingKeyBytes, "Verifying key bytes should not be null");

            testProofs = testData.getJSONArray("test_proofs");
            assertNotNull(testProofs, "Test proofs array should not be null");
            assertTrue(testProofs.length() > 0, "Test proofs array should not be empty");

        } catch (Exception e) {
            e.printStackTrace();
            fail("Error loading or parsing rln_test_data.json: " + e.getMessage());
        }
    }

    @Test
    void verifyAllProofsFromTestData() {
        if (verifyingKeyBytes == null || testProofs == null) {
            fail("Test data not loaded properly, skipping verification.");
        }

        for (int i = 0; i < testProofs.length(); i++) {
            JSONObject proofEntry = testProofs.getJSONObject(i);
            String proofHex = proofEntry.getString("proof");
            JSONObject publicInputsJson = proofEntry.getJSONObject("public_inputs");
            String rawEpochString = proofEntry.optString("raw_epoch_string", "Epoch " + i);

            byte[] proofBytes = hexToBytes(proofHex);
            String[] publicInputsHex = new String[5];
            publicInputsHex[0] = publicInputsJson.getString("share_x");
            publicInputsHex[1] = publicInputsJson.getString("share_y");
            publicInputsHex[2] = publicInputsJson.getString("epoch");
            publicInputsHex[3] = publicInputsJson.getString("root");
            publicInputsHex[4] = publicInputsJson.getString("nullifier");

            final int proofIndex = i; // for use in lambda
            try {
                boolean isValid = RlnBridge.verifyRlnProof(verifyingKeyBytes, proofBytes, publicInputsHex);
                assertTrue(isValid, "Proof #" + (proofIndex + 1) + " ('" + rawEpochString + "') should be valid.");
                System.out.println("Proof #" + (proofIndex + 1) + " ('" + rawEpochString + "') verified successfully: " + isValid);
            } catch (UnsatisfiedLinkError e) {
                fail("UnsatisfiedLinkError during RlnBridge.verifyRlnProof for proof #" + (proofIndex + 1) + ". Ensure native library is loaded. " + e.getMessage(), e);
            } catch (RuntimeException e) {
                fail("RuntimeException during RlnBridge.verifyRlnProof for proof #" + (proofIndex + 1) + ". " + e.getMessage(), e);
            } catch (Exception e) {
                fail("Unexpected exception during RlnBridge.verifyRlnProof for proof #" + (proofIndex + 1) + ". " + e.getMessage(), e);
            }
        }
        System.out.println("Successfully verified " + testProofs.length() + " proofs.");
    }

    // Helper to convert hex string to byte array (from RlnVerifierValidator or similar)
    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            throw new IllegalArgumentException("Hex string cannot be null or empty");
        }
        String cleanHex = hex.startsWith("0x") ? hex.substring(2) : hex;
        if (cleanHex.length() % 2 != 0) {
            // Pad with a leading zero if odd length
            cleanHex = "0" + cleanHex;
        }
        byte[] data = new byte[cleanHex.length() / 2];
        for (int i = 0; i < cleanHex.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(cleanHex.charAt(i), 16) << 4)
                    + Character.digit(cleanHex.charAt(i + 1), 16));
        }
        return data;
    }
} 