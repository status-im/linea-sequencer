package net.consensys.linea.rln.jni;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;

import org.apache.tuweni.bytes.Bytes;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

// These tests require the native library to be compiled and accessible.
// They might be disabled by default in CI if the native lib isn't built there.
// Use a system property, e.g., -Drln.native.tests.enabled=true to run them.
@EnabledIfSystemProperty(
    named = "rln.native.tests.enabled",
    matches = "true",
    disabledReason = "RLN Native tests are disabled. Set -Drln.native.tests.enabled=true")
public class RlnBridgeTest {

  private static byte[] verifyingKeyBytes;
  private static JSONArray testProofs;
  private static JSONObject testData;

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
      System.err.println(
          "Native library for RlnBridge not found. Skipping tests. Error: " + e.getMessage());
      // Rethrow or handle in a way that Junit understands the tests should be skipped if not using
      // @EnabledIf... based on this.
      throw e;
    }

    // Load the entire JSON file once
    try (InputStream inputStream =
        RlnBridgeTest.class.getClassLoader().getResourceAsStream("rln_test_data.json")) {
      if (inputStream == null) {
        throw new RuntimeException("Cannot find rln_test_data.json in test resources");
      }
      JSONTokener tokener = new JSONTokener(inputStream);
      testData = new JSONObject(tokener);
      // Pre-decode verifying key as it's used for all tests
      String vkHex = testData.getString("verifying_key_hex");
      verifyingKeyBytes = Bytes.fromHexString(vkHex).toArrayUnsafe();

      testProofs = testData.getJSONArray("test_proofs");
      assertNotNull(testProofs, "Test proofs array should not be null");
      assertTrue(testProofs.length() > 0, "Test proofs array should not be empty");

    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException("Failed to load and parse rln_test_data.json", e);
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

      byte[] proofBytes = Bytes.fromHexString(proofHex).toArrayUnsafe();
      String[] publicInputsHex = new String[5];
      publicInputsHex[0] = publicInputsJson.getString("share_x");
      publicInputsHex[1] = publicInputsJson.getString("share_y");
      publicInputsHex[2] = publicInputsJson.getString("epoch");
      publicInputsHex[3] = publicInputsJson.getString("root");
      publicInputsHex[4] = publicInputsJson.getString("nullifier");

      final int proofIndex = i; // for use in lambda
      try {
        boolean isValid = RlnBridge.verifyRlnProof(verifyingKeyBytes, proofBytes, publicInputsHex);
        assertTrue(
            isValid, "Proof #" + (proofIndex + 1) + " ('" + rawEpochString + "') should be valid.");
        System.out.println(
            "Proof #"
                + (proofIndex + 1)
                + " ('"
                + rawEpochString
                + "') verified successfully: "
                + isValid);
      } catch (UnsatisfiedLinkError e) {
        fail(
            "UnsatisfiedLinkError during RlnBridge.verifyRlnProof for proof #"
                + (proofIndex + 1)
                + ". Ensure native library is loaded. "
                + e.getMessage(),
            e);
      } catch (RuntimeException e) {
        fail(
            "RuntimeException during RlnBridge.verifyRlnProof for proof #"
                + (proofIndex + 1)
                + ". "
                + e.getMessage(),
            e);
      } catch (Exception e) {
        fail(
            "Unexpected exception during RlnBridge.verifyRlnProof for proof #"
                + (proofIndex + 1)
                + ". "
                + e.getMessage(),
            e);
      }
    }
    System.out.println("Successfully verified " + testProofs.length() + " proofs.");
  }

  @Test
  void testVerifyRlnProof_withValidAndInvalidProofs() {
    JSONArray proofs = testData.getJSONArray("test_proofs");
    assertNotNull(proofs, "Test proofs array should not be null");
    assertTrue(proofs.length() > 0, "Test proofs array should not be empty");

    for (int i = 0; i < proofs.length(); i++) {
      JSONObject proofEntry = proofs.getJSONObject(i);
      String proofHex = proofEntry.getString("proof");
      JSONObject publicInputsJson = proofEntry.getJSONObject("public_inputs");

      byte[] currentProofBytes = Bytes.fromHexString(proofHex).toArrayUnsafe();

      // Prepare publicInputsHex for RlnBridge
      String[] publicInputsHex =
          new String[] {
            publicInputsJson.getString("share_x"),
            publicInputsJson.getString("share_y"),
            publicInputsJson.getString("epoch"),
            publicInputsJson.getString("root"),
            publicInputsJson.getString("nullifier")
          };

      // For this test, we assume all proofs in rln_test_data.json are valid against the provided
      // VK.
      boolean isValid =
          RlnBridge.verifyRlnProof(verifyingKeyBytes, currentProofBytes, publicInputsHex);
      assertTrue(
          isValid,
          "Proof entry "
              + i
              + " (epoch: "
              + publicInputsJson.getString("epoch")
              + ", raw_epoch: "
              + proofEntry.optString("raw_epoch_string")
              + ") should be valid");
    }
  }
}
