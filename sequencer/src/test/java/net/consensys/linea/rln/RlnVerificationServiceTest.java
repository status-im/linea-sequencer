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
package net.consensys.linea.rln;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test class demonstrating how the new RLN verification architecture makes testing easier.
 * 
 * <p>This example shows:
 * <ul>
 *   <li>Easy mocking without JNI dependencies</li>
 *   <li>Configurable test scenarios</li>
 *   <li>Clean separation of concerns</li>
 *   <li>Better error handling</li>
 * </ul>
 */
class RlnVerificationServiceTest {

  private MockRlnVerificationService mockService;
  private byte[] dummyVerifyingKey;
  private byte[] dummyProofBytes;
  private String[] validPublicInputs;

  @BeforeEach
  void setUp() {
    mockService = new MockRlnVerificationService();
    dummyVerifyingKey = new byte[]{1, 2, 3, 4};
    dummyProofBytes = new byte[]{5, 6, 7, 8};
    validPublicInputs = new String[]{
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x2b1c4b4e1f1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",
        "0x3a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789abcdef0"
    };
  }

  @Test
  void testSuccessfulVerification() throws Exception {
    // Given: Mock configured for successful verification
    mockService.setVerificationResult(true);

    // When: Verify a proof
    boolean result = mockService.verifyRlnProof(dummyVerifyingKey, dummyProofBytes, validPublicInputs);

    // Then: Verification succeeds
    assertThat(result).isTrue();
  }

  @Test
  void testFailedVerification() throws Exception {
    // Given: Mock configured for failed verification
    mockService.setVerificationResult(false);

    // When: Verify a proof
    boolean result = mockService.verifyRlnProof(dummyVerifyingKey, dummyProofBytes, validPublicInputs);

    // Then: Verification fails
    assertThat(result).isFalse();
  }

  @Test
  void testVerificationException() {
    // Given: Mock configured to throw exception
    mockService.setThrowException(true, "Test verification error");

    // When/Then: Verification throws exception
    assertThatThrownBy(() -> mockService.verifyRlnProof(dummyVerifyingKey, dummyProofBytes, validPublicInputs))
        .isInstanceOf(RlnVerificationService.RlnVerificationException.class)
        .hasMessage("Test verification error");
  }

  @Test
  void testParseAndVerifyProof() throws Exception {
    // Given: Mock configured with custom proof data
    String epoch = "0x123456789abcdef0";
    RlnVerificationService.RlnProofData customData = new RlnVerificationService.RlnProofData(
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222222222222222222222222222",
        epoch,
        "0x3333333333333333333333333333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444444444444444444444444444",
        true
    );
    mockService.setMockProofData(customData);

    // When: Parse and verify proof
    RlnVerificationService.RlnProofData result = mockService.parseAndVerifyRlnProof(
        dummyVerifyingKey, dummyProofBytes, epoch);

    // Then: Returns expected data with correct epoch
    assertThat(result.shareX()).isEqualTo("0x1111111111111111111111111111111111111111111111111111111111111111");
    assertThat(result.shareY()).isEqualTo("0x2222222222222222222222222222222222222222222222222222222222222222");
    assertThat(result.epoch()).isEqualTo(epoch); // Should use provided epoch
    assertThat(result.root()).isEqualTo("0x3333333333333333333333333333333333333333333333333333333333333333");
    assertThat(result.nullifier()).isEqualTo("0x4444444444444444444444444444444444444444444444444444444444444444");
    assertThat(result.isValid()).isTrue();
  }

  @Test
  void testServiceAvailability() {
    // Then: Mock service is always available
    assertThat(mockService.isAvailable()).isTrue();
    assertThat(mockService.getImplementationInfo()).contains("Mock RLN verification service");
  }

  @Test
  void testInvalidPublicInputs() {
    // Given: Invalid public inputs (wrong number)
    String[] invalidInputs = new String[]{"0x123", "0x456"}; // Only 2 instead of 5

    // When/Then: Should throw exception
    assertThatThrownBy(() -> mockService.verifyRlnProof(dummyVerifyingKey, dummyProofBytes, invalidInputs))
        .isInstanceOf(RlnVerificationService.RlnVerificationException.class)
        .hasMessage("Expected exactly 5 public inputs, got: 2");
  }

  @Test
  void testFactoryAutoSelection() {
    // When: Create service with auto selection
    RlnVerificationService service = RlnVerificationServiceFactory.createAutoService();

    // Then: Should return available service (likely mock since native may not be available in tests)
    assertThat(service).isNotNull();
    assertThat(service.isAvailable()).isTrue();
  }

  @Test
  void testFactoryMockCreation() {
    // When: Explicitly create mock service
    RlnVerificationService service = RlnVerificationServiceFactory.create(
        RlnVerificationServiceFactory.ServiceType.MOCK);

    // Then: Should return mock service
    assertThat(service).isInstanceOf(MockRlnVerificationService.class);
    assertThat(service.isAvailable()).isTrue();
    assertThat(service.getImplementationInfo()).contains("Mock RLN verification service");
  }

  @Test
  void testMockReset() throws Exception {
    // Given: Mock configured with non-default behavior
    mockService.setVerificationResult(false);
    mockService.setThrowException(true, "Error");

    // When: Reset the mock
    mockService.reset();

    // Then: Should return to default behavior (successful verification, no exceptions)
    boolean result = mockService.verifyRlnProof(dummyVerifyingKey, dummyProofBytes, validPublicInputs);
    assertThat(result).isTrue();
  }
} 