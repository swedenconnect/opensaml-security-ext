/*
 * Copyright 2016-2025 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.opensaml.xmlsec.encryption.support;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;

class RsaOaepMgf1PaddingTest {

  @Test
  void testMgf1pPadding() throws Exception {

    this.testAgainstStandardOaepEcnryption(this.getOaepParameterSpec("SHA-1", "SHA-1", null));
    this.testAgainstExternalPadding(this.getOaepParameterSpec("SHA-1", "SHA-1", null));
    this.testAgainstStandardOaepEcnryption(this.getOaepParameterSpec("SHA-256", "SHA-1", null));
    this.testAgainstExternalPadding(this.getOaepParameterSpec("SHA-256", "SHA-1", null));
    this.testAgainstStandardOaepEcnryption(this.getOaepParameterSpec("SHA-256", "SHA-256", null));
    this.testAgainstExternalPadding(this.getOaepParameterSpec("SHA-256", "SHA-256", null));
  }

  void testAgainstExternalPadding(final OAEPParameterSpec oaepParams) throws Exception {
    this.testAgainstExternalPadding(oaepParams, null);
  }

  void testAgainstExternalPadding(final OAEPParameterSpec oaepParams, byte[] message) throws Exception {
    System.out.println("Testing against internal padding " + this.paramsToString(oaepParams));
    message = message == null ? "Test".getBytes() : message;
    final RsaOaepMgf1Padding rsaOaepMgf1Padding = new RsaOaepMgf1Padding(oaepParams, 2048);
    System.out.println("Encrypted message: " + Hex.toHexString(message));
    final byte[] paddedMessage = rsaOaepMgf1Padding.pad(message);
    System.out.println("Padded message: " + Hex.toHexString(paddedMessage));
    final byte[] unpadded = rsaOaepMgf1Padding.unpad(paddedMessage);
    System.out.println("Unpadded message: " + Hex.toHexString(unpadded));
    Assertions.assertArrayEquals(message, unpadded);
  }

  void testAgainstStandardOaepEcnryption(final OAEPParameterSpec oaepParams) throws Exception {
    this.testAgainstStandardOaepEcnryption(oaepParams, null);
  }

  void testAgainstStandardOaepEcnryption(final OAEPParameterSpec oaepParams, byte[] message) throws Exception {
    System.out.println("Testing against RSA encryption padding " + this.paramsToString(oaepParams));
    message = message == null ? "Test".getBytes() : message;
    System.out.println("Testing parameterspec " + this.paramsToString(oaepParams));
    System.out.println("Encrypted message: " + Hex.toHexString(message));
    final byte[] paddedMessage = generatePaddedMessage(message, oaepParams);
    System.out.println("Padded message: " + Hex.toHexString(paddedMessage));
    final RsaOaepMgf1Padding rsaOaepMgf1Padding = new RsaOaepMgf1Padding(oaepParams, 2048);
    final byte[] unpadded = rsaOaepMgf1Padding.unpad(paddedMessage);
    System.out.println("Unpadded message: " + Hex.toHexString(unpadded));
    Assertions.assertArrayEquals(message, unpadded);
  }

  private String paramsToString(final OAEPParameterSpec oaepParams) {
    return "OAEP-hash: " + oaepParams.getDigestAlgorithm() + ", "
        + "MGF-hash: " + oaepParams.getMGFAlgorithm() + ", "
        + "P-source algorithm: " + oaepParams.getPSource().getAlgorithm();
  }

  private OAEPParameterSpec getOaepParameterSpec(final String oaepHash, final String mgf1Hash, final String pSource) {
    final PSource ps = pSource == null
        ? PSource.PSpecified.DEFAULT
        : new PSource.PSpecified(pSource.getBytes());
    return new OAEPParameterSpec(oaepHash, "MGF1", new MGF1ParameterSpec(mgf1Hash), ps);
  }

  /**
   * Generates the test data for unpadding testing.
   *
   * @param message The message to encrypt.
   * @param oaepParams The OAEP parameters.
   * @return Unpadded bytes after raw RSA decryption.
   * @throws Exception If any cryptographic error occurs.
   */
  public static byte[] generatePaddedMessage(final byte[] message, final OAEPParameterSpec oaepParams)
      throws Exception {
    // 1. Generate RSA Key Pair
    final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048); // Use a 2048-bit RSA key
    final KeyPair keyPair = keyPairGen.generateKeyPair();
    final PublicKey publicKey = keyPair.getPublic();
    final PrivateKey privateKey = keyPair.getPrivate();

    // 3. Encrypt the message using RSA/OAEP
    final Cipher oaepCipher =
        Cipher.getInstance("RSA/ECB/OAEPWith" + oaepParams.getDigestAlgorithm() + "AndMGF1Padding");
    oaepCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
    final byte[] encryptedData = oaepCipher.doFinal(message);

    // 4. Decrypt the encrypted data using raw RSA (no padding)
    final Cipher rawCipher = Cipher.getInstance("RSA/ECB/NoPadding");
    rawCipher.init(Cipher.DECRYPT_MODE, privateKey);
    final byte[] rawDecryptedData = rawCipher.doFinal(encryptedData);

    // 5. Return raw decrypted data (unpadded)
    return rawDecryptedData;
  }
}
