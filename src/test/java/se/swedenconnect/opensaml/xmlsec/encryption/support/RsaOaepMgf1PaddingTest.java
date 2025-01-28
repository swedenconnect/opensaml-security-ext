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

    testAgainstStandardOaepEcnryption(getOaepParameterSpec("SHA-1", "SHA-1", null));
    testAgainstExternalPadding(getOaepParameterSpec("SHA-1", "SHA-1", null));
    testAgainstStandardOaepEcnryption(getOaepParameterSpec("SHA-256", "SHA-1", null));
    testAgainstExternalPadding(getOaepParameterSpec("SHA-256", "SHA-1", null));
    testAgainstStandardOaepEcnryption(getOaepParameterSpec("SHA-256", "SHA-256", null));
    testAgainstExternalPadding(getOaepParameterSpec("SHA-256", "SHA-256", null));
  }

  void testAgainstExternalPadding(OAEPParameterSpec oaepParams) throws Exception {
    testAgainstExternalPadding(oaepParams, null);
  }

  void testAgainstExternalPadding(OAEPParameterSpec oaepParams, byte[] message) throws Exception {
    System.out.println("Testing against internal padding " + paramsToString(oaepParams));
    message = message == null ? "Test".getBytes() : message;
    RsaOaepMgf1Padding rsaOaepMgf1Padding = new RsaOaepMgf1Padding(oaepParams, 2048);
    System.out.println("Encrypted message: " + Hex.toHexString(message));
    byte[] paddedMessage = rsaOaepMgf1Padding.pad(message);
    System.out.println("Padded message: " + Hex.toHexString(paddedMessage));
    byte[] unpadded = rsaOaepMgf1Padding.unpad(paddedMessage);
    System.out.println("Unpadded message: " + Hex.toHexString(unpadded));
    Assertions.assertArrayEquals(message, unpadded);
  }

  void testAgainstStandardOaepEcnryption(OAEPParameterSpec oaepParams) throws Exception {
    testAgainstStandardOaepEcnryption(oaepParams, null);
  }

  void testAgainstStandardOaepEcnryption(OAEPParameterSpec oaepParams, byte[] message) throws Exception {
    System.out.println("Testing against RSA encryption padding " + paramsToString(oaepParams));
    message = message == null ? "Test".getBytes() : message;
    System.out.println("Testing parameterspec " + paramsToString(oaepParams));
    System.out.println("Encrypted message: " + Hex.toHexString(message));
    byte[] paddedMessage = generatePaddedMessage(message, oaepParams);
    System.out.println("Padded message: " + Hex.toHexString(paddedMessage));
    RsaOaepMgf1Padding rsaOaepMgf1Padding = new RsaOaepMgf1Padding(oaepParams, 2048);
    byte[] unpadded = rsaOaepMgf1Padding.unpad(paddedMessage);
    System.out.println("Unpadded message: " + Hex.toHexString(unpadded));
    Assertions.assertArrayEquals(message, unpadded);
  }

  private String paramsToString(OAEPParameterSpec oaepParams) {
    StringBuilder b = new StringBuilder();
    b.append("OAEP-hash: ").append(oaepParams.getDigestAlgorithm()).append(", ");
    b.append("MGF-hash: ").append(oaepParams.getMGFAlgorithm()).append(", ");
    b.append("P-source algorithm: ").append(oaepParams.getPSource().getAlgorithm());
    return b.toString();
  }

  private OAEPParameterSpec getOaepParameterSpec(String oaepHash, String mgf1Hash, String pSource) {
    PSource ps = pSource == null
      ? PSource.PSpecified.DEFAULT
      : new PSource.PSpecified(pSource.getBytes());
    return new OAEPParameterSpec(oaepHash, "MGF1", new MGF1ParameterSpec(mgf1Hash), ps);
  }

  /**
   * Generates the test data for unpadding testing.
   *
   * @param message    The message to encrypt.
   * @param oaepParams The OAEP parameters.
   * @return Unpadded bytes after raw RSA decryption.
   * @throws Exception If any cryptographic error occurs.
   */
  public static byte[] generatePaddedMessage(byte[] message, OAEPParameterSpec oaepParams) throws Exception {
    // 1. Generate RSA Key Pair
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048); // Use a 2048-bit RSA key
    KeyPair keyPair = keyPairGen.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    // 3. Encrypt the message using RSA/OAEP
    Cipher oaepCipher = Cipher.getInstance("RSA/ECB/OAEPWith" + oaepParams.getDigestAlgorithm() + "AndMGF1Padding");
    oaepCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
    byte[] encryptedData = oaepCipher.doFinal(message);

    // 4. Decrypt the encrypted data using raw RSA (no padding)
    Cipher rawCipher = Cipher.getInstance("RSA/ECB/NoPadding");
    rawCipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] rawDecryptedData = rawCipher.doFinal(encryptedData);

    // 5. Return raw decrypted data (unpadded)
    return rawDecryptedData;
  }
}