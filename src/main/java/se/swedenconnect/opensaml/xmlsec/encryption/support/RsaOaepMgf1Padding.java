/*
 * Copyright 2019-2025 Sweden Connect
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

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import se.swedenconnect.opensaml.xmlsec.algorithm.PaddingOps;
import se.swedenconnect.opensaml.xmlsec.signature.support.provider.padding.MGF1;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Random;

/**
 * Represents the RSA-OAEP-MGF1 padding mechanism for use in RSA encryption and decryption. This implementation provides
 * padding and unpadding functionalities following the OAEP (Optimal Asymmetric Encryption Padding) scheme, using MGF1
 * as the mask generation function. The class ensures compatibility with the defined RSA key length and associated
 * padding parameters.
 * <p>
 * RSA-OAEP is widely used for securely encrypting data with RSA. It combines the use of hash functions and MGF1 to
 * provide semantic security against chosen plaintext attacks.
 */
public class RsaOaepMgf1Padding {

  private static final Random RNG = CryptoServicesRegistrar.getSecureRandom();

  private final int hLen;
  private final int rsaModByteLen;
  private final int emLen;
  private final int dataMaxLen;
  private final MGF1 mgf1;
  private final MessageDigest md;
  private final MessageDigest mgfDigest;
  private final OAEPParameterSpec parameterSpec;

  /**
   * Constructs an instance of the RsaOaepMgf1Padding class, initializing it with the provided OAEP parameter
   * specification and RSA key length in bits. It validates and configures the digest functions, computes essential
   * parameters for padding operations, and ensures the RSA key length is suitable for RSA-OAEP padding.
   *
   * @param parameterSpec the OAEP parameter specification, which includes the digest algorithm, MGF parameters, and
   *     possibly more, providing configuration details for the padding
   * @param rsaKeyLengthBits the length of the RSA key, in bits. This should be a multiple of 8 and is used to
   *     calculate padding parameters and data constraints
   * @throws NoSuchAlgorithmException if the specified digest algorithm in the provided parameter specification or
   *     the MGF parameters is not available
   * @throws IllegalArgumentException if the MGF parameters are not of type MGF1ParameterSpec, or if
   *     rsaKeyLengthBits is not a multiple of 8
   */
  public RsaOaepMgf1Padding(final OAEPParameterSpec parameterSpec, final int rsaKeyLengthBits)
      throws NoSuchAlgorithmException {
    this.md = MessageDigest.getInstance(parameterSpec.getDigestAlgorithm());
    if (parameterSpec.getMGFParameters() instanceof final MGF1ParameterSpec mgf1ParameterSpec) {
      this.mgfDigest = MessageDigest.getInstance(mgf1ParameterSpec.getDigestAlgorithm());
    }
    else {
      throw new IllegalArgumentException("Illegal MGF1 parameter spec");
    }
    this.hLen = this.md.getDigestLength();
    this.mgf1 = new MGF1(this.mgfDigest);
    this.parameterSpec = parameterSpec;
    if (rsaKeyLengthBits % 8 != 0) {
      throw new IllegalArgumentException("RSA key length bits must be a factor of 8 (" + rsaKeyLengthBits + " bits)");
    }
    this.rsaModByteLen = rsaKeyLengthBits / 8;
    this.emLen = (rsaKeyLengthBits - 1 + 7) / 8; // Equal to ceil (((rsaKeyLengthBits-1)/8))
    this.dataMaxLen = this.rsaModByteLen - (2 * this.hLen) - 2;
  }

  /**
   * Pads the given data array using RSA-OAEP padding with a randomly generated seed.
   *
   * @param data the input data to be padded, which should not exceed the maximum allowable length based on the RSA
   *     modulus size and padding parameters
   * @return a byte array containing the padded data
   * @throws BadPaddingException if the input data length exceeds the allowable limit for padding or if the padding
   *     process encounters an error
   */
  public byte[] pad(final byte[] data) throws BadPaddingException {
    final byte[] seed = new byte[this.hLen];
    RNG.nextBytes(seed);
    return this.pad(data, seed);
  }

  /**
   * Pads the given data array using RSA-OAEP padding with the specified seed.
   *
   * @param data the input data to be padded, which must not exceed the maximum allowable length based on the RSA
   *     modulus size and padding parameters
   * @param seed the seed value used for mask generation in the padding process
   * @return a byte array containing the padded data
   * @throws BadPaddingException if the input data length exceeds the allowable limit for padding or if the padding
   *     process encounters an error
   */
  public byte[] pad(final byte[] data, final byte[] seed) throws BadPaddingException {
    if (data.length > this.dataMaxLen) {
      throw new BadPaddingException("Too long data message for this RSA modulus (" + this.rsaModByteLen + " bits)");
    }

    final int psLen = this.rsaModByteLen - data.length - (2 * this.hLen) - 2;
    final int dbLen = this.hLen + psLen + 1 + data.length;
    final byte[] ps = new byte[psLen];
    final byte[] pInput;
    if (this.parameterSpec.getPSource() instanceof final PSource.PSpecified pSpecified) {
      pInput = pSpecified.getValue();
    }
    else {
      throw new BadPaddingException("Unsupported padding algorithm");
    }
    this.md.reset();
    final byte[] pHash = this.md.digest(pInput);
    this.md.reset();
    final byte[] db = PaddingOps.concatenate(pHash, ps, new byte[] { 0x01 }, data);
    final byte[] dbMask = this.mgf1.getMask(seed, dbLen);
    final byte[] maskedDb = PaddingOps.xor(db, dbMask);
    final byte[] seedMask = this.mgf1.getMask(maskedDb, this.hLen);
    final byte[] maskedSeed = PaddingOps.xor(seed, seedMask);

    return PaddingOps.i2osp(PaddingOps.os2ip(PaddingOps.concatenate(maskedSeed, maskedDb)), this.emLen);
  }

  /**
   * Removes the padding from the provided byte array, reversing the RSA-OAEP padding process.
   *
   * @param padded the input byte array containing padded data. Its length must match the expected padded size, and
   *     it must conform to RSA-OAEP padding structure, including the specified padding and data encoding.
   * @return a byte array containing the original unpadded data extracted from the padded input
   * @throws BadPaddingException if the input does not conform to RSA-OAEP padding scheme, including errors like
   *     mismatched lengths, incorrect padding format, or hash validation failures
   */
  public byte[] unpad(final byte[] padded) throws BadPaddingException {
    if (padded.length != this.emLen) {
      throw new BadPaddingException(
          String.format("Decryption error. The padded array length (%d) is not the specified padded size (%d)",
              padded.length, this.emLen));
    }
    if (padded[0] != 0) {
      throw new BadPaddingException("First byte of padded data must be zero");
    }
    final byte[] maskedSeed = Arrays.copyOfRange(padded, 1, this.hLen + 1);
    final byte[] maskedDb = Arrays.copyOfRange(padded, this.hLen + 1, padded.length);
    final byte[] seedMask = this.mgf1.getMask(maskedDb, this.hLen);
    final byte[] seed = PaddingOps.xor(maskedSeed, seedMask);
    final byte[] dbMask = this.mgf1.getMask(seed, maskedDb.length);
    final byte[] db = PaddingOps.xor(maskedDb, dbMask);
    final byte[] pHash = Arrays.copyOfRange(db, 0, this.hLen);
    final byte[] psAndData = Arrays.copyOfRange(db, this.hLen, db.length);
    final byte[] data = this.getData(psAndData);
    this.md.reset();
    final byte[] pInput;
    if (this.parameterSpec.getPSource() instanceof final PSource.PSpecified pSpecified) {
      pInput = pSpecified.getValue();
    }
    else {
      throw new BadPaddingException("Unsupported padding algorithm");
    }
    final byte[] pHash2 = this.md.digest(pInput);
    if (!Arrays.equals(pHash, pHash2)) {
      throw new BadPaddingException("Padding error");
    }
    return data;
  }

  private byte[] getData(final byte[] psAndData) throws BadPaddingException {
    int index = 0;

    // Skip leading 0x00 bytes
    while (index < psAndData.length && psAndData[index] == 0x00) {
      index++;
    }

    // Check if the next byte is 0x01
    if (index >= psAndData.length || psAndData[index] != 0x01) {
      throw new BadPaddingException("Padding structure is invalid. Expected a 0x01 byte after 0x00 bytes.");
    }

    // Return the data after 0x01
    return Arrays.copyOfRange(psAndData, index + 1, psAndData.length);
  }
}
