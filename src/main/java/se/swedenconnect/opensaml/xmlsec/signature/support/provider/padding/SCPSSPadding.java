/*
 * Copyright 2019-2021 Sweden Connect
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
package se.swedenconnect.opensaml.xmlsec.signature.support.provider.padding;

import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

/**
 * Implements the RSA-PSS padding algorithm in accordance with PKCS#1 v2.1.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class SCPSSPadding {

  /** Default end byte. */
  private static final byte DEFAULT_END_BYTE = (byte) 0xBC;

  /** The digest. */
  private final MessageDigest messageDigest;

  /** Size (in bytes) of the digest produced by the above message digest. */
  private final int messageDigestSize;

  /** The Mask Generation Function. */
  private final MGF maskGenerationFunction;

  /** Encoded message length. */
  private final int emLength;

  /** Encoded message bits. */
  private final int emBits;

  /** The salt bytes. */
  private byte[] salt;

  /** Length of salt (in bytes). */
  private int saltLength;

  /** Random number generator. */
  private final SecureRandom rng = CryptoServicesRegistrar.getSecureRandom();

  /**
   * Constructor for the PSS padding generator. This padding generator uses the default parameter structure of RSA-PSS
   * where message digest equals MGF hash function and where salt length equals hash length and finally where the final
   * byte is set to 0xBC.
   *
   * @param messageDigest
   *          Message digest function
   * @param modulusBits
   *          number of modulus bits of the RSA key
   */
  public SCPSSPadding(final MessageDigest messageDigest, final int modulusBits) {
    if (messageDigest == null) {
      throw new NullPointerException("messageDigest must not be null");
    }
    this.messageDigest = messageDigest;
    this.messageDigestSize = messageDigest.getDigestLength();
    this.emBits = modulusBits - 1;
    this.emLength = (int) Math.ceil((double) this.emBits / (double) 8);
    this.maskGenerationFunction = new MGF1(messageDigest);
    this.saltLength = messageDigest.getDigestLength();
    this.salt = new byte[this.saltLength];
    this.rng.nextBytes(this.salt);
  }

  /**
   * Inject a predefined salt value
   *
   * @param salt
   *          predefined salt value;
   */
  public void setSalt(final byte[] salt) {
    this.salt = salt;
    this.saltLength = salt.length;
  }

  /**
   * Generates RSA-PSS encoded message (EM) for a given message.
   *
   * @param message
   *          message
   * @return encoded message (EM) for RSA PSS
   */
  public byte[] getPaddingFromMessage(final byte[] message) {    
    return this.getPadding(this.messageDigest.digest(message));
  }

  /**
   * Calculates the padding for a message hash.
   *
   * @param messageHash
   *          message hash
   * @return encoded message (EM) for RSA PSS
   * @throws IllegalArgumentException
   *           if specified modulus is to short
   */
  public byte[] getPadding(final byte[] messageHash) throws IllegalArgumentException {
    if (this.emLength < this.messageDigestSize + this.saltLength + 2) {
      throw new IllegalArgumentException("Illegal key modulus length for RSA PSS");
    }

    // Creating the M' block (8 bytes of 0x00 + mHash + salt)
    final byte[] mBlock = new byte[8 + this.messageDigestSize + this.saltLength];
    System.arraycopy(messageHash, 0, mBlock, 8, this.messageDigestSize);
    System.arraycopy(this.salt, 0, mBlock, 8 + this.messageDigestSize, this.saltLength);

    // Creating hash of M'
    final byte[] mBlockHash = this.messageDigest.digest(mBlock);    

    // Creating the DB block (padding + 0x01 + salt)
    final byte[] dbBlock = new byte[this.emLength - this.messageDigestSize - 1];
    dbBlock[this.emLength - this.messageDigestSize - this.saltLength - 2] = (byte) 0x01;
    System.arraycopy(this.salt, 0, dbBlock, dbBlock.length - this.saltLength, this.saltLength);

    // Creating MGF mask bytes from mBlockHash
    final byte[] dbMask = this.maskGenerationFunction.getMask(mBlockHash, dbBlock.length);

    // Creating the encoded message output data block
    final byte[] em = new byte[this.emLength];
    // XOR MGF mask with DB Block and store result in em
    for (int i = 0; i < dbBlock.length; i++) {
      em[i] = (byte) (dbBlock[i] ^ dbMask[i]);
    }

    // Set leading bits exceeding emBit length to 0
    em[0] &= 0xff >> this.emLength * 8 - this.emBits;

    // Copy M' block hash to EM
    System.arraycopy(mBlockHash, 0, em, dbBlock.length, this.messageDigestSize);
    // Set ending byte value
    em[this.emLength - 1] = SCPSSPadding.DEFAULT_END_BYTE;

    return em;
  }

}
