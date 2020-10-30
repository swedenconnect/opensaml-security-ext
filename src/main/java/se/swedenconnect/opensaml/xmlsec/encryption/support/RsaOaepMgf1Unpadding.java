/*
 * Copyright 2020 Sweden Connect
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

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Support class for the {@link Pkcs11Decrypter}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class RsaOaepMgf1Unpadding {

  // Size of the padded block (i.e. size of the modulus)
  private final int paddedSize;

  // Maximum size of the data
  private final int maxDataSize;

  // Main message digest
  private MessageDigest md;

  // MGF1 message digest
  private MessageDigest mgfMessageDigest;

  // Value of digest of data (user-supplied or zero-length) using md
  private final byte[] lHash;

  /**
   * Constructor.
   * 
   * @param paddedSize
   *          the padded size
   * @param spec
   *          the OAEP parameter specification
   * @throws InvalidKeyException
   *           for invalid keys
   * @throws InvalidAlgorithmParameterException
   *           for invalid parameters
   */
  public RsaOaepMgf1Unpadding(final int paddedSize, final OAEPParameterSpec spec)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

    this.paddedSize = paddedSize;
    if (paddedSize < 64) {
      throw new InvalidKeyException("Padded size must be at least 64");
    }
    String mdName = "SHA-1";
    String mgfMdName = mdName;
    byte[] digestInput = null;
    try {
      mdName = spec.getDigestAlgorithm();
      mgfMdName = ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm();
      final PSource pSrc = spec.getPSource();
      digestInput = ((PSource.PSpecified) pSrc).getValue();
      this.md = MessageDigest.getInstance(mdName);
      this.mgfMessageDigest = MessageDigest.getInstance(mgfMdName);
    }
    catch (final NoSuchAlgorithmException e) {
      throw new InvalidKeyException("Digest not available", e);
    }
    this.lHash = getInitialHash(this.md, digestInput);
    final int digestLen = this.lHash.length;
    this.maxDataSize = paddedSize - 2 - 2 * digestLen;
    if (this.maxDataSize <= 0) {
      throw new InvalidKeyException("Key is too short for encryption using OAEPPadding" +
          " with " + mdName + " and MGF1" + this.mgfMessageDigest.getAlgorithm());
    }
  }

  /**
   * Unpads the supplied data.
   * 
   * @param padded
   *          the padded data
   * @return the unpadded data
   * @throws BadPaddingException
   *           for bad padding
   */
  public byte[] unpad(final byte[] padded) throws BadPaddingException {
    if (padded.length != this.paddedSize) {
      throw new BadPaddingException(
        String.format("Decryption error. The padded array length (%d) is not the specified padded size (%d)",
          padded.length, this.paddedSize));
    }

    final byte[] EM = padded;
    boolean bp = false;
    final int hLen = this.lHash.length;

    if (EM[0] != 0) {
      bp = true;
    }

    final int seedStart = 1;
    final int seedLen = hLen;

    final int dbStart = hLen + 1;
    final int dbLen = EM.length - dbStart;

    this.generateAndXor(EM, dbStart, dbLen, seedLen, EM, seedStart);
    this.generateAndXor(EM, seedStart, seedLen, dbLen, EM, dbStart);

    // verify lHash == lHash'
    for (int i = 0; i < hLen; i++) {
      if (this.lHash[i] != EM[dbStart + i]) {
        bp = true;
      }
    }

    final int padStart = dbStart + hLen;
    int onePos = -1;

    for (int i = padStart; i < EM.length; i++) {
      final int value = EM[i];
      if (onePos == -1) {
        if (value == 0x00) {
          // continue;
        }
        else if (value == 0x01) {
          onePos = i;
        }
        else {  // Anything other than {0,1} is bad.
          bp = true;
        }
      }
    }

    // We either ran off the rails or found something other than 0/1.
    if (onePos == -1) {
      bp = true;
      onePos = EM.length - 1;  // Don't inadvertently return any data.
    }

    final int mStart = onePos + 1;

    // copy useless padding array for a constant-time method
    final byte[] tmp = new byte[mStart - padStart];
    System.arraycopy(EM, padStart, tmp, 0, tmp.length);

    final byte[] m = new byte[EM.length - mStart];
    System.arraycopy(EM, mStart, m, 0, m.length);

    if (bp) {
      throw new BadPaddingException("Decryption error");
    }
    else {
      return m;
    }
  }

  private void generateAndXor(
      final byte[] seed, final int seedOfs, final int seedLen, int maskLen, final byte[] out, int outOfs)
      throws RuntimeException 
  {
    final byte[] C = new byte[4]; // 32 bit counter
    final byte[] digest = new byte[this.md.getDigestLength()];
    while (maskLen > 0) {
      this.mgfMessageDigest.update(seed, seedOfs, seedLen);
      this.mgfMessageDigest.update(C);
      try {
        this.mgfMessageDigest.digest(digest, 0, digest.length);
      }
      catch (final DigestException e) {
        // should never happen
        throw new RuntimeException(e.toString());
      }
      for (int i = 0; i < digest.length && maskLen > 0; maskLen--) {
        out[outOfs++] ^= digest[i++];
      }
      if (maskLen > 0) {
        // increment counter
        for (int i = C.length - 1; ++C[i] == 0 && i > 0; i--) {
          // empty
        }
      }
    }
  }

  private static final Map<String, byte[]> emptyHashes = Collections.synchronizedMap(new HashMap<String, byte[]>());

  private static byte[] getInitialHash(final MessageDigest md, final byte[] digestInput) {
    byte[] result;
    if (digestInput == null || digestInput.length == 0) {
      final String digestName = md.getAlgorithm();
      result = emptyHashes.get(digestName);
      if (result == null) {
        result = md.digest();
        emptyHashes.put(digestName, result);
      }
    }
    else {
      result = md.digest(digestInput);
    }
    return result;
  }

}
