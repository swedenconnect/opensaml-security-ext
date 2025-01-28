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
package se.swedenconnect.opensaml.xmlsec.signature.support.provider.padding;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import com.google.common.primitives.Bytes;

/**
 * Implementation of the MGF1 mask generation function.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class MGF1 implements MGF {

  /** The digest. */
  private final MessageDigest digest;

  /** The digest size (in bytes). */
  private final int digestSize;

  /**
   * Constructor.
   *
   * @param digest the digest function for the MGF
   */
  public MGF1(final MessageDigest digest) {
    this.digest = digest;
    this.digestSize = this.digest.getDigestLength();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getMask(final byte[] seed, final int length) {
    byte[] maskBytes = new byte[] {};
    final int n = (int) Math.ceil((double) length / (double) this.digestSize);
    for (int i = 0; i < n; i++) {
      final byte[] counterBytes = getCounterBytes(i);
      final byte[] maskFragment = this.concatenateAndHash(seed, counterBytes);
      maskBytes = Bytes.concat(maskBytes, maskFragment);
    }
    return Arrays.copyOf(maskBytes, length);
  }

  /**
   * Concatenates and hashes the seed and counter bytes.
   *
   * @param seed the seed bytes
   * @param counter the counter bytes
   * @return the digest of the concatenation
   */
  private byte[] concatenateAndHash(final byte[] seed, final byte[] counter) {
    this.digest.reset();
    this.digest.update(seed, 0, seed.length);
    this.digest.update(counter, 0, counter.length);
    return this.digest.digest();
  }

  /**
   * Returns a 4 octet representation of the supplied counter.
   *
   * @param counter the counter
   * @return octet representation
   */
  private static byte[] getCounterBytes(final int counter) {
    final BigInteger c = BigInteger.valueOf(counter);
    final int requiredBytes = (int) Math.ceil((double) c.bitLength() / (double) 8);
    byte[] counterBytes = c.toByteArray();

    // Pad
    final int byteLen = counterBytes.length;
    if (byteLen > requiredBytes) {
      // Sign bit is in extra byte
      counterBytes = Arrays.copyOfRange(counterBytes, 1, byteLen);
    }

    for (int i = 0; i < (4 - requiredBytes); i++) {
      counterBytes = Bytes.concat(new byte[] { 0x00 }, counterBytes);
    }
    return counterBytes;
  }

}
