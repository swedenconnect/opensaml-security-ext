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
package se.swedenconnect.opensaml.xmlsec.algorithm;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Static data operations for PSS padding
 */
public class PaddingOps {

  /**
   * Convert a BigInteger value to a byte array of a specified length.
   *
   * @param val the BigInteger value to be converted
   * @param len the length of the resulting byte array
   * @return the byte array representation of the BigInteger value
   * @throws IllegalArgumentException if the value requires more bytes than the assigned length size
   */
  public static byte[] i2osp(BigInteger val, int len) {
    // Get the byte array representation of the BigInteger
    byte[] lengthVal = val.toByteArray();

    // Clone and handle leading zero if present
    byte[] paddedLengthVal = lengthVal.clone();
    if (paddedLengthVal.length > 1 && paddedLengthVal[0] == 0x00) {
      // Remove leading 00
      paddedLengthVal = Arrays.copyOfRange(paddedLengthVal, 1, paddedLengthVal.length);
    }

    // Check if the byte array exceeds the required length
    if (paddedLengthVal.length > len) {
      throw new IllegalArgumentException("Value requires more bytes than the assigned length size");
    }

    // Padding to match the required length
    if (paddedLengthVal.length < len) {
      for (int i = paddedLengthVal.length; i < len; i++) {
        paddedLengthVal = Arrays.concatenate(new byte[]{0x00}, paddedLengthVal);
      }
    }

    return paddedLengthVal;
  }

  /**
   * Converts a byte array to a BigInteger.
   *
   * @param val the byte array to convert
   * @return the BigInteger representation of the byte array
   */
  public static BigInteger os2ip(byte[] val) {
    // Make sure we get a positive value by adding 0x00 as leading byte in the value byte array
    return new BigInteger(Arrays.concatenate(new byte[]{0x00}, val));
  }

  /**
   * Performs bitwise XOR operation on two byte arrays.
   *
   * @param arg1 the first byte array
   * @param arg2 the second byte array
   * @return the result of the XOR operation as a new byte array
   * @throws NullPointerException     if either arg1 or arg2 is null
   * @throws IllegalArgumentException if arg1 and arg2 have different lengths
   */
  public static byte[] xor(byte[] arg1, byte[] arg2) {
    Objects.requireNonNull(arg1, "XOR argument must not be null");
    Objects.requireNonNull(arg2, "XOR argument must not be null");

    if (arg1.length != arg2.length) {
      throw new IllegalArgumentException("XOR operation on parameters of different lengths");
    }
    byte[] xorArray = new byte[arg1.length];
    for (int i = 0; i < arg1.length; i++) {
      xorArray[i] = (byte) (arg1[i] ^ arg2[i]);
    }
    return xorArray;
  }

  public static byte[] concatenate(byte[]... arrays) {
    int totalLength = 0;

    // Calculate the total length of the resulting byte array
    for (byte[] array : arrays) {
      totalLength += array.length;
    }

    byte[] result = new byte[totalLength];
    int currentIndex = 0;

    // Copy each array into the result array
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, currentIndex, array.length);
      currentIndex += array.length;
    }

    return result;
  }


}
