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
package se.swedenconnect.opensaml.xmlsec.algorithm;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;

/**
 * OpenSAML's {@link AlgorithmSupport} class does not offer utility methods needed for RSA-PSS. This class adds this.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public final class ExtendedAlgorithmSupport {

  /**
   * Predicate that tells whether the supplied algorithm is a RSA-PSS algorithm.
   * 
   * @param signatureAlgorithm
   *          the algorithm to test
   * @return true if the algorithm is a RSA-PSS algorithm, and false otherwise
   */
  public static boolean isRSAPSS(final String signatureAlgorithm) {
    return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1.equals(signatureAlgorithm)
        || XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1.equals(signatureAlgorithm);
  }

  // Hidden constructor.
  private ExtendedAlgorithmSupport() {
  }

}
