/*
 * Copyright 2019 Sweden Connect
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
package se.swedenconnect.opensaml.xmlsec.algorithm.descriptors;

import javax.annotation.Nonnull;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;

/**
 * Algorithm descriptor for signature algorithm: http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignatureSHA3_256_RSA_MGF1 implements SignatureAlgorithm {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getKey() {
    return JCAConstants.KEY_ALGO_RSA;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getURI() {
    return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AlgorithmType getType() {
    return AlgorithmType.Signature;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getJCAAlgorithmID() {
    return "SHA3-256withRSAandMGF1";
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getDigest() {
    return "SHA3-256";
  }

}
