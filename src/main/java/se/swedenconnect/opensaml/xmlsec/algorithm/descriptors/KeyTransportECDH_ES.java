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

import org.opensaml.xmlsec.algorithm.KeyAgreementAlgorithm;

import se.swedenconnect.opensaml.xmlsec.encryption.support.EcEncryptionConstants;

/**
 * Algorithm descriptor for key agreement algorithm: Elliptic Curve Diffie-Hellman Ephemeral Static.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyTransportECDH_ES implements KeyAgreementAlgorithm {

  /** {@inheritDoc} */
  @Override
  public String getURI() {
    return EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES;
  }

  /** {@inheritDoc} */
  @Override
  public AlgorithmType getType() {
    return AlgorithmType.KeyAgreement;
  }

  /** {@inheritDoc} */
  @Override
  public String getJCAAlgorithmID() {
    return "ECDH";  
  }

}
