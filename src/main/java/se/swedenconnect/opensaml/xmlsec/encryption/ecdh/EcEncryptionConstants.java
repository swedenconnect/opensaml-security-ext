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
package se.swedenconnect.opensaml.xmlsec.encryption.ecdh;

import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

/**
 * Constants for Elliptic Curve Diffie-Hellman algorithms.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EcEncryptionConstants {

  /** Key Derivation - ConcatKDF. */
  public static final String ALGO_ID_KEYDERIVATION_CONCAT = EncryptionConstants.XMLENC11_NS + "ConcatKDF";

  /** Key Agreement - ECDH-ES. */
  public static final String ALGO_ID_KEYAGREEMENT_ECDH_ES = EncryptionConstants.XMLENC11_NS + "ECDH-ES";

  /** Hidden constructor. */
  protected EcEncryptionConstants() {}

}
