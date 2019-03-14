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

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import javax.crypto.SecretKey;

import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.encryption.OriginatorKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Support methods for performing ECDH key agreement.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECDHSupport {
  
  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ECDHSupport.class);

  public static SecretKey deriveKeyAgreementKey(PrivateKey keyAgreementKey, OriginatorKeyInfo originatorKeyInfo, String keyWrappingAlgorithm) throws SecurityException {
    
    if (keyAgreementKey == null || !ECPrivateKey.class.isInstance(keyAgreementKey)) {
      log.error("Supplied keyAgreementKey must be an ECPrivateKey");
      throw new SecurityException("Supplied keyAgreementKey must be an ECPrivateKey");
    }    
    
    return null;
  }
  
}
