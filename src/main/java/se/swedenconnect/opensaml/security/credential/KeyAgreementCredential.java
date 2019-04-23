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
package se.swedenconnect.opensaml.security.credential;

import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * A special purpose credential that is used when key agreement is used for encryption.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyAgreementCredential extends BasicCredential {

  /** The generated ephemeral public key for the sender. */
  private PublicKey senderGeneratedPublicKey;

  /** The peer credentials. */
  private Credential peerCredential;

  /** The agreement method used for this key agreement credential. */
  private String agreementMethodAlgorithm;

  /** The key derivation method used. */
  private KeyDerivationMethod keyDerivationMethod;

  /**
   * Constructor.
   * 
   * @param secretKey
   *          the key wrapping key (from the key agreement process)
   * @param senderGeneratedPublicKey
   *          the generated public key (for key derivation)
   * @param peerCredential
   *          the peer public certificate
   * @param agreementMethodAlgorith
   *          the agreement method used for this key agreement credential
   * @param keyDerivationMethod
   *          the key derivation method used
   */
  public KeyAgreementCredential(SecretKey secretKey, PublicKey senderGeneratedPublicKey,
      Credential peerCredential, String agreementMethodAlgorith, KeyDerivationMethod keyDerivationMethod) {

    super(secretKey);
    this.senderGeneratedPublicKey = Constraint.isNotNull(senderGeneratedPublicKey, "senderGeneratedPublicKey must not be null");
    this.peerCredential = Constraint.isNotNull(peerCredential, "peerCredential must not be null");
    this.agreementMethodAlgorithm = Constraint.isNotNull(agreementMethodAlgorith, "agreementMethodAlgorith must not be null");
    this.keyDerivationMethod = Constraint.isNotNull(keyDerivationMethod, "keyDerivationMethod must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public Class<? extends Credential> getCredentialType() {
    return KeyAgreementCredential.class;
  }

  /**
   * Returns the generated public key that is used for key derivation.
   * 
   * @return public key
   */
  public PublicKey getSenderGeneratedPublicKey() {
    return this.senderGeneratedPublicKey;
  }

  /**
   * Returns the peer credential.
   * 
   * @return peer credential
   */
  public Credential getPeerCredential() {
    return this.peerCredential;
  }

  /**
   * Returns the agreement method used for this credential.
   * 
   * @return the agreement method used for this credential
   */
  public String getAgreementMethodAlgorithm() {
    return this.agreementMethodAlgorithm;
  }

  /**
   * Returns the key derivation method used when constructing the key agreement key.
   * 
   * @return the key derivation method
   */
  public KeyDerivationMethod getKeyDerivationMethod() {
    try {
      return XMLObjectSupport.cloneXMLObject(this.keyDerivationMethod);
    }
    catch (MarshallingException | UnmarshallingException e) {
      throw new XMLRuntimeException("Failed to clone KeyDerivationMethod", e);
    }
  }

}
