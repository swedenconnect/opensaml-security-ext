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
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;

import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHParameters;

/**
 * Represents the peer ECDH credential.
 * <p>
 * Used only for encryption.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Deprecated
public class ECDHPeerCredential extends BasicX509Credential {

  /** The parameters for the ConcatKDF key derivation algorithm. */
  private ConcatKDFParams concatKDFParams;

  /** The generated ephemeral public key for the sender. */
  private PublicKey senderGeneratedPublicKey;

  /** ECDH parameters. */
  private ECDHParameters ecdhParameters;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Class<? extends Credential> getCredentialType() {
    return ECDHPeerCredential.class;
  }

  /**
   * Constructor.
   *
   * @param entityCertificate
   *          the entity certificate for the peer credential
   */
  public ECDHPeerCredential(X509Certificate entityCertificate) {
    super(entityCertificate);
  }

  /**
   * Gets the parameters for the ConcatKDF key derivation algorithm.
   *
   * @return the ConcatKDF parameters
   */
  public ConcatKDFParams getConcatKDFParams() {
    return this.concatKDFParams;
  }

  /**
   * Sets the parameters for the ConcatKDF key derivation algorithm.
   *
   * @param concatKDF
   *          the ConcatKDF parameters
   */
  public void setConcatKDF(ConcatKDFParams concatKDF) {
    this.concatKDFParams = concatKDF;
  }

  /**
   * Gets the generated ephemeral public key for the sender.
   * 
   * @return public key
   */
  public PublicKey getSenderGeneratedPublicKey() {
    return this.senderGeneratedPublicKey;
  }

  /**
   * Sets the generated ephemeral public key for the sender.
   * 
   * @param senderPubKey
   *          the public key
   */
  public void setSenderGeneratedPublicKey(PublicKey senderPubKey) {
    this.senderGeneratedPublicKey = senderPubKey;
  }

  /**
   * Gets the ECDH parameters.
   * 
   * @return ECDH parameters
   */
  public ECDHParameters getECDHParameters() {
    return this.ecdhParameters;
  }

  /**
   * Sets the ECDH parameters.
   * 
   * @param ecdhParameters
   *          the ECDH parameters
   */
  public void setECDHParameters(ECDHParameters ecdhParameters) {
    this.ecdhParameters = ecdhParameters;
  }
}
