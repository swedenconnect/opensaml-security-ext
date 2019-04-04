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
package se.swedenconnect.opensaml.xmlsec.encryption.support;

import javax.annotation.Nullable;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.encryption.support.Encrypter;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;

import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionParameters;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;

/**
 * An extension to OpenSAML's {@link KeyEncryptionParameters} that introduces parameters that may be needed for key
 * agreement protocols used to encrypt the data encryption key.
 * 
 * <p>
 * <b>Note:</b> Until OpenSAML's {@link Encrypter} is updated to handle also key agreement this class can not be used
 * using standard OpenSAML. However, if you instantiate XXX (which is this library's suggestion of how OpenSAML should
 * be extended) key agreement works during encryption.
 * </p>
 * <p>
 * If you are using the standard OpenSAML {@link Encrypter} and still want to use key agreement while encrypting a SAML
 * object, you should make sure to provider the OpenSAML {@link Encrypter} with a YYY instance as KEK parameters. The
 * YYY class is a work-around class with some logic and tweaks (that doesn't belong in a parameter instance) that we
 * had to build to get ....
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedKeyEncryptionParameters extends KeyEncryptionParameters {

  /** In the case key agreement protocols are used, this attribute holds the agreement method algorithm. */
  private String agreementMethodAlgorithm;

  /** The key derivation algorithm to be used if a key agreement protocol is used to encrypt the key encryption key. */
  private String keyDerivationAlgorithm;

  /**
   * The parameters to use if {@value EcEncryptionConstants#ALGO_ID_KEYDERIVATION_CONCAT} is used for key derivation.
   */
  private ConcatKDFParameters concatKDFParameters;

  /**
   * If ephemeral key agreement is used, the peer credential (i.e., the public key or certificate) of the recipient is
   * different from the {@link #getEncryptionCredential()} credential. In these cases the encryption credential will be
   * the ephemeral key and the peer certificate holds the recipient public key/certificate.
   */
  private Credential peerCredential;

  /**
   * Constructor.
   */
  public ExtendedKeyEncryptionParameters() {
    super();
  }

  /**
   * Convenience constructor which allows copying the relevant key encryption parameters from an instance of
   * {@link EncryptionParameters}. If the supplied {@code params} parameter is an instance of
   * {@link ExtendedEncryptionParameters} the object also handles algorithms and credentials for key agreement and
   * derivation.
   *
   * @param params
   *          the encryption parameters instance
   * @param recipientId
   *          the recipient of the key
   */
  public ExtendedKeyEncryptionParameters(final EncryptionParameters params, final String recipientId) {
    super(params, recipientId);
    if (ExtendedEncryptionParameters.class.isInstance(params)) {

    }
  }

  /**
   * Predicate that tells if this parameter object is a parameter instance for a key agreement process (as opposed to a
   * RSA key transport process).
   *
   * @return {@code true} if key agreement should be used and {@code false} otherwise
   */
  public boolean useKeyAgreement() {
    return this.getPeerCredential() != null
        && this.getAgreementMethodAlgorithm() != null
        && this.getKeyDerivationAlgorithm() != null;
  }

  /**
   * Gets the recipient credential.
   * 
   * <p>
   * Note: If ephemeral key agreement is used, the peer credential (i.e., the public key or certificate) of the
   * recipient is different from the {@link #getEncryptionCredential()} credential. In these cases the encryption
   * credential will be the ephemeral key and the peer certificate holds the recipient public key/certificate.
   * </p>
   * 
   * @return the recipient credential, or {@code null}
   */
  @Nullable
  public Credential getPeerCredential() {
    return this.peerCredential;
  }

  /**
   * Sets the recipient credential.
   * 
   * <p>
   * Note: If ephemeral key agreement is used, the peer credential (i.e., the public key or certificate) of the
   * recipient is different from the {@link #getEncryptionCredential()} credential. In these cases the encryption
   * credential will be the ephemeral key and the peer certificate holds the recipient public key/certificate.
   * </p>
   * 
   * @param peerCredential
   *          the recipient credential
   */
  public void setPeerCredential(@Nullable final Credential peerCredential) {
    this.peerCredential = peerCredential;
  }

  /**
   * Gets the agreement method algorithm to be used when encrypting the key encryption key.
   * <p>
   * Assigned in the cases where a key agreement protocol is used to protect the key encryption key.
   * </p>
   *
   * @return the agreement method algorithm, or {@code null}
   */
  @Nullable
  public String getAgreementMethodAlgorithm() {
    return this.agreementMethodAlgorithm;
  }

  /**
   * Sets the agreement method algorithm to be used when encrypting the key encryption key using a key agreement
   * protocol.
   *
   * @param agreementMethodAlgorithm
   *          algorithm URI
   */
  public void setAgreementMethodAlgorithm(@Nullable final String agreementMethodAlgorithm) {
    this.agreementMethodAlgorithm = agreementMethodAlgorithm;
  }

  /**
   * Gets the key derivation algorithm to be used when using a key agreement protocol to encrypt the key agreement key.
   *
   * @return the algorithm URI for the key derivation algorithm, or {@code null}
   */
  @Nullable
  public String getKeyDerivationAlgorithm() {
    return this.keyDerivationAlgorithm;
  }

  /**
   * Sets the key derivation algorithm to be used when using a key agreement protocol to encrypt the key agreement key.
   *
   * @param keyDerivationAlgorithm
   *          algorithm URI
   */
  public void setKeyDerivationAlgorithm(@Nullable final String keyDerivationAlgorithm) {
    this.keyDerivationAlgorithm = keyDerivationAlgorithm;
  }

  /**
   * Gets the ConcatKDF key derivation paramaters to use. Only of interest if key agreement with ConcatKDF key
   * derivation is configured.
   *
   * @return the ConcatKDF parameters, or {@code null}
   */
  @Nullable
  public ConcatKDFParameters getConcatKDFParameters() {
    return this.concatKDFParameters;
  }

  /**
   * Sets the ConcatKDF key derivation paramaters to use. Only relevant if key agreement with ConcatKDF key derivation
   * is to be used.
   *
   * @param concatKDFParameters
   *          the ConcatKDF parameters
   */
  public void setConcatKDFParameters(final ConcatKDFParameters concatKDFParameters) {
    this.concatKDFParameters = concatKDFParameters;
  }

}
