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
package se.swedenconnect.opensaml.xmlsec.encryption.support;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.EncryptionParametersResolver;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.Encrypter;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.security.credential.KeyAgreementCredential;
import se.swedenconnect.opensaml.xmlsec.BasicExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.algorithm.ExtendedAlgorithmSupport;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;
import se.swedenconnect.opensaml.xmlsec.keyinfo.KeyAgreementKeyInfoGeneratorFactory.KeyAgreementKeyInfoGenerator;

/**
 * A specialization of OpenSAML's {@link KeyEncryptionParameters} that is to be used for Elliptic-curves Diffie-Hellman
 * (Ephemeral-Static) key agreement ({@value EcEncryptionConstants#ALGO_ID_KEYAGREEMENT_ECDH_ES}).
 * 
 * <p>
 * Note: This class is mainly intended to be used when you invoke the {@link Encrypter} without using an
 * {@link EncryptionParametersResolver} that handles key agreement (see below). The implementation of this class is
 * really not how we would like things to be done, but in order for the OpenSAML {@link Encrypter} to work for
 * {@value EcEncryptionConstants#ALGO_ID_KEYAGREEMENT_ECDH_ES} we introduce this solution where we really bend things
 * for our needs. And hope that generic ECDH key agreement will be supported in OpenSAML soon.
 * </p>
 * <p>
 * In order to get everything to play along with OpenSAML's {@link Encrypter} we let the {@link #getAlgorithm()} return
 * the algorithm for the key wrapping method. Normally, the {@link KeyEncryptionParameters#getAlgorithm()} returns the
 * key encryption algorithm, but in our case this is always {@value EcEncryptionConstants#ALGO_ID_KEYAGREEMENT_ECDH_ES}.
 * </p>
 * <p>
 * Furthermore, the key derivation algorithm is hard-wired to
 * {@value EcEncryptionConstants#ALGO_ID_KEYDERIVATION_CONCAT} and its parameters are not currently possible to
 * configure (other than the digest method, see {@link #setConcatKDFParameters(ConcatKDFParameters)}.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECDHKeyAgreementParameters extends KeyEncryptionParameters {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ECDHKeyAgreementParameters.class);

  /**
   * The key derivation algorithm. Currently, the only supported algorithm is
   * {@link EcEncryptionConstants#ALGO_ID_KEYDERIVATION_CONCAT}.
   */
  private String keyDerivationAlgorithm;

  /**
   * The parameters to use if {@value EcEncryptionConstants#ALGO_ID_KEYDERIVATION_CONCAT} is used for key derivation.
   */
  private ConcatKDFParameters concatKDFParameters;

  /** The key agreement credential. */
  private KeyAgreementCredential keyAgreementCredential;

  /**
   * Flag that tells whether the key agreement credential was assigned using the
   * {@link #setKeyAgreementCredential(KeyAgreementCredential)} or whether it was calculated internally using the peer
   * credential.
   */
  private boolean keyAgreementCredentialAssigned = false;

  /**
   * Constructor.
   */
  public ECDHKeyAgreementParameters() {
    super();

    // Assign defaults for ECDH ...
    BasicExtendedEncryptionConfiguration config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration(
      ConfigurationService.get(EncryptionConfiguration.class));

    this.setAlgorithm(config.getKeyTransportEncryptionAlgorithms()
      .stream()
      .map(AlgorithmSupport.getGlobalAlgorithmRegistry()::get)
      .filter(ExtendedAlgorithmSupport::isKeyWrappingAlgorithm)
      .map(AlgorithmDescriptor::getURI)
      .findFirst()
      .orElse(null));
    this.setKeyDerivationAlgorithm(config.getKeyDerivationAlgorithms().stream().findFirst().orElse(null));
    this.setConcatKDFParameters(config.getConcatKDFParameters());
  }

  /**
   * Convenience constructor which allows copying the relevant key encryption parameters from an instance of
   * {@link EncryptionParameters}.
   * <p>
   * If the supplied {@code params} contains a key transport encryption credential of type
   * {@link KeyAgreementCredential} the {@link #setKeyAgreementCredential(Credential)} will be invoked. This means that
   * the key agreement credential will not be created by the {@link #getKeyAgreementCredential()} method.
   * </p>
   * 
   * @param params
   *          the encryption parameters instance
   * @param recipientId
   *          the recipient of the key
   */
  public ECDHKeyAgreementParameters(EncryptionParameters params, String recipientId) {
    super(params, recipientId);

    if (params.getKeyTransportEncryptionCredential() != null &&
        KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential())) {
      this.setKeyAgreementCredential(params.getKeyTransportEncryptionCredential());
    }
  }

  /**
   * Returns the key agreement credential.
   * 
   * <p>
   * If the key agreement has not been assigned, the method will attempt to generate it using the key derivation
   * parameters and peer credential of this instance.
   * </p>
   * 
   * @return the key agreement credential, or {@code null} if it could not generate such a credential
   */
  public Credential getKeyAgreementCredential() {
    if (this.keyAgreementCredential != null) {
      return this.keyAgreementCredential;
    }
    else {
      log.debug("Generating key agreement credential ...");

      Credential peerCredential = this.getPeerCredential();
      if (peerCredential == null) {
        log.info("Could not generate key agreement credential - peer credential is missing");
        return null;
      }
      try {
        KeyDerivationMethod keyDerivationMethod = (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(
          KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
        keyDerivationMethod.setAlgorithm(this.keyDerivationAlgorithm);
        if (this.concatKDFParameters != null) {
          keyDerivationMethod.getUnknownXMLObjects().add(this.concatKDFParameters.toXMLObject());
        }

        this.keyAgreementCredential = ECDHSupport.createKeyAgreementCredential(this.getPeerCredential(),
          this.getAlgorithm(), keyDerivationMethod);

        log.debug("Key agreement credential successfully generated");
        this.keyAgreementCredentialAssigned = false;
        return this.keyAgreementCredential;
      }
      catch (SecurityException e) {
        log.error("Failed to generate KeyAgreementCredential - {}", e.getMessage(), e);
        return null;
      }
    }
  }

  /**
   * Assigns the key agreement credential. This must be of the type {@link KeyAgreementCredential}.
   * 
   * <p>
   * If this credential is not assigned, it will be generated. See {@link #getKeyAgreementCredential()}.
   * </p>
   * 
   * @param keyAgreementCredential
   *          the key agreement credential
   */
  public void setKeyAgreementCredential(Credential keyAgreementCredential) {
    Constraint.isTrue(KeyAgreementCredential.class.isInstance(keyAgreementCredential),
      "Supplied credential must be a keyAgreementCredential");

    this.keyAgreementCredential = KeyAgreementCredential.class.cast(keyAgreementCredential);
    this.keyAgreementCredentialAssigned = true;
  }

  /**
   * Instead of returning the credential assigned ({@link #setEncryptionCredential(Credential)}), the method will return
   * the key agreement credential ({@link #getKeyAgreementCredential()}). The reason for this is a work-around so that
   * we can squeeze key agreement functionality into the OpenSAML {@link Encrypter}.
   */
  @Override
  public Credential getEncryptionCredential() {
    return this.getKeyAgreementCredential();
  }

  /**
   * For the {@code ECDHKeyAgreementParameters} class, this means {@link #setPeerCredential(Credential)}.
   */
  @Override
  public void setEncryptionCredential(Credential encryptionCredential) {
    this.setPeerCredential(encryptionCredential);
  }

  /**
   * Returns the peer credential. This is the credential that was assigned using
   * {@link #setEncryptionCredential(Credential)}.
   * 
   * @return the peer credential
   */
  public Credential getPeerCredential() {
    return super.getEncryptionCredential();
  }

  /**
   * Assigs the peer credential (this is the same as
   * {@link DataEncryptionParameters#setEncryptionCredential(Credential)}.
   * 
   * @param peerCredential
   *          the peer credentials
   */
  public void setPeerCredential(Credential peerCredential) {
    super.setEncryptionCredential(peerCredential);
    if (!this.keyAgreementCredentialAssigned && this.keyAgreementCredential != null) {
      this.keyAgreementCredential = null;
    }
  }

  /**
   * If a {@link KeyInfoGenerator} has not been explicitly assigned, a default {@link KeyAgreementKeyInfoGenerator}
   * (@link {@link ExtendedDefaultSecurityConfigurationBootstrap#buildDefaultKeyAgreementKeyInfoGeneratorFactory()})
   * will be created.
   */
  @Override
  public KeyInfoGenerator getKeyInfoGenerator() {
    KeyInfoGenerator generator = super.getKeyInfoGenerator();
    if (generator == null || KeyAgreementKeyInfoGenerator.class.isInstance(generator)) {
      generator = ExtendedDefaultSecurityConfigurationBootstrap
        .buildDefaultKeyAgreementKeyInfoGeneratorFactory()
        .newInstance();
    }
    return generator;
  }

  /**
   * Gets the key derivation algorithm.
   * 
   * @return the key derivation algorithm
   */
  public String getKeyDerivationAlgorithm() {
    return this.keyAgreementCredential != null ? this.keyAgreementCredential.getKeyDerivationMethod().getAlgorithm() : null;
  }

  /**
   * Sets the key derivation algorithm.
   * <p>
   * Currently, the only supported algorithm is {@link EcEncryptionConstants#ALGO_ID_KEYDERIVATION_CONCAT}.
   * </p>
   * 
   * @param keyDerivationAlgorithm
   *          the key derivation algorithm
   */
  public void setKeyDerivationAlgorithm(String keyDerivationAlgorithm) {
    Constraint.isTrue(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT.equals(keyDerivationAlgorithm),
      String.format("The only supported key derivation algorithm is '%s'", EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT));
    this.keyDerivationAlgorithm = keyDerivationAlgorithm;
    if (!this.keyAgreementCredentialAssigned && this.keyAgreementCredential != null) {
      this.keyAgreementCredential = null;
    }
  }

  /**
   * Returns the ConcatKDF parameters to use.
   * 
   * @return parameters
   */
  public ConcatKDFParameters getConcatKDFParameters() {
    if (this.keyAgreementCredential != null) {
      KeyDerivationMethod kdm = this.keyAgreementCredential.getKeyDerivationMethod();
      ConcatKDFParams params = kdm.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME)
        .stream()
        .map(ConcatKDFParams.class::cast)
        .findFirst()
        .orElse(null);
      if (params != null) {
        return new ConcatKDFParameters(params);
      }
    }
    return this.concatKDFParameters;
  }

  /**
   * Assigns the ConcatKDF parameters to use.
   * 
   * @param concatKDFParameters
   *          parameters
   */
  public void setConcatKDFParameters(ConcatKDFParameters concatKDFParameters) {
    this.concatKDFParameters = concatKDFParameters;
  }

}
