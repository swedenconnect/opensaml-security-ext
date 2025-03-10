/*
 * Copyright 2016-2025 Sweden Connect
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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import net.shibboleth.shared.logic.Constraint;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.EncryptedElementType;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.DecryptionConfiguration;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.DecryptionException;

/**
 * A support bean for easy decryption.
 * <p>
 * OpenSAML offers two ways to represent decryption parameters, the {@link DecryptionParameters} and the
 * {@link DecryptionConfiguration}. This bean supports being initialized by either of these two, but also, and perhaps
 * easier to use; it supports initialization with just the encryption credentials and assigns the defaults from
 * {@link DecryptionUtils#createDecryptionParameters(Credential...)}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class SAMLObjectDecrypter {

  /** The decrypter. */
  private Decrypter decrypter;

  /** Decryption parameters. */
  private final DecryptionParameters parameters;

  /**
   * If using an HSM it is likely that the SunPKCS11 crypto provider is used. This provider does not have support for
   * OAEP padding. This is used commonly for XML encryption since
   * {@code http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p} is the default algorithm to use for key encryption. This
   * class has a workaround for this limitation that is enabled by setting the {@code pkcs11Workaround} flag.
   */
  private boolean pkcs11Workaround = false;

  /** For testing the workaround without the use of an HSM. */
  private boolean pkcs11testMode = false;

  /**
   * Constructor given the credential to use to decrypt the messages (certificate or key pair).
   *
   * @param decryptionCredential decryption credential
   */
  public SAMLObjectDecrypter(final Credential decryptionCredential) {
    this(Collections.singletonList(decryptionCredential));
  }

  /**
   * Constructor accepting several credentials (certificates or key pairs) to be used when decrypting. This may be
   * useful after a key rollover.
   *
   * @param decryptionCredentials decryption credentials
   */
  public SAMLObjectDecrypter(final List<Credential> decryptionCredentials) {
    Constraint.isNotEmpty(decryptionCredentials, "At least one credential must be supplied to SAMLObjectDecrypter");
    this.parameters = DecryptionUtils.createDecryptionParameters(
        decryptionCredentials.toArray(Credential[]::new));

    // Should be assigned explicitly
    this.parameters.setExcludedAlgorithms(Collections.emptyList());
    this.parameters.setIncludedAlgorithms(Collections.emptyList());
  }

  /**
   * Initializes the decrypter using {@link DecryptionParameters}.
   *
   * @param decryptionParameters parameters
   */
  public SAMLObjectDecrypter(final DecryptionParameters decryptionParameters) {
    this.parameters = new DecryptionParameters();
    this.parameters.setDataKeyInfoCredentialResolver(decryptionParameters.getDataKeyInfoCredentialResolver());
    this.parameters.setKEKKeyInfoCredentialResolver(decryptionParameters.getKEKKeyInfoCredentialResolver());
    this.parameters.setEncryptedKeyResolver(decryptionParameters.getEncryptedKeyResolver());
    this.parameters.setExcludedAlgorithms(decryptionParameters.getExcludedAlgorithms());
    this.parameters.setIncludedAlgorithms(decryptionParameters.getIncludedAlgorithms());
  }

  /**
   * Initializes the decrypter using {@link DecryptionConfiguration}.
   *
   * @param decryptionConfiguration parameters
   */
  public SAMLObjectDecrypter(final DecryptionConfiguration decryptionConfiguration) {
    this.parameters = new DecryptionParameters();
    this.parameters.setDataKeyInfoCredentialResolver(decryptionConfiguration.getDataKeyInfoCredentialResolver());
    this.parameters.setKEKKeyInfoCredentialResolver(decryptionConfiguration.getKEKKeyInfoCredentialResolver());
    this.parameters.setEncryptedKeyResolver(decryptionConfiguration.getEncryptedKeyResolver());
    this.parameters.setExcludedAlgorithms(decryptionConfiguration.getExcludedAlgorithms());
    this.parameters.setIncludedAlgorithms(decryptionConfiguration.getIncludedAlgorithms());
  }

  /**
   * Decrypts the supplied encrypted object into an object of the given type.
   *
   * @param encryptedObject the encrypted object
   * @param destinationClass the class of the destination object
   * @param <T> the type of the destination object
   * @param <E> the type of the encrypted object
   * @return the decrypted element of object T
   * @throws DecryptionException for decryption errors
   */
  public <T extends XMLObject, E extends EncryptedElementType> T decrypt(final E encryptedObject,
      final Class<T> destinationClass)
      throws DecryptionException {

    if (encryptedObject.getEncryptedData() == null) {
      throw new DecryptionException("Object contains no encrypted data");
    }
    return this.decrypt(encryptedObject.getEncryptedData(), destinationClass);
  }

  /**
   * Decrypts the supplied encrypted object into an object of the given type.
   *
   * @param encryptedData the encrypted data
   * @param destinationClass the class of the destination object
   * @param <T> the type of the destination object
   * @return the decrypted element of object T
   * @throws DecryptionException for decryption errors
   */
  public <T extends XMLObject> T decrypt(final EncryptedData encryptedData, final Class<T> destinationClass)
      throws DecryptionException {

    final XMLObject object = this.getDecrypter().decryptData(encryptedData);
    if (!destinationClass.isInstance(object)) {
      throw new DecryptionException(String.format("Decrypted object can not be cast to %s - is %s",
          destinationClass.getSimpleName(), object.getClass().getSimpleName()));
    }
    return destinationClass.cast(object);
  }

  /**
   * Returns the decrypter to use.
   *
   * @return the decrypter
   */
  private synchronized Decrypter getDecrypter() {
    if (this.decrypter == null) {
      if (this.pkcs11Workaround) {
        final Pkcs11Decrypter p11Decrypter = new Pkcs11Decrypter(this.parameters);
        p11Decrypter.setTestMode(this.pkcs11testMode);
        this.decrypter = p11Decrypter;
      }
      else {
        this.decrypter = new Decrypter(this.parameters);
      }
      this.decrypter.setRootInNewDocument(true);
    }
    return this.decrypter;
  }

  /**
   * Assigns a list of black listed algorithms
   *
   * @param blacklistedAlgorithms non allowed algorithms
   */
  public void setBlacklistedAlgorithms(final Collection<String> blacklistedAlgorithms) {
    if (this.decrypter != null) {
      throw new IllegalStateException("Object has already been initialized");
    }
    this.parameters.setExcludedAlgorithms(blacklistedAlgorithms);
  }

  /**
   * Assigns a list of white listed algorithms
   *
   * @param whitelistedAlgorithms white listed algorithms
   */
  public void setWhitelistedAlgorithms(final Collection<String> whitelistedAlgorithms) {
    if (this.decrypter != null) {
      throw new IllegalStateException("Object has already been initialized");
    }
    this.parameters.setIncludedAlgorithms(whitelistedAlgorithms);
  }

  /**
   * If using an HSM it is likely that the SunPKCS11 crypto provider is used. This provider does not have support for
   * OAEP padding. This is used commonly for XML encryption since
   * {@code http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p} is the default algorithm to use for key encryption. This
   * class has a workaround for this limitation that is enabled by setting the {@code pkcs11Workaround} flag.
   *
   * @param pkcs11Workaround whether to run in PKCS11 workaround mode
   */
  public void setPkcs11Workaround(final boolean pkcs11Workaround) {
    this.pkcs11Workaround = pkcs11Workaround;
  }

  /**
   * For internal testing only.
   *
   * @param pkcs11testMode test flag
   */
  public void setPkcs11testMode(final boolean pkcs11testMode) {
    this.pkcs11testMode = pkcs11testMode;
  }

}
