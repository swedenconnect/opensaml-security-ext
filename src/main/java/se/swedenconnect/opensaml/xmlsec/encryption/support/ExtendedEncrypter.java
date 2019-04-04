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

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import se.swedenconnect.opensaml.security.credential.ECDHPeerCredential;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHKeyAgreementBase;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHParameters;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;

/**
 * Extends OpenSAML's {@link Encrypter} with support for ECDH.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedEncrypter extends org.opensaml.saml.saml2.encryption.Encrypter {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ExtendedDecrypter.class);

  /**
   * Constructor.
   * 
   * @param dataEncParams
   *          the data encryption parameters
   * @param keyEncParams
   *          the key encryption parameters
   */
  public ExtendedEncrypter(DataEncryptionParameters dataEncParams, List<KeyEncryptionParameters> keyEncParams) {
    super(dataEncParams, keyEncParams);
  }

  /**
   * Constructor.
   * 
   * @param dataEncParams
   *          the data encryption parameters
   * @param keyEncParam
   *          the key encryption parameter
   */
  public ExtendedEncrypter(DataEncryptionParameters dataEncParams, KeyEncryptionParameters keyEncParam) {
    super(dataEncParams, keyEncParam);
  }

  /**
   * Constructor.
   * 
   * @param dataEncParams
   *          the data encryption parameters
   */
  public ExtendedEncrypter(DataEncryptionParameters dataEncParams) {
    super(dataEncParams);
  }

  /**
   * Extends OpenSAML's
   * {@link org.opensaml.xmlsec.encryption.support.Encrypter#encryptKey(Key, KeyEncryptionParameters, Document)} with
   * support for ECDH.
   */
  @Override
  @Nonnull
  public EncryptedKey encryptKey(@Nonnull final Key key, @Nonnull final KeyEncryptionParameters kekParams,
      @Nonnull final Document containingDocument) throws EncryptionException {

    checkParams(kekParams, false);

    final Key encryptionKey = CredentialSupport.extractEncryptionKey(kekParams.getEncryptionCredential());

    /**
     * ECDH Amendment. If the key is ECDH then generate agreed key and use it to generate the encrypted key.
     */
    EncryptedKey encryptedKey;
    if (encryptionKey instanceof ECPublicKey
        && EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES.equals(kekParams.getAlgorithm())) {
      
        ECDHParameters ecdhParameters = ((ECDHPeerCredential) kekParams.getEncryptionCredential()).getECDHParameters();
        String keyWrapMethod = ecdhParameters.getKeyWrapMethod();
        Key keyAgreementKey = ECDHKeyAgreementBase.getECDHKeyAgreementKey(kekParams, encryptionKey, keyWrapMethod);
        encryptedKey = encryptKey(key, keyAgreementKey, keyWrapMethod, null, containingDocument);
      
    }
    else {
      encryptedKey = encryptKey(key, encryptionKey, kekParams.getAlgorithm(), kekParams.getRSAOAEPParameters(), containingDocument);
    }

    if (kekParams.getKeyInfoGenerator() != null) {
      final KeyInfoGenerator generator = kekParams.getKeyInfoGenerator();
      log.debug("Dynamically generating KeyInfo from Credential for EncryptedKey using generator: {}", generator.getClass().getName());
      try {
        encryptedKey.setKeyInfo(generator.generate(kekParams.getEncryptionCredential()));
      }
      catch (final SecurityException e) {
        log.error("Error during EncryptedKey KeyInfo generation", e);
        throw new EncryptionException("Error during EncryptedKey KeyInfo generation", e);
      }
    }

    if (kekParams.getRecipient() != null) {
      encryptedKey.setRecipient(kekParams.getRecipient());
    }

    return encryptedKey;
  }

  /**
   * Extends OpenSAML's
   * {@link org.opensaml.xmlsec.encryption.support.Encrypter#checkParams(KeyEncryptionParameters, boolean)} with support
   * for ECDH.
   */
  @Override
  protected void checkParams(@Nullable final KeyEncryptionParameters kekParams, final boolean allowEmpty)
      throws EncryptionException {

    if (kekParams == null && allowEmpty) {
      return;
    }
    final Key key = CredentialSupport.extractEncryptionKey(kekParams.getEncryptionCredential());
    if (key != null && ECPublicKey.class.isInstance(key)
        && EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES.equals(kekParams.getAlgorithm())) {
      log.debug("Allowing EC key for algorithm {}", EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
      return;
    }
    super.checkParams(kekParams, allowEmpty);
  }

}
