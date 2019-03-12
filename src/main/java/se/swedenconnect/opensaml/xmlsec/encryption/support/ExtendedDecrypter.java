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
import java.security.interfaces.ECPrivateKey;
import java.util.Collection;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;

import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHKeyAgreementBase;

/**
 * Extends OpenSAML's {@link Decrypter} class so that the decrypter also supports ECDH key agreement.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedDecrypter extends Decrypter {

  /**
   * Constructor.
   *
   * @param params
   *          decryption parameters to use
   */
  public ExtendedDecrypter(final DecryptionParameters params) {
    super(params);
  }

  /**
   * Constructor.
   * 
   * @param newResolver
   *          resolver for data encryption keys.
   * @param newKEKResolver
   *          resolver for key encryption keys.
   * @param newEncKeyResolver
   *          resolver for EncryptedKey elements
   */
  public ExtendedDecrypter(@Nullable KeyInfoCredentialResolver newResolver,
      @Nullable KeyInfoCredentialResolver newKEKResolver,
      @Nullable EncryptedKeyResolver newEncKeyResolver) {
    super(newResolver, newKEKResolver, newEncKeyResolver);
  }

  /**
   * Constructor.
   *
   * @param newResolver
   *          resolver for data encryption keys.
   * @param newKEKResolver
   *          resolver for key encryption keys.
   * @param newEncKeyResolver
   *          resolver for EncryptedKey elements
   * @param whitelistAlgos
   *          collection of whitelisted algorithm URIs
   * @param blacklistAlgos
   *          collection of blacklisted algorithm URIs
   */
  public ExtendedDecrypter(@Nullable KeyInfoCredentialResolver newResolver,
      @Nullable KeyInfoCredentialResolver newKEKResolver,
      @Nullable EncryptedKeyResolver newEncKeyResolver,
      @Nullable Collection<String> whitelistAlgos,
      @Nullable Collection<String> blacklistAlgos) {
    super(newResolver, newKEKResolver, newEncKeyResolver, whitelistAlgos, blacklistAlgos);
  }

  /**
   * Extends {@link Decrypter#decryptKey(EncryptedKey, String, Key)} with support for ECDH key agreement.
   */
  @Override
  @Nonnull
  public Key decryptKey(@Nonnull final EncryptedKey encryptedKey, @Nonnull final String algorithm,
      @Nonnull Key kek) throws DecryptionException {

    if (kek != null && ECPrivateKey.class.isInstance(kek)) {
      // Replace the kek with the DH agreed key.
      return super.decryptKey(encryptedKey, algorithm, ECDHKeyAgreementBase.getECDHKeyAgreementKey(encryptedKey, kek));
    }
    else {
      return super.decryptKey(encryptedKey, algorithm, kek);
    }
  }

}
