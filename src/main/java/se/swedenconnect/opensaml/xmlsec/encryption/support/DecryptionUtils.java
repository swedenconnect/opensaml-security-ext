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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.DecryptionConfiguration;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.ChainingKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.LocalKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.provider.AgreementMethodKeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.DEREncodedKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.DSAKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.ECKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.KeyInfoReferenceProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.RSAKeyValueProvider;

/**
 * Utility class with helper methods for decryption.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DecryptionUtils {

  /**
   * Utility method that sets up {@link DecryptionParameters} for a {@link Decrypter} instance.
   *
   * @param localCredentials the decrypter's credentials
   * @return the parameters needed to instantiate a {@link Decrypter} object
   */
  public static DecryptionParameters createDecryptionParameters(final Credential... localCredentials) {
    final DecryptionParameters parameters = new DecryptionParameters();

    DecryptionConfiguration config = ConfigurationService.get(DecryptionConfiguration.class);
    if (config == null) {
      config = DefaultSecurityConfigurationBootstrap.buildDefaultDecryptionConfiguration();
    }

    parameters.setExcludedAlgorithms(config.getExcludedAlgorithms());
    parameters.setIncludedAlgorithms(config.getIncludedAlgorithms());
    parameters.setDataKeyInfoCredentialResolver(config.getDataKeyInfoCredentialResolver());

    // We set our own encrypted key resolver (OpenSAML defaults don't include EncryptedElementTypeEncryptedKeyResolver).
    //
    final ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(Arrays.asList(
        new InlineEncryptedKeyResolver(),
        new EncryptedElementTypeEncryptedKeyResolver(),
        new SimpleRetrievalMethodEncryptedKeyResolver(),
        new SimpleKeyInfoReferenceEncryptedKeyResolver()));

    parameters.setEncryptedKeyResolver(encryptedKeyResolver);

    // Based on the supplied local credentials, set a key info credential resolver.
    //
    parameters.setKEKKeyInfoCredentialResolver(createKeyInfoCredentialResolver(localCredentials));

    return parameters;
  }

  /**
   * Builds a KeyInfo credential resolver to be used during decryption of a SAML object.
   *
   * @param localCredentials the decrypter's credentials
   * @return a {@code KeyInfoCredentialResolver} instance.
   */
  public static KeyInfoCredentialResolver createKeyInfoCredentialResolver(final Credential... localCredentials) {

    final ArrayList<KeyInfoProvider> providers = new ArrayList<>();
    providers.add(new AgreementMethodKeyInfoProvider());
    providers.add(new RSAKeyValueProvider());
    providers.add(new ECKeyValueProvider());
    providers.add(new DSAKeyValueProvider());
    providers.add(new DEREncodedKeyValueProvider());
    providers.add(new InlineX509DataProvider());
    providers.add(new KeyInfoReferenceProvider());

    final List<Credential> credList =
        localCredentials != null ? Arrays.asList(localCredentials) : Collections.emptyList();

    return new ChainingKeyInfoCredentialResolver(Arrays.asList(
        new LocalKeyInfoCredentialResolver(providers, new CollectionKeyInfoCredentialResolver(credList)),
        new StaticKeyInfoCredentialResolver(credList)));
  }

  protected DecryptionUtils() {
  }

}
