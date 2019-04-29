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
package se.swedenconnect.opensaml.xmlsec.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;

import se.swedenconnect.opensaml.xmlsec.BasicExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;
import se.swedenconnect.opensaml.xmlsec.encryption.support.EcEncryptionConstants;
import se.swedenconnect.opensaml.xmlsec.keyinfo.KeyAgreementKeyInfoGeneratorFactory;

/**
 * Extends OpenSAML's {@link DefaultSecurityConfigurationBootstrap} with support for key agreement and key derivation
 * algorithms.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedDefaultSecurityConfigurationBootstrap extends DefaultSecurityConfigurationBootstrap {

  /**
   * Constructor.
   */
  protected ExtendedDefaultSecurityConfigurationBootstrap() {
  }

  /**
   * Build and return a default encryption configuration.
   * 
   * @return a new basic configuration with reasonable default values
   */
  @Nonnull
  public static BasicExtendedEncryptionConfiguration buildDefaultEncryptionConfiguration() {
    return buildDefaultEncryptionConfiguration(
      DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration());
  }

  /**
   * Builds an {@link ExtendedEncryptionConfiguration} object based on the supplied {@link EncryptionConfiguration}
   * object.
   * 
   * @param config
   *          the config to start from
   * @return an {@code ExtendedEncryptionConfiguration} object
   */
  public static BasicExtendedEncryptionConfiguration buildDefaultEncryptionConfiguration(EncryptionConfiguration config) {

    if (BasicExtendedEncryptionConfiguration.class.isInstance(config)) {
      return BasicExtendedEncryptionConfiguration.class.cast(config);
    }
    if (config == null) {
      config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    }

    BasicExtendedEncryptionConfiguration extendedConfig = new BasicExtendedEncryptionConfiguration();

    extendedConfig.setAgreementMethodAlgorithms(Arrays.asList(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES));
    extendedConfig.setKeyDerivationAlgorithms(Arrays.asList(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT));

    extendedConfig.setConcatKDFParameters(new ConcatKDFParameters(EncryptionConstants.ALGO_ID_DIGEST_SHA256));

    extendedConfig.setBlacklistedAlgorithms(config.getBlacklistedAlgorithms());
    extendedConfig.setBlacklistMerge(config.isBlacklistMerge());
    extendedConfig.setWhitelistBlacklistPrecedence(config.getWhitelistBlacklistPrecedence());
    extendedConfig.setWhitelistedAlgorithms(config.getWhitelistedAlgorithms());
    extendedConfig.setWhitelistMerge(config.isWhitelistMerge());

    extendedConfig.setDataEncryptionAlgorithms(config.getDataEncryptionAlgorithms());
    extendedConfig.setDataEncryptionCredentials(config.getDataEncryptionCredentials());
    extendedConfig.setDataKeyInfoGeneratorManager(config.getDataKeyInfoGeneratorManager());
    extendedConfig.setKeyTransportAlgorithmPredicate(config.getKeyTransportAlgorithmPredicate());
    extendedConfig.setKeyTransportEncryptionCredentials(config.getKeyTransportEncryptionCredentials());
    extendedConfig.setRSAOAEPParameters(config.getRSAOAEPParameters());
    extendedConfig.setRSAOAEPParametersMerge(config.isRSAOAEPParametersMerge());

    extendedConfig.setKeyTransportKeyInfoGeneratorManager(config.getKeyTransportKeyInfoGeneratorManager());

    // The order for key wrapping algorithms does not matter for DefaultSecurityConfigurationBootstrap, but it does so
    // for us,
    // so we set this property ourselves.
    if (config.getKeyTransportEncryptionAlgorithms()
      .equals(DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration().getKeyTransportEncryptionAlgorithms())) {

      extendedConfig.setKeyTransportEncryptionAlgorithms(Arrays.asList(
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,

        EncryptionConstants.ALGO_ID_KEYWRAP_AES256,
        EncryptionConstants.ALGO_ID_KEYWRAP_AES192,
        EncryptionConstants.ALGO_ID_KEYWRAP_AES128,
        EncryptionConstants.ALGO_ID_KEYWRAP_TRIPLEDES));
    }
    else {
      // The defaults have already been modified.
      extendedConfig.setKeyTransportEncryptionAlgorithms(config.getKeyTransportEncryptionAlgorithms());
    }

    return extendedConfig;
  }

  /**
   * Build a basic instance of {@link EncryptedKeyResolver}. Extends the one from
   * {@link DefaultSecurityConfigurationBootstrap} with {@link EncryptedElementTypeEncryptedKeyResolver}.
   * 
   * @return an EncryptedKey resolver instance
   */
  protected static EncryptedKeyResolver buildBasicEncryptedKeyResolver() {
    final List<EncryptedKeyResolver> resolverChain = new ArrayList<>();
    resolverChain.add(new InlineEncryptedKeyResolver());
    resolverChain.add(new EncryptedElementTypeEncryptedKeyResolver());
    resolverChain.add(new SimpleRetrievalMethodEncryptedKeyResolver());
    resolverChain.add(new SimpleKeyInfoReferenceEncryptedKeyResolver());

    return new ChainingEncryptedKeyResolver(resolverChain);
  }

  /**
   * Build a basic {@link NamedKeyInfoGeneratorManager}.
   * 
   * @return a named KeyInfo generator manager instance
   */
  public static NamedKeyInfoGeneratorManager buildBasicKeyInfoGeneratorManager() {
    return buildBasicKeyInfoGeneratorManager(DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager());
  }

  /**
   * Build a basic {@link NamedKeyInfoGeneratorManager}.
   * 
   * @param manager
   *          the manager to extend
   * @return a named KeyInfo generator manager instance
   */
  public static NamedKeyInfoGeneratorManager buildBasicKeyInfoGeneratorManager(NamedKeyInfoGeneratorManager manager) {
    manager.getDefaultManager().registerFactory(buildDefaultKeyAgreementKeyInfoGeneratorFactory());
    return manager;
  }

  /**
   * Creates a {@code KeyAgreementKeyInfoGeneratorFactory} with default settings.
   * 
   * @return a {@code KeyAgreementKeyInfoGeneratorFactory} instance
   */
  public static KeyAgreementKeyInfoGeneratorFactory buildDefaultKeyAgreementKeyInfoGeneratorFactory() {
    final KeyAgreementKeyInfoGeneratorFactory kaFactory = new KeyAgreementKeyInfoGeneratorFactory();
    kaFactory.setEmitEntityCertificate(true);
    kaFactory.setEmitOriginatorKeyInfoPublicKeyValue(true);
    return kaFactory;
  }

}
