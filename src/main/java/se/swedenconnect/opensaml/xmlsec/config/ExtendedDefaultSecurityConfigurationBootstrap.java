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

import java.util.Arrays;

import javax.annotation.Nonnull;

import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.impl.BasicDecryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;

import se.swedenconnect.opensaml.xmlsec.ExtendedBasicEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;
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
  public static ExtendedBasicEncryptionConfiguration buildDefaultEncryptionConfiguration() {
    ExtendedBasicEncryptionConfiguration conf = new ExtendedBasicEncryptionConfiguration();

    conf.setAgreementMethodAlgorithms(Arrays.asList(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES));
    conf.setKeyDerivationAlgorithms(Arrays.asList(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT));
    
    conf.setConcatKDFParameters(new ConcatKDFParameters(EncryptionConstants.ALGO_ID_DIGEST_SHA256));

    BasicEncryptionConfiguration openSamlConf = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    conf.setBlacklistedAlgorithms(openSamlConf.getBlacklistedAlgorithms());
    conf.setBlacklistMerge(openSamlConf.isBlacklistMerge());
    conf.setWhitelistBlacklistPrecedence(openSamlConf.getWhitelistBlacklistPrecedence());
    conf.setWhitelistedAlgorithms(openSamlConf.getWhitelistedAlgorithms());
    conf.setWhitelistMerge(openSamlConf.isWhitelistMerge());

    conf.setDataEncryptionAlgorithms(openSamlConf.getDataEncryptionAlgorithms());
    conf.setDataEncryptionCredentials(openSamlConf.getDataEncryptionCredentials());
    conf.setDataKeyInfoGeneratorManager(openSamlConf.getDataKeyInfoGeneratorManager());
    conf.setKeyTransportAlgorithmPredicate(openSamlConf.getKeyTransportAlgorithmPredicate());    
    conf.setKeyTransportEncryptionCredentials(openSamlConf.getKeyTransportEncryptionCredentials());
    conf.setRSAOAEPParameters(openSamlConf.getRSAOAEPParameters());
    conf.setRSAOAEPParametersMerge(openSamlConf.isRSAOAEPParametersMerge());

    conf.setKeyTransportKeyInfoGeneratorManager(ExtendedDefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager());
    
    // The order for key wrapping algorithms does not matter for our base class, but it does so for us,
    // so we set this property ourselves.
    conf.setKeyTransportEncryptionAlgorithms(Arrays.asList(
      EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,

      EncryptionConstants.ALGO_ID_KEYWRAP_AES256,
      EncryptionConstants.ALGO_ID_KEYWRAP_AES192,
      EncryptionConstants.ALGO_ID_KEYWRAP_AES128,      
      EncryptionConstants.ALGO_ID_KEYWRAP_TRIPLEDES));

    return conf;
  }

  /**
   * Build and return a default decryption configuration.
   * 
   * @return a new basic configuration with reasonable default values
   */
  @Nonnull
  public static BasicDecryptionConfiguration buildDefaultDecryptionConfiguration() {

    // TODO
    return DefaultSecurityConfigurationBootstrap.buildDefaultDecryptionConfiguration();
  }

  /**
   * Build a basic {@link NamedKeyInfoGeneratorManager}.
   * 
   * @return a named KeyInfo generator manager instance
   */
  public static NamedKeyInfoGeneratorManager buildBasicKeyInfoGeneratorManager() {

    final NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager();

    final KeyAgreementKeyInfoGeneratorFactory ecdhFactory = new KeyAgreementKeyInfoGeneratorFactory();
    ecdhFactory.setEmitEntityCertificate(true);

    manager.getDefaultManager().registerFactory(ecdhFactory);

    return manager;
  }

}
