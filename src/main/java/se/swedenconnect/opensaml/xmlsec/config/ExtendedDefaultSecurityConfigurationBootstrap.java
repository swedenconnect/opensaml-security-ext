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

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
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

    // The order for key wrapping algorithms does not matter for DefaultSecurityConfigurationBootstrap,
    // but it does so for us, so we set this property ourselves.
    //
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
   * Extends {@link DefaultSecurityConfigurationBootstrap#buildDefaultSignatureSigningConfiguration()} with
   * http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1, http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1 and
   * http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1.
   * 
   * @return signature signing configuration
   */
  public static BasicSignatureSigningConfiguration buildDefaultSignatureSigningConfiguration() {
    return buildDefaultSignatureSigningConfiguration(null);
  }

  /**
   * Given a {@code SignatureSigningConfiguration} the method ensures that the signature algorithms
   * http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1, http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1 and
   * http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1 are among the signature algorithms and returns a
   * {@code BasicSignatureSigningConfiguration} object.
   * 
   * @param config
   *          the configuration
   * @return a signing configuration with RSA-PSS algorithms included
   */
  public static BasicSignatureSigningConfiguration buildDefaultSignatureSigningConfiguration(SignatureSigningConfiguration config) {
    BasicSignatureSigningConfiguration updatedConfig;
    if (config == null) {
      updatedConfig = DefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration();
    }
    else if (BasicSignatureSigningConfiguration.class.isInstance(config)) { 
      updatedConfig = BasicSignatureSigningConfiguration.class.cast(config);
    }
    else {
      updatedConfig = new BasicSignatureSigningConfiguration();
      updatedConfig.setBlacklistedAlgorithms(config.getBlacklistedAlgorithms());
      updatedConfig.setBlacklistMerge(config.isBlacklistMerge());
      updatedConfig.setWhitelistedAlgorithms(config.getWhitelistedAlgorithms());
      updatedConfig.setWhitelistMerge(config.isWhitelistMerge());
      updatedConfig.setWhitelistBlacklistPrecedence(config.getWhitelistBlacklistPrecedence());
      updatedConfig.setKeyInfoGeneratorManager(config.getKeyInfoGeneratorManager());
      updatedConfig.setSignatureCanonicalizationAlgorithm(config.getSignatureCanonicalizationAlgorithm());
      updatedConfig.setSignatureHMACOutputLength(config.getSignatureHMACOutputLength());
      updatedConfig.setSignatureReferenceCanonicalizationAlgorithm(config.getSignatureReferenceCanonicalizationAlgorithm());
      updatedConfig.setSignatureReferenceDigestMethods(config.getSignatureReferenceDigestMethods());
      updatedConfig.setSigningCredentials(config.getSigningCredentials());
      updatedConfig.setSignatureAlgorithms(config.getSignatureAlgorithms());
    }    
    
    List<String> signatureAlgorithms = new ArrayList<>(updatedConfig.getSignatureAlgorithms());
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1);
    }
    if (!signatureAlgorithms.contains(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1)) {
      signatureAlgorithms.add(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1);
    }    
    updatedConfig.setSignatureAlgorithms(signatureAlgorithms);
    
    return updatedConfig;
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
