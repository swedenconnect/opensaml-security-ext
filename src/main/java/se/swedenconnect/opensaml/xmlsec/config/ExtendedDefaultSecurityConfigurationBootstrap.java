/*
 * Copyright 2019-2024 Sweden Connect
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import jakarta.annotation.Nonnull;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.security.SAMLMetadataKeyAgreementEncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyAgreementEncryptionConfiguration;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;

/**
 * Extends OpenSAML's {@link DefaultSecurityConfigurationBootstrap} with support for the RSA-PSS signature algorithms.
 * <p>
 * Note: Even though OpenSAML 5.x has introduced support for RSA-PSS algorithms, they are not part of the
 * {@link DefaultSecurityConfigurationBootstrap}, so this class is still needed.
 * </p>
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
   * Extends {@link DefaultSecurityConfigurationBootstrap#buildDefaultSignatureSigningConfiguration()} with
   * http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1, http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1 and
   * http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1.
   *
   * @return signature signing configuration
   */
  @Nonnull
  public static BasicSignatureSigningConfiguration buildDefaultSignatureSigningConfiguration() {
    return buildDefaultSignatureSigningConfiguration(null);
  }

  /**
   * Given a {@code SignatureSigningConfiguration} the method ensures that the signature algorithms
   * http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1, http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1 and
   * http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1 are among the signature algorithms and returns a
   * {@code BasicSignatureSigningConfiguration} object.
   *
   * @param config the configuration
   * @return a signing configuration with RSA-PSS algorithms included
   */
  @Nonnull
  public static BasicSignatureSigningConfiguration buildDefaultSignatureSigningConfiguration(
      final SignatureSigningConfiguration config) {

    final BasicSignatureSigningConfiguration updatedConfig;
    if (config == null) {
      updatedConfig = DefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration();
    }
    else if (config instanceof BasicSignatureSigningConfiguration) {
      updatedConfig = (BasicSignatureSigningConfiguration) config;
    }
    else {
      updatedConfig = new BasicSignatureSigningConfiguration();

      updatedConfig.setSigningCredentials(config.getSigningCredentials());
      updatedConfig.setSignatureAlgorithms(config.getSignatureAlgorithms());
      updatedConfig.setSignatureReferenceDigestMethods(config.getSignatureReferenceDigestMethods());
      updatedConfig
          .setSignatureReferenceCanonicalizationAlgorithm(config.getSignatureReferenceCanonicalizationAlgorithm());
      updatedConfig.setSignatureCanonicalizationAlgorithm(config.getSignatureCanonicalizationAlgorithm());
      updatedConfig.setSignatureHMACOutputLength(config.getSignatureHMACOutputLength());
      updatedConfig.setKeyInfoGeneratorManager(config.getKeyInfoGeneratorManager());

      updatedConfig.setExcludedAlgorithms(config.getExcludedAlgorithms());
      updatedConfig.setExcludeMerge(config.isExcludeMerge());
      updatedConfig.setIncludedAlgorithms(config.getIncludedAlgorithms());
      updatedConfig.setIncludeMerge(config.isIncludeMerge());
      updatedConfig.setIncludeExcludePrecedence(config.getIncludeExcludePrecedence());
    }

    final List<String> signatureAlgorithms = new ArrayList<>(updatedConfig.getSignatureAlgorithms());
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
  @Nonnull
  protected static EncryptedKeyResolver buildBasicEncryptedKeyResolver() {
    final List<EncryptedKeyResolver> resolverChain = new ArrayList<>();
    resolverChain.add(new InlineEncryptedKeyResolver());
    resolverChain.add(new EncryptedElementTypeEncryptedKeyResolver());
    resolverChain.add(new SimpleRetrievalMethodEncryptedKeyResolver());
    resolverChain.add(new SimpleKeyInfoReferenceEncryptedKeyResolver());

    return new ChainingEncryptedKeyResolver(resolverChain);
  }

  /**
   * Extends {@link DefaultSecurityConfigurationBootstrap#buildDefaultEncryptionConfiguration()} with fixes for XXX.
   *
   * @return a {@link BasicEncryptionConfiguration}
   */
  @Nonnull
  public static BasicEncryptionConfiguration buildDefaultEncryptionConfiguration() {
    return (BasicEncryptionConfiguration) patchEncryptionConfiguration(
        DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration(), false);
  }

  /**
   * A method that makes sure that the key agreement configuration for EC always uses key wrap.
   *
   * @param configuration the configuration to patch
   * @param copy whether to make a copy of the supplied configuration (if patched)
   * @return an updated configuration
   */
  @Nonnull
  public static EncryptionConfiguration patchEncryptionConfiguration(
      @Nonnull final EncryptionConfiguration configuration, final boolean copy) {

    if (!needsPatching(configuration)) {
      return configuration;
    }

    final BasicEncryptionConfiguration updatedConfig;
    if (configuration instanceof BasicEncryptionConfiguration) {
      updatedConfig = copy ? copy(configuration) : (BasicEncryptionConfiguration) configuration;
    }
    else {
      updatedConfig = copy(configuration);
    }

    final Map<String, KeyAgreementEncryptionConfiguration> keyAgreementEncryptionConfigurations =
        new HashMap<>(updatedConfig.getKeyAgreementConfigurations());
    final KeyAgreementEncryptionConfiguration ecConf = keyAgreementEncryptionConfigurations.get("EC");
    if (ecConf instanceof final SAMLMetadataKeyAgreementEncryptionConfiguration samlKeyAgreementConf) {
      samlKeyAgreementConf.setMetadataUseKeyWrap(SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always);
    }
    else {
      final SAMLMetadataKeyAgreementEncryptionConfiguration samlEcKeyAgreementParams =
          new SAMLMetadataKeyAgreementEncryptionConfiguration();
      samlEcKeyAgreementParams.setMetadataUseKeyWrap(SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always);
      samlEcKeyAgreementParams.setAlgorithm(ecConf.getAlgorithm());
      samlEcKeyAgreementParams.setParameters(ecConf.getParameters());
      keyAgreementEncryptionConfigurations.put("EC", samlEcKeyAgreementParams);
    }
    updatedConfig.setKeyAgreementConfigurations(keyAgreementEncryptionConfigurations);

    return updatedConfig;
  }

  /**
   * Makes a copy of the supplied {@link EncryptionConfiguration}.
   *
   * @param configuration the object to copy
   * @return a {@link BasicEncryptionConfiguration}
   */
  @Nonnull
  private static BasicEncryptionConfiguration copy(@Nonnull final EncryptionConfiguration configuration) {
    final BasicEncryptionConfiguration copy = new BasicEncryptionConfiguration();
    copy.setDataEncryptionCredentials(configuration.getDataEncryptionCredentials());
    copy.setDataEncryptionAlgorithms(configuration.getDataEncryptionAlgorithms());
    copy.setKeyTransportEncryptionCredentials(configuration.getKeyTransportEncryptionCredentials());
    copy.setKeyTransportEncryptionAlgorithms(configuration.getKeyTransportEncryptionAlgorithms());
    copy.setDataKeyInfoGeneratorManager(configuration.getDataKeyInfoGeneratorManager());
    copy.setKeyTransportKeyInfoGeneratorManager(configuration.getKeyTransportKeyInfoGeneratorManager());
    copy.setRSAOAEPParameters(configuration.getRSAOAEPParameters());
    copy.setRSAOAEPParametersMerge(configuration.isRSAOAEPParametersMerge());
    copy.setKeyTransportAlgorithmPredicate(configuration.getKeyTransportAlgorithmPredicate());
    copy.setKeyAgreementConfigurations(configuration.getKeyAgreementConfigurations());

    copy.setIncludedAlgorithms(configuration.getIncludedAlgorithms());
    copy.setIncludeMerge(configuration.isIncludeMerge());
    copy.setExcludedAlgorithms(configuration.getExcludedAlgorithms());
    copy.setExcludeMerge(configuration.isExcludeMerge());
    copy.setIncludeExcludePrecedence(configuration.getIncludeExcludePrecedence());

    return copy;
  }

  /**
   * Predicate that tells whether the supplied {@link EncryptionConfiguration} needs to be patched. If it contains key
   * agreement encrypt configuration for EC that has key wrap set to "always" no patching is needed.
   *
   * @param configuration the configuration to check
   * @return {@code true} if the configuration needs to be patched, and {@code false} otherwise
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private static boolean needsPatching(final EncryptionConfiguration configuration) {
    final KeyAgreementEncryptionConfiguration ecKeyAgreementConf =
        configuration.getKeyAgreementConfigurations().get("EC");
    if (ecKeyAgreementConf == null) {
      return false;
    }
    if (ecKeyAgreementConf instanceof final SAMLMetadataKeyAgreementEncryptionConfiguration samlKeyAgreementConf) {
      return !Objects.equals(samlKeyAgreementConf.getMetadataUseKeyWrap(),
          SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always);
    }
    return true;
  }

}
