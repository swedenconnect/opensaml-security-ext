/*
 * Copyright 2019-2023 Sweden Connect
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
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
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
  public static BasicSignatureSigningConfiguration buildDefaultSignatureSigningConfiguration(
      final SignatureSigningConfiguration config) {

    BasicSignatureSigningConfiguration updatedConfig;
    if (config == null) {
      updatedConfig = DefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration();
    }
    else if (BasicSignatureSigningConfiguration.class.isInstance(config)) {
      updatedConfig = BasicSignatureSigningConfiguration.class.cast(config);
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
  protected static EncryptedKeyResolver buildBasicEncryptedKeyResolver() {
    final List<EncryptedKeyResolver> resolverChain = new ArrayList<>();
    resolverChain.add(new InlineEncryptedKeyResolver());
    resolverChain.add(new EncryptedElementTypeEncryptedKeyResolver());
    resolverChain.add(new SimpleRetrievalMethodEncryptedKeyResolver());
    resolverChain.add(new SimpleKeyInfoReferenceEncryptedKeyResolver());

    return new ChainingEncryptedKeyResolver(resolverChain);
  }

}
