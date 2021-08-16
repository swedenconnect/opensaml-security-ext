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
package se.swedenconnect.opensaml.xmlsec.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

/**
 * Security defaults according to Kantara's
 * <a href="https://kantarainitiative.github.io/SAMLprofiles/saml2int.html">SAML2Int specification</a>.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SAML2IntSecurityConfiguration extends AbstractSecurityConfiguration {

  /** {@inheritDoc} */
  @Override
  public String getProfileName() {
    return "saml2int";
  }

  /**
   * Builds an {@link EncryptionConfiguration} that is according to SAML2Int.
   */
  @Override
  protected EncryptionConfiguration createDefaultEncryptionConfiguration() {
    BasicEncryptionConfiguration config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

    config.setDataEncryptionAlgorithms(Arrays.asList(
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM,
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192,
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128,
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES));

    config.setKeyTransportEncryptionAlgorithms(Arrays.asList(
      EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
      EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11,

      EncryptionConstants.ALGO_ID_KEYWRAP_AES256,
      EncryptionConstants.ALGO_ID_KEYWRAP_AES192,
      EncryptionConstants.ALGO_ID_KEYWRAP_AES128,
      EncryptionConstants.ALGO_ID_KEYWRAP_TRIPLEDES));

    return config;
  }

  /**
   * Black-lists SHA-1 from use and adds RSA-PSS algos.
   */
  @Override
  protected SignatureSigningConfiguration createDefaultSignatureSigningConfiguration() {
    BasicSignatureSigningConfiguration config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration();
    
    // Remove SHA-1
    List<String> excludedAlgorithms = new ArrayList<>(config.getExcludedAlgorithms());
    excludedAlgorithms.add(SignatureConstants.ALGO_ID_DIGEST_SHA1);
    excludedAlgorithms.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    excludedAlgorithms.add(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);
    excludedAlgorithms.add(SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1);
    excludedAlgorithms.add(SignatureConstants.ALGO_ID_MAC_HMAC_SHA1);    
    config.setExcludedAlgorithms(excludedAlgorithms);
    
    return config;
  }

}
