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

import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
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

    config.setRSAOAEPParameters(new RSAOAEPParameters(
      SignatureConstants.ALGO_ID_DIGEST_SHA256,
      EncryptionConstants.ALGO_ID_MGF1_SHA1,
      null));

    // Make sure to get support for key agreement algorithms ...
    return ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration(config);
  }

}
