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

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionConfiguration;

/**
 * Test cases for {@code SAML2IntSecurityConfiguration}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SAML2IntSecurityConfigurationTest {

  @Test
  public void testConfig() throws Exception {

    OpenSAMLInitializer.getInstance()
      .initialize(new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()));

    EncryptionConfiguration config = ConfigurationService.get(EncryptionConfiguration.class);
    
    // Assert we have the SAML2Int defaults.
    Assert.assertEquals(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM, config.getDataEncryptionAlgorithms().get(0));
    Assert.assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA1, config.getRSAOAEPParameters().getDigestMethod());
    Assert.assertTrue(config.getKeyTransportEncryptionAlgorithms().contains(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11));
    
    // Assert that the extensions of this lib are there ...
    Assert.assertTrue("Expected encryption configuration to be of ExtendedEncryptionConfiguration",
      ExtendedEncryptionConfiguration.class.isInstance(config));

    ExtendedEncryptionConfiguration extConfig = ExtendedEncryptionConfiguration.class.cast(config);
    Assert.assertFalse(extConfig.getAgreementMethodAlgorithms().isEmpty());
    Assert.assertFalse(extConfig.getKeyDerivationAlgorithms().isEmpty());
    Assert.assertNotNull(extConfig.getConcatKDFParameters());

  }

}
