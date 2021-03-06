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
package se.swedenconnect.opensaml;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.EncryptionConfiguration;

import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Test cases for {@code OpenSAMLSecurityExtensionConfig}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLSecurityExtensionConfigTest {

  @Test
  public void testInit() throws Exception {

    OpenSAMLInitializer.getInstance()
      .initialize(new OpenSAMLSecurityExtensionConfig());
    
    // Assert that our extension have been loaded
    //
    EncryptionConfiguration config = ConfigurationService.get(EncryptionConfiguration.class);
    Assert.assertTrue("Expected encryption configuration to be of ExtendedEncryptionConfiguration", 
      ExtendedEncryptionConfiguration.class.isInstance(config));
    
    ExtendedEncryptionConfiguration extConfig = ExtendedEncryptionConfiguration.class.cast(config);
    Assert.assertFalse(extConfig.getAgreementMethodAlgorithms().isEmpty());
    Assert.assertFalse(extConfig.getKeyDerivationAlgorithms().isEmpty());
    Assert.assertNotNull(extConfig.getConcatKDFParameters());
    
    // Also try to create an XMLObject defined in this lib ...
    XMLObjectSupport.buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
  }

}
