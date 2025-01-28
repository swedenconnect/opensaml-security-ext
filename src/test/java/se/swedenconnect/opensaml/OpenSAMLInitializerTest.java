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
package se.swedenconnect.opensaml;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Issuer;

import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;

/**
 * Test cases for {@code OpenSAMLInitializer}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLInitializerTest {

  @Test
  public void testInitSecurityExtensions() {

    // Try creating OpenSAML object. Should not be possible.
    Assertions.assertThrows(XMLRuntimeException.class, () -> {
      XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    });

    Assertions.assertDoesNotThrow(() -> {
      OpenSAMLInitializer.getInstance()
          .initialize(
              new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
              new OpenSAMLSecurityExtensionConfig());

      // Now, it should work
      XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    });
  }

}
