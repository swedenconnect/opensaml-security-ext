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
package se.swedenconnect.opensaml.xmlsec.encryption.impl;

import org.opensaml.core.xml.AbstractXMLObjectBuilder;
import org.opensaml.xmlsec.encryption.XMLEncryptionBuilder;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * Builder for {@link KeyDerivationMethod}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyDerivationMethodBuilder extends AbstractXMLObjectBuilder<KeyDerivationMethod> implements
    XMLEncryptionBuilder<KeyDerivationMethod> {

  /** {@inheritDoc} */
  public KeyDerivationMethod buildObject() {
    return buildObject(
      EncryptionConstants.XMLENC11_NS, KeyDerivationMethod.DEFAULT_ELEMENT_LOCAL_NAME, EncryptionConstants.XMLENC11_PREFIX);
  }

  /** {@inheritDoc} */
  public KeyDerivationMethod buildObject(String namespaceURI, String localName, String namespacePrefix) {
    return new KeyDerivationMethodImpl(namespaceURI, localName, namespacePrefix);
  }
  
}
