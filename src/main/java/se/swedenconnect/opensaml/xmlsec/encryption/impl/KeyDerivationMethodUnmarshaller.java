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

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionUnmarshaller;
import org.w3c.dom.Attr;

import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * Unmarshaller for {@link KeyDerivationMethod}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyDerivationMethodUnmarshaller extends AbstractXMLEncryptionUnmarshaller {

  /** {@inheritDoc} */
  protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {

    KeyDerivationMethod keyDerivationMethod = (KeyDerivationMethod) xmlObject;

    if (attribute.getLocalName().equals(KeyDerivationMethod.ALGORITHM_ATTRIBUTE_NAME)) {
      keyDerivationMethod.setAlgorithm(attribute.getValue());
      attribute.getOwnerElement().setIdAttributeNode(attribute, true);
    }
  }

  /** {@inheritDoc} */
  protected void processChildElement(final XMLObject parentXMLObject, final XMLObject childXMLObject) throws UnmarshallingException {
    KeyDerivationMethod keyDerivationMethod = (KeyDerivationMethod) parentXMLObject;
    keyDerivationMethod.getUnknownXMLObjects().add(childXMLObject);
  }
}
