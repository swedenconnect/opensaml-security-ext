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
package se.swedenconnect.opensaml.xmlsec.encryption.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionMarshaller;
import org.w3c.dom.Element;

import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * Marshaller for {@link KeyDerivationMethod}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyDerivationMethodMarshaller extends AbstractXMLEncryptionMarshaller {

  /** {@inheritDoc} */
  protected void marshallAttributes(final XMLObject xmlObject, final Element domElement) throws MarshallingException {
    
    KeyDerivationMethod keyDerivationMethod = (KeyDerivationMethod) xmlObject;

    if (keyDerivationMethod.getAlgorithm() != null) {
      domElement.setAttributeNS(null, KeyDerivationMethod.ALGORITHM_ATTRIBUTE_NAME, keyDerivationMethod.getAlgorithm());
    }
  }
  
}
