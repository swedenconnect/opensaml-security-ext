/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.opensaml.ecdh.xmlsec.encryption.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionUnmarshaller;
import org.w3c.dom.Attr;

/**
 *
 */
public class KeyDerivationMethodUnmarshaller extends AbstractXMLEncryptionUnmarshaller {

    /** {@inheritDoc} */
    protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {

        final KeyDerivationMethod kdm = (KeyDerivationMethod) xmlObject;
        if (attribute.getLocalName().equals(KeyDerivationMethod.ALGORITHM_ATTRIBUTE_NAME)) {
            kdm.setAlgorithm(attribute.getValue());
            attribute.getOwnerElement().setIdAttributeNode(attribute, true);
        }
    }

    /** {@inheritDoc} */
    protected void processChildElement(final XMLObject parentXMLObject, final XMLObject childXMLObject)
            throws UnmarshallingException {
        final KeyDerivationMethod am = (KeyDerivationMethod) parentXMLObject;
        am.getUnknownXMLObjects().add(childXMLObject);
    }
}
