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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.ConcatKDFParams;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionUnmarshaller;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.w3c.dom.Attr;

/**
 *
 */
public class ConcatKDFParamsUnmarshaller extends AbstractXMLEncryptionUnmarshaller {

    /** {@inheritDoc} */
    protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {

        final ConcatKDFParams concat = (ConcatKDFParams) xmlObject;
        try {
            if (attribute.getLocalName().equals(ConcatKDFParams.ALGORITHMID_ATTRIBUTE_NAME)) {
                concat.setAlgorithmID(Hex.decodeHex(attribute.getValue().toCharArray()));
            } else if (attribute.getLocalName().equals(ConcatKDFParams.PARTYUINFO_ATTRIBUTE_NAME)) {
                concat.setPartyUInfo(Hex.decodeHex(attribute.getValue().toCharArray()));
            } else if (attribute.getLocalName().equals(ConcatKDFParams.PARTYVINFO_ATTRIBUTE_NAME)) {
                concat.setPartyVInfo(Hex.decodeHex(attribute.getValue().toCharArray()));
            } else if (attribute.getLocalName().equals(ConcatKDFParams.SUPPPRIVINFO_ATTRIBUTE_NAME)) {
                concat.setSuppPrivInfo(Hex.decodeHex(attribute.getValue().toCharArray()));
            } else if (attribute.getLocalName().equals(ConcatKDFParams.SUPPPUBINFO_ATTRIBUTE_NAME)) {
                concat.setSuppPubInfo(Hex.decodeHex(attribute.getValue().toCharArray()));
            }
        } catch (DecoderException e) {
            throw new UnmarshallingException(e);
        }
    }

    /** {@inheritDoc} */
    protected void processChildElement(final XMLObject parentXMLObject, final XMLObject childXMLObject)
            throws UnmarshallingException {
        final ConcatKDFParams concat = (ConcatKDFParams) parentXMLObject;

        if (childXMLObject instanceof DigestMethod) {
            concat.setDigestMethod((DigestMethod) childXMLObject);
        }
    }
}
