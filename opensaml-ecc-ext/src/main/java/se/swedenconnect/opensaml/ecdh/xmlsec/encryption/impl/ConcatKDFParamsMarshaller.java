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

import org.bouncycastle.util.encoders.Hex;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.ConcatKDFParams;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionMarshaller;
import org.w3c.dom.Element;

/**
 *
 */
public class ConcatKDFParamsMarshaller extends AbstractXMLEncryptionMarshaller {
    /** {@inheritDoc} */
    protected void marshallAttributes(final XMLObject xmlObject, final Element domElement) throws MarshallingException {
        final ConcatKDFParams kdfParams = (ConcatKDFParams) xmlObject;

        if (kdfParams.getAlgorithmID() != null) {
            domElement.setAttributeNS(null, ConcatKDFParams.ALGORITHMID_ATTRIBUTE_NAME,
                    Hex.toHexString(kdfParams.getAlgorithmID()));
        }
        if (kdfParams.getPartyUInfo() != null) {
            domElement.setAttributeNS(null, ConcatKDFParams.PARTYUINFO_ATTRIBUTE_NAME,
                    Hex.toHexString(kdfParams.getPartyUInfo()));
        }
        if (kdfParams.getPartyVInfo() != null) {
            domElement.setAttributeNS(null, ConcatKDFParams.PARTYVINFO_ATTRIBUTE_NAME,
                    Hex.toHexString(kdfParams.getPartyVInfo()));
        }
        if (kdfParams.getSuppPrivInfo() != null) {
            domElement.setAttributeNS(null, ConcatKDFParams.SUPPPRIVINFO_ATTRIBUTE_NAME,
                    Hex.toHexString(kdfParams.getSuppPrivInfo()));
        }
        if (kdfParams.getSuppPubInfo() != null) {
            domElement.setAttributeNS(null, ConcatKDFParams.SUPPPUBINFO_ATTRIBUTE_NAME,
                    Hex.toHexString(kdfParams.getSuppPubInfo()));
        }
    }

}
