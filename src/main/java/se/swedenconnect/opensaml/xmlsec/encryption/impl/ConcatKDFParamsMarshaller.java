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

import org.bouncycastle.util.encoders.Hex;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionMarshaller;
import org.w3c.dom.Element;

import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Marshaller for {@link ConcatKDFParams}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ConcatKDFParamsMarshaller extends AbstractXMLEncryptionMarshaller {

  /** {@inheritDoc} */
  protected void marshallAttributes(XMLObject xmlObject, Element domElement) throws MarshallingException {

    ConcatKDFParams concatKDFParams = (ConcatKDFParams) xmlObject;
    
    if (concatKDFParams.getAlgorithmID() != null) {
      domElement.setAttributeNS(null, ConcatKDFParams.ALGORITHMID_ATTRIBUTE_NAME, Hex.toHexString(concatKDFParams.getAlgorithmID()));
    }
    if (concatKDFParams.getPartyUInfo() != null) {
      domElement.setAttributeNS(null, ConcatKDFParams.PARTY_UI_NFO_ATTRIBUTE_NAME, Hex.toHexString(concatKDFParams.getPartyUInfo()));
    }
    if (concatKDFParams.getPartyVInfo() != null) {
      domElement.setAttributeNS(null, ConcatKDFParams.PARTY_V_INFO_ATTRIBUTE_NAME, Hex.toHexString(concatKDFParams.getPartyVInfo()));
    }
    if (concatKDFParams.getSuppPubInfo() != null) {
      domElement.setAttributeNS(null, ConcatKDFParams.SUPP_PUB_INFO_ATTRIBUTE_NAME, Hex.toHexString(concatKDFParams.getSuppPubInfo()));
    }
    if (concatKDFParams.getSuppPrivInfo() != null) {
      domElement.setAttributeNS(null, ConcatKDFParams.SUPP_PRIV_INFO_ATTRIBUTE_NAME, Hex.toHexString(concatKDFParams.getSuppPrivInfo()));
    }
  }

}
