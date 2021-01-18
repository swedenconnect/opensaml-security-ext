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

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.encryption.impl.AbstractXMLEncryptionUnmarshaller;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.w3c.dom.Attr;

import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Unmarshaller for {@link ConcatKDFParams}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ConcatKDFParamsUnmarshaller extends AbstractXMLEncryptionUnmarshaller {

  /** {@inheritDoc} */
  protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {

    ConcatKDFParams concatKDFParams = (ConcatKDFParams) xmlObject;

    try {
      if (attribute.getLocalName().equals(ConcatKDFParams.ALGORITHMID_ATTRIBUTE_NAME)) {
        concatKDFParams.setAlgorithmID(Hex.decode(attribute.getValue()));
      }
      else if (attribute.getLocalName().equals(ConcatKDFParams.PARTY_UI_NFO_ATTRIBUTE_NAME)) {
        concatKDFParams.setPartyUInfo(Hex.decode(attribute.getValue()));
      }
      else if (attribute.getLocalName().equals(ConcatKDFParams.PARTY_V_INFO_ATTRIBUTE_NAME)) {
        concatKDFParams.setPartyVInfo(Hex.decode(attribute.getValue()));
      }
      else if (attribute.getLocalName().equals(ConcatKDFParams.SUPP_PUB_INFO_ATTRIBUTE_NAME)) {
        concatKDFParams.setSuppPubInfo(Hex.decode(attribute.getValue()));
      }
      else if (attribute.getLocalName().equals(ConcatKDFParams.SUPP_PRIV_INFO_ATTRIBUTE_NAME)) {
        concatKDFParams.setSuppPrivInfo(Hex.decode(attribute.getValue()));
      }
    }
    catch (DecoderException e) {
      throw new UnmarshallingException(e);
    }
  }

  /** {@inheritDoc} */
  protected void processChildElement(final XMLObject parentXMLObject, final XMLObject childXMLObject) throws UnmarshallingException {

    ConcatKDFParams concatKDFParams = (ConcatKDFParams) parentXMLObject;
    if (childXMLObject instanceof DigestMethod) {
      concatKDFParams.setDigestMethod((DigestMethod) childXMLObject);
    }
  }

}
