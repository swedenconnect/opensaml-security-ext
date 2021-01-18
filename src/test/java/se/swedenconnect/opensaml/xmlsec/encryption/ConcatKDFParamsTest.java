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
package se.swedenconnect.opensaml.xmlsec.encryption;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.w3c.dom.Element;

import se.swedenconnect.opensaml.OpenSAMLTestBase;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Test cases for {@link ConcatKDFParams}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ConcatKDFParamsTest extends OpenSAMLTestBase {

  @Test
  public void testSimpleEncodeDecode() throws Exception {
    ConcatKDFParams params = createXmlObject(ConcatKDFParams.class, ConcatKDFParams.DEFAULT_ELEMENT_NAME);    
    DigestMethod digest = createXmlObject(DigestMethod.class, DigestMethod.DEFAULT_ELEMENT_NAME);
    digest.setAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);    
    params.setDigestMethod(digest);

    // Marshall
    Element e = marshall(params);
    
    // Unmarshall
    ConcatKDFParams params2 = unmarshall(e, ConcatKDFParams.class);
    
    // Verify
    Assert.assertEquals(digest.getAlgorithm(), params2.getDigestMethod().getAlgorithm());
  }
  
  @Test
  public void testAttributes() throws Exception {
    ConcatKDFParams params = createXmlObject(ConcatKDFParams.class, ConcatKDFParams.DEFAULT_ELEMENT_NAME);    
    DigestMethod digest = createXmlObject(DigestMethod.class, DigestMethod.DEFAULT_ELEMENT_NAME);
    digest.setAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);    
    params.setDigestMethod(digest);
    
    // From the example in the XML enc spec...
    //
    params.setAlgorithmID(new byte[] { 0x00, 0x00 });
    params.setPartyUInfo(Hex.decode("03d8"));
    params.setPartyVInfo(Hex.decode("03d0"));
    
    // Marshall
    Element e = marshall(params);
    
    // Verify that the attributes are correctly encoded
    Assert.assertEquals("0000", e.getAttribute(ConcatKDFParams.ALGORITHMID_ATTRIBUTE_NAME));
    Assert.assertEquals("03d8", e.getAttribute(ConcatKDFParams.PARTY_UI_NFO_ATTRIBUTE_NAME));
    Assert.assertEquals("03d0", e.getAttribute(ConcatKDFParams.PARTY_V_INFO_ATTRIBUTE_NAME));
    
    // Unmarshall
    ConcatKDFParams params2 = unmarshall(e, ConcatKDFParams.class);
    
    // Verify
    Assert.assertEquals(digest.getAlgorithm(), params2.getDigestMethod().getAlgorithm());
    Assert.assertArrayEquals(new byte[] { 0x00, 0x00 }, params2.getAlgorithmID());
    Assert.assertArrayEquals(new byte[] { 0x03, (byte)0xd8 }, params2.getPartyUInfo());
    Assert.assertArrayEquals(new byte[] { 0x03, (byte)0xd0 }, params2.getPartyVInfo());
    Assert.assertNull(params2.getSuppPubInfo());
    Assert.assertNull(params2.getSuppPrivInfo());
    
  }
    
}
