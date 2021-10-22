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
package se.swedenconnect.opensaml.xmlsec.encryption.support;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.x509.X509Credential;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Test cases for {@code SAMLObjectDecrypter}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 */
public class SAMLObjectDecrypterTest extends OpenSAMLTestBase {

  @Test
  public void test() throws Exception {
    final X509Credential credential = loadKeyStoreCredential(
      new ClassPathResource("sp-enc-cert.jks").getInputStream(), "secret", "eid", "secret");
    final SAMLObjectDecrypter decrypter = new SAMLObjectDecrypter(credential); 
    
    final Resource r = new ClassPathResource("encrypted-20180428.xml");
    final Response response = unmarshall(r.getInputStream(), Response.class);
    
    final EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
    
    final Assertion assertion = decrypter.decrypt(encryptedAssertion, Assertion.class);
    Assert.assertNotNull(assertion);
    // System.out.println(SerializeSupport.prettyPrintXML(assertion.getDOM()));
  }
    
  @Test
  public void testP11workaround() throws Exception {
    final X509Credential credential = loadKeyStoreCredential(
      new ClassPathResource("sp-enc-cert.jks").getInputStream(), "secret", "eid", "secret");
    final SAMLObjectDecrypter decrypter = new SAMLObjectDecrypter(credential); 
    decrypter.setPkcs11testMode(true);
    decrypter.setPkcs11Workaround(true);

    final Resource r = new ClassPathResource("encrypted-basic.xml");
    final Response response = unmarshall(r.getInputStream(), Response.class);
    
    final EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
    
    final Assertion assertion = decrypter.decrypt(encryptedAssertion, Assertion.class);
    Assert.assertNotNull(assertion);
    //System.out.println(SerializeSupport.prettyPrintXML(assertion.getDOM()));
  }
  
}
