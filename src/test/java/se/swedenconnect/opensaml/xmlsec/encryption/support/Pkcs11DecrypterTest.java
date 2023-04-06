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

import java.util.Arrays;

import net.shibboleth.shared.resolver.CriteriaSet;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.EncryptionParametersResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Test cases for Pkcs11Decrypter.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pkcs11DecrypterTest extends OpenSAMLTestBase {

  /** The value that we encrypt. */
  private final static String VALUE = "https://www.idsec.se";

  /** The encrypted object. */
  private Issuer encryptedObject;

  /** The RSA credential. */
  private X509Credential rsaCredential;

  /** The RSA certificate/peer credential. */
  private X509Credential rsaPeerCredential;

  /**
   * Sets up objects needed for our tests.
   * 
   * @throws Exception
   *           for errors
   */
  @Before
  public void setUp() throws Exception {

    // Create the XML object that should be encrypted.
    this.encryptedObject = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    this.encryptedObject.setValue(VALUE);

    // Load credentials ...
    //
    this.rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    this.rsaPeerCredential = new BasicX509Credential(this.rsaCredential.getEntityCertificate());
    ((BasicX509Credential) this.rsaPeerCredential).setUsageType(UsageType.ENCRYPTION);
  }

  @Test
  public void testDecrypt() throws Exception {

    final BasicEncryptionConfiguration config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    config.setKeyTransportEncryptionCredentials(Arrays.asList(this.rsaPeerCredential));
    
    final EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);

    final EncryptionParametersResolver resolver = new BasicEncryptionParametersResolver();
    EncryptionParameters params = resolver.resolveSingle(new CriteriaSet(criterion));

    // Verify that RSA OAEP will used
    Assert.assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP, params.getKeyTransportEncryptionAlgorithm());

    org.opensaml.xmlsec.encryption.support.Encrypter encrypter = new org.opensaml.xmlsec.encryption.support.Encrypter();

    EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
      new DataEncryptionParameters(params), new KeyEncryptionParameters(params, "recipient"));

    // OK, let's decrypt ...
    //
    Pkcs11Decrypter decrypter = new Pkcs11Decrypter(DecryptionUtils.createDecryptionParameters(rsaCredential));
    decrypter.setRootInNewDocument(true);
    decrypter.setTestMode(true);

    Issuer decryptedObject = (Issuer) decrypter.decryptData(encryptedData);
    System.out.println(OpenSAMLTestBase.toString(decryptedObject));

    Assert.assertEquals(String.format("Expected '%s' as decrypted message", VALUE), VALUE, decryptedObject.getValue());
  }

}
