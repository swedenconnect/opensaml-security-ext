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
package se.swedenconnect.opensaml.xmlsec;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.springframework.core.io.ClassPathResource;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import se.swedenconnect.opensaml.OpenSAMLTestBase;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;

/**
 * Test cases for {@link ExtendedBasicEncryptionParametersResolver}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedBasicEncryptionParametersResolverTest extends OpenSAMLTestBase {

  /**
   * Test using the OpenSAML BasicEncryptionParametersResolver. It won't find any encryption parameters that can be used
   * to ECDH key agreement.
   * 
   * @throws Exception
   *           for errors
   */
  @Test
  public void testBasicEncryptionParametersResolver() throws Exception {
    
    X509Credential ecCredential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("eckey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    
    X509Credential rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    
    ExtendedBasicEncryptionConfiguration config = (ExtendedBasicEncryptionConfiguration) 
        ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    config.setKeyTransportEncryptionCredentials(Arrays.asList(ecCredential));
    
    EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
    CriteriaSet criteriaSet = new CriteriaSet(criterion);
    
    ExtendedBasicEncryptionParametersResolver resolver = new ExtendedBasicEncryptionParametersResolver();
    EncryptionParameters params = resolver.resolveSingle(criteriaSet);
    
//    EncryptionParameters params = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params);
  }

}
