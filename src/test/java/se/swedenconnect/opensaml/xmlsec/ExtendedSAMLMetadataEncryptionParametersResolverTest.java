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
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLMDCredentialContext;
import org.opensaml.saml.security.impl.SAMLMetadataEncryptionParametersResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory.X509KeyInfoGenerator;
import org.springframework.core.io.ClassPathResource;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.OpenSAMLTestBase;
import se.swedenconnect.opensaml.security.credential.KeyAgreementCredential;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;
import se.swedenconnect.opensaml.xmlsec.encryption.support.EcEncryptionConstants;
import se.swedenconnect.opensaml.xmlsec.keyinfo.KeyAgreementKeyInfoGeneratorFactory.KeyAgreementKeyInfoGenerator;

public class ExtendedSAMLMetadataEncryptionParametersResolverTest extends OpenSAMLTestBase {

  @Mock
  MetadataCredentialResolver credentialResolver;

  private EncryptionMethod emRsaOaep;

  private EncryptionMethod emAes256;

  private EncryptionMethod emAes256kw;

  private EncryptionMethod emEcdhComplete;

  private EncryptionMethod emEcdhNoKeyDerivation;

  private EncryptionMethod emEcdhNoConcatKDFParams;
  
  private EncryptionMethod emEcdhUnsupportedKeyDerivation;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);

    emRsaOaep = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emRsaOaep.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

    emAes256 = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emAes256.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

    emAes256kw = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emAes256kw.setAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);

    emEcdhComplete = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emEcdhComplete.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
    KeyDerivationMethod kdm = (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
    kdm.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT);
    ConcatKDFParameters concatKDFParameters = ((ExtendedEncryptionConfiguration) ExtendedDefaultSecurityConfigurationBootstrap
      .buildDefaultEncryptionConfiguration()).getConcatKDFParameters();
    ConcatKDFParams cparams = concatKDFParameters.toXMLObject();
    kdm.getUnknownXMLObjects().add(cparams);
    emEcdhComplete.getUnknownXMLObjects().add(kdm);

    emEcdhNoKeyDerivation = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emEcdhNoKeyDerivation.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);

    emEcdhNoConcatKDFParams = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emEcdhNoConcatKDFParams.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
    KeyDerivationMethod kdm2 = (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
    kdm2.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT);
    emEcdhNoConcatKDFParams.getUnknownXMLObjects().add(kdm2);
    
    emEcdhUnsupportedKeyDerivation = (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
    emEcdhUnsupportedKeyDerivation.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
    KeyDerivationMethod kdm3 = (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
    kdm3.setAlgorithm("http://www.unsupported.algo/abc");
    emEcdhUnsupportedKeyDerivation.getUnknownXMLObjects().add(kdm3);
  }
  
  // Verifies that we haven't messed anything up with OpenSAML's SAMLMetadataEncryptionParametersResolver.
  //
  @Test
  public void testOriginal() throws Exception {

    X509Credential rsaCredential = this.getRsaCredential(
      emAes256  /* Data encryption */,
      emRsaOaep /* Key transport */);

    this.setupCredentialResolver(rsaCredential);

    BasicEncryptionConfiguration config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

    EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
    CriteriaSet criteriaSet = new CriteriaSet(criterion);
    
    SAMLMetadataEncryptionParametersResolver resolver = new SAMLMetadataEncryptionParametersResolver(this.credentialResolver);

    EncryptionParameters params = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params);
    Assert.assertEquals("RSA", params.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm());
    Assert.assertEquals(emRsaOaep.getAlgorithm(), params.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(emAes256.getAlgorithm(), params.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected X509KeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      X509KeyInfoGenerator.class.isInstance(params.getKeyTransportKeyInfoGenerator()));
    
    // The same with the extended generator
    resolver = new SAMLMetadataEncryptionParametersResolver(this.credentialResolver);

    EncryptionParameters params2 = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params2);
    Assert.assertEquals(params.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm(), params2.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm());
    Assert.assertEquals(params.getKeyTransportEncryptionAlgorithm(), params2.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(params.getDataEncryptionAlgorithm(), params2.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected X509KeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      X509KeyInfoGenerator.class.isInstance(params2.getKeyTransportKeyInfoGenerator()));
  }  

  // Test using the extended resolver
  @Test
  public void testExtended() throws Exception {

    X509Credential ecCredential = this.getEcCredential(
      emAes256       /* Data encryption */,
      emAes256kw     /* Key wrapping */,
      emEcdhComplete /* Key agreement */);

    X509Credential rsaCredential = this.getRsaCredential(
      emAes256  /* Data encryption */,
      emRsaOaep /* Key transport */);

    this.setupCredentialResolver(ecCredential, rsaCredential);

    BasicEncryptionConfiguration config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

    EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
    CriteriaSet criteriaSet = new CriteriaSet(criterion);
    
    SAMLMetadataEncryptionParametersResolver resolver = new ExtendedSAMLMetadataEncryptionParametersResolver(this.credentialResolver);

    EncryptionParameters params = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params);
    Assert.assertEquals("AESWrap", params.getKeyTransportEncryptionCredential().getSecretKey().getAlgorithm());
    Assert.assertTrue("Expected KeyAgreementCredential for KeyTransportEncryptionCredential", 
      KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential())); 
    KeyAgreementCredential kaCred = KeyAgreementCredential.class.cast(params.getKeyTransportEncryptionCredential());
    Assert.assertEquals(emEcdhComplete.getAlgorithm(), kaCred.getAgreementMethodAlgorithm());
    Assert.assertEquals(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT, kaCred.getKeyDerivationMethod().getAlgorithm());
    Assert.assertTrue(!kaCred.getKeyDerivationMethod().getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).isEmpty());
    
    Assert.assertEquals(emAes256kw.getAlgorithm(), params.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(emAes256.getAlgorithm(), params.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected KeyAgreementKeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      KeyAgreementKeyInfoGenerator.class.isInstance(params.getKeyTransportKeyInfoGenerator()));
    
    // Let the RSA key be resolved first. Assert that this key is used instead ...
    //
    this.setupCredentialResolver(rsaCredential, ecCredential);
    
    EncryptionParameters params2 = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params2);
    Assert.assertEquals("RSA", params2.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm());
    Assert.assertEquals(emRsaOaep.getAlgorithm(), params2.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(emAes256.getAlgorithm(), params2.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected X509KeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      X509KeyInfoGenerator.class.isInstance(params2.getKeyTransportKeyInfoGenerator()));
  }
  
  // Test that we use local config if no EncryptionMethod elements are supplied in metadata
  //
  @Test
  public void testExtendedLocalAlgoConfig() throws Exception {
    
    X509Credential ecCredential = this.getEcCredential();
    X509Credential rsaCredential = this.getRsaCredential();
    this.setupCredentialResolver(ecCredential, rsaCredential);

    BasicExtendedEncryptionConfiguration config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    config.setKeyTransportEncryptionAlgorithms(Arrays.asList(
      EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP, EncryptionConstants.ALGO_ID_KEYWRAP_AES192));
    config.setDataEncryptionAlgorithms(Arrays.asList(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192));

    EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
    CriteriaSet criteriaSet = new CriteriaSet(criterion);
    
    SAMLMetadataEncryptionParametersResolver resolver = new ExtendedSAMLMetadataEncryptionParametersResolver(this.credentialResolver);

    EncryptionParameters params = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params);
    Assert.assertEquals("AESWrap", params.getKeyTransportEncryptionCredential().getSecretKey().getAlgorithm());
    Assert.assertTrue("Expected KeyAgreementCredential for KeyTransportEncryptionCredential", 
      KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential())); 
    KeyAgreementCredential kaCred = KeyAgreementCredential.class.cast(params.getKeyTransportEncryptionCredential());
    Assert.assertEquals(config.getAgreementMethodAlgorithms().get(0), kaCred.getAgreementMethodAlgorithm());
    Assert.assertEquals(config.getKeyDerivationAlgorithms().get(0), kaCred.getKeyDerivationMethod().getAlgorithm());
    Assert.assertTrue(!kaCred.getKeyDerivationMethod().getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).isEmpty());
    
    Assert.assertEquals(EncryptionConstants.ALGO_ID_KEYWRAP_AES192, params.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192, params.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected KeyAgreementKeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      KeyAgreementKeyInfoGenerator.class.isInstance(params.getKeyTransportKeyInfoGenerator()));
    
    // Let the RSA key be resolved first. Assert that this key is used instead ...
    //
    this.setupCredentialResolver(rsaCredential, ecCredential);
    
    EncryptionParameters params2 = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params2);
    Assert.assertEquals("RSA", params2.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm());
    Assert.assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP, params2.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192, params2.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected X509KeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      X509KeyInfoGenerator.class.isInstance(params2.getKeyTransportKeyInfoGenerator()));    
  }
  
  // Test using the extended resolver
  @Test
  public void testExtendedKeyDerivationDefault() throws Exception {

    X509Credential ecCredential = this.getEcCredential(
      emAes256       /* Data encryption */,
      emAes256kw     /* Key wrapping */,
      emEcdhNoKeyDerivation /* Key agreement */);

    X509Credential rsaCredential = this.getRsaCredential(
      emAes256  /* Data encryption */,
      emRsaOaep /* Key transport */);

    this.setupCredentialResolver(ecCredential, rsaCredential);

    BasicEncryptionConfiguration config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

    EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
    CriteriaSet criteriaSet = new CriteriaSet(criterion);
    
    ExtendedSAMLMetadataEncryptionParametersResolver resolver = new ExtendedSAMLMetadataEncryptionParametersResolver(this.credentialResolver);
    resolver.setUseKeyAgreementDefaults(true);

    EncryptionParameters params = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params);
    Assert.assertEquals("AESWrap", params.getKeyTransportEncryptionCredential().getSecretKey().getAlgorithm());
    Assert.assertTrue("Expected KeyAgreementCredential for KeyTransportEncryptionCredential", 
      KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential())); 
    KeyAgreementCredential kaCred = KeyAgreementCredential.class.cast(params.getKeyTransportEncryptionCredential());
    Assert.assertEquals(emEcdhComplete.getAlgorithm(), kaCred.getAgreementMethodAlgorithm());
    Assert.assertEquals(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT, kaCred.getKeyDerivationMethod().getAlgorithm());
    Assert.assertTrue(!kaCred.getKeyDerivationMethod().getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).isEmpty());
    
    Assert.assertEquals(emAes256kw.getAlgorithm(), params.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(emAes256.getAlgorithm(), params.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected KeyAgreementKeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      KeyAgreementKeyInfoGenerator.class.isInstance(params.getKeyTransportKeyInfoGenerator()));
    
    // Try again. This time the key derivation algorithm is specified, but no ConcatKDFParams ...
    //
    ecCredential = this.getEcCredential(
      emAes256       /* Data encryption */,
      emAes256kw     /* Key wrapping */,
      emEcdhNoConcatKDFParams /* Key agreement */);
    
    this.setupCredentialResolver(ecCredential, rsaCredential);

    params = resolver.resolveSingle(criteriaSet);
    Assert.assertNotNull(params);
    Assert.assertEquals("AESWrap", params.getKeyTransportEncryptionCredential().getSecretKey().getAlgorithm());
    Assert.assertTrue("Expected KeyAgreementCredential for KeyTransportEncryptionCredential", 
      KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential())); 
    kaCred = KeyAgreementCredential.class.cast(params.getKeyTransportEncryptionCredential());
    Assert.assertEquals(emEcdhComplete.getAlgorithm(), kaCred.getAgreementMethodAlgorithm());
    Assert.assertEquals(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT, kaCred.getKeyDerivationMethod().getAlgorithm());
    Assert.assertTrue(!kaCred.getKeyDerivationMethod().getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).isEmpty());
    
    Assert.assertEquals(emAes256kw.getAlgorithm(), params.getKeyTransportEncryptionAlgorithm());
    Assert.assertEquals(emAes256.getAlgorithm(), params.getDataEncryptionAlgorithm());
    Assert.assertTrue("Expected KeyAgreementKeyInfoGenerator for KeyTransportKeyInfoGenerator", 
      KeyAgreementKeyInfoGenerator.class.isInstance(params.getKeyTransportKeyInfoGenerator()));    
  }
  
  private void setupCredentialResolver(Credential... credentials) throws ResolverException {
    final List<Credential> credList = credentials != null
        ? Arrays.asList(credentials) : Collections.emptyList();
    
    Mockito.when(credentialResolver.resolve(Mockito.any())).then(new Answer<Iterable<Credential>>() {
      @Override
      public Iterable<Credential> answer(InvocationOnMock invocation) throws Throwable {
        return () -> credList.iterator();
      }
    });
  }

  private X509Credential getRsaCredential(EncryptionMethod... encryptionMethods) throws Exception {
    X509Credential credential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    return this.getCredential(credential, encryptionMethods);
  }

  private X509Credential getEcCredential(EncryptionMethod... encryptionMethods) throws Exception {
    X509Credential credential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("eckey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    return this.getCredential(credential, encryptionMethods);
  }

  private X509Credential getCredential(X509Credential cred, EncryptionMethod... encryptionMethods) throws Exception {
    ((KeyStoreX509CredentialAdapter) cred).setUsageType(UsageType.ENCRYPTION);

    KeyDescriptor kd = Mockito.mock(KeyDescriptor.class);
    if (encryptionMethods == null) {
      Mockito.when(kd.getEncryptionMethods()).thenReturn(Collections.emptyList());
    }
    else {
      Mockito.when(kd.getEncryptionMethods()).thenReturn(Arrays.asList(encryptionMethods));
    }
    SAMLMDCredentialContext ecContext = new SAMLMDCredentialContext(kd);
    cred.getCredentialContextSet().add(ecContext);
    return cred;
  }

}
