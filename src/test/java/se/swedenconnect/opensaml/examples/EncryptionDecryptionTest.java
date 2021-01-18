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
package se.swedenconnect.opensaml.examples;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.criterion.RoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
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
import org.springframework.core.io.ClassPathResource;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import se.swedenconnect.opensaml.OpenSAMLTestBase;
import se.swedenconnect.opensaml.security.credential.KeyAgreementCredential;
import se.swedenconnect.opensaml.xmlsec.BasicExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionParametersResolver;
import se.swedenconnect.opensaml.xmlsec.ExtendedSAMLMetadataEncryptionParametersResolver;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.support.DecryptionUtils;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ECDHKeyAgreementParameters;
import se.swedenconnect.opensaml.xmlsec.encryption.support.EcEncryptionConstants;

/**
 * Examples for different ways of encrypting and decrypting using key agreement.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EncryptionDecryptionTest extends OpenSAMLTestBase {

  /** The value that we encrypt. */
  private final static String VALUE = "https://www.idsec.se";

  /** The encrypted object. */
  private Issuer encryptedObject;

  /** The EC credential. */
  private X509Credential ecCredential;

  /** The EC certificate/peer credential. */
  private X509Credential ecPeerCredential;

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
    this.ecCredential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("eckey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    this.ecPeerCredential = new BasicX509Credential(this.ecCredential.getEntityCertificate());
    ((BasicX509Credential) this.ecPeerCredential).setUsageType(UsageType.ENCRYPTION);

    this.rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");
    this.rsaPeerCredential = new BasicX509Credential(this.rsaCredential.getEntityCertificate());
    ((BasicX509Credential) this.rsaPeerCredential).setUsageType(UsageType.ENCRYPTION);
  }

  /**
   * Illustrates how we encrypt using ECDH key agreement where we set up the encryption parameters manually. Normally,
   * we obtain encryption parameters from a {@link EncryptionParametersResolver} (see below).
   * 
   * @throws Exception
   *           for test errors
   */
  @Test
  public void manualEncryptionSetup() throws Exception {

    // Set up parameters for encryption manually ...
    //
    DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
    dataEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);

    // In order for ECDH to be possible with OpenSAML's Encrypter class we need to instantiate
    // our special purpose key encryption parameters object.
    //
    ECDHKeyAgreementParameters kekParams = new ECDHKeyAgreementParameters();
    kekParams.setPeerCredential(this.ecPeerCredential);
    // The kekParams will use default algorithms for key wrapping and key agreement.

    // We also need the special purpose key info generator (for key agreement).
    kekParams.setKeyInfoGenerator(
      ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultKeyAgreementKeyInfoGeneratorFactory().newInstance());

    // Encrypt
    //
    Encrypter encrypter = new Encrypter(dataEncryptionParameters, kekParams);
    encrypter.setKeyPlacement(KeyPlacement.INLINE);

    EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject, dataEncryptionParameters, kekParams);

    System.out.println("Encrypted data:\n" + OpenSAMLTestBase.toString(encryptedData));

    // OK, let's decrypt ...
    //
    Decrypter decrypter = new Decrypter(DecryptionUtils.createDecryptionParameters(rsaCredential, ecCredential));
    decrypter.setRootInNewDocument(true);

    Issuer decryptedObject = (Issuer) decrypter.decryptData(encryptedData);
    System.out.println(OpenSAMLTestBase.toString(decryptedObject));

    Assert.assertEquals(String.format("Expected '%s' as decrypted message", VALUE), VALUE, decryptedObject.getValue());
  }

  /**
   * Illustrates how we use the {@link ExtendedEncryptionParametersResolver} to resolve encryption parameters before
   * encrypting.
   * 
   * @throws Exception
   *           for test errors
   */
  @Test
  public void resolvedEncryptionParameters() throws Exception {

    // We use the default encryption configuration. The extended part introduces support
    // for key agreement and key derivation configuration.
    //
    BasicExtendedEncryptionConfiguration config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

    // Install our key transport encryption credentials.
    // The setKeyTransportEncryptionCredentials will analyze whether the added credential can be
    // used for ordinary key transport or key agreement.
    // Note: You may also use the setKeyAgreementCredentials to explicitly assign credentials that
    // may be used for key agreement.
    //
    config.setKeyTransportEncryptionCredentials(Arrays.asList(this.ecPeerCredential, this.rsaPeerCredential));

    // Make our encryption configuration into a criteria for the resolver.
    //
    EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
    CriteriaSet criteriaSet = new CriteriaSet(criterion);

    // Instantiate our extension of the EncryptionParametersResolver to get the parameters needed
    // for encryption.
    //
    ExtendedEncryptionParametersResolver resolver = new ExtendedEncryptionParametersResolver();
    EncryptionParameters params = resolver.resolveSingle(criteriaSet);

    // As you see above we have both an EC credential and a RSA credential. The ExtendedEncryptionParametersResolver
    // will use the first credential that matches the supplied EncryptionConfigurationCriterion.
    // In this case it should be the EC credential. Let's assert that ...
    //
    Assert.assertTrue("Expected KeyAgreementCredential for KeyTransportEncryptionCredential",
      KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential()));

    // Encrypt
    // For this example we use the base Encrypter ...
    //
    org.opensaml.xmlsec.encryption.support.Encrypter encrypter = new org.opensaml.xmlsec.encryption.support.Encrypter();

    EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
      new DataEncryptionParameters(params), new KeyEncryptionParameters(params, "recipient"));

    System.out.println("Encrypted data:\n" + OpenSAMLTestBase.toString(encryptedData));

    // OK, let's decrypt ...
    //
    Decrypter decrypter = new Decrypter(DecryptionUtils.createDecryptionParameters(ecCredential, rsaCredential));
    decrypter.setRootInNewDocument(true);

    Issuer decryptedObject = (Issuer) decrypter.decryptData(encryptedData);
    System.out.println(OpenSAMLTestBase.toString(decryptedObject));

    Assert.assertEquals(String.format("Expected '%s' as decrypted message", VALUE), VALUE, decryptedObject.getValue());

    // OK, let's put the RSA credential first and verify that RSA OAEP is used instead.
    //
    config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    config.setKeyTransportEncryptionCredentials(Arrays.asList(this.rsaPeerCredential, this.ecPeerCredential));

    criterion = new EncryptionConfigurationCriterion(config);
    params = resolver.resolveSingle(new CriteriaSet(criterion));

    Assert.assertEquals("RSA", params.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm());
  }

  /**
   * Illustrates the "real" case where we resolve encryption parameters by parsing the peer metadata entry.
   * 
   * @throws Exception
   *           for test errors
   */
  @Test
  public void resolvedEncryptionParametersFromMetadata() throws Exception {
    
    // The peer metadata.
    final EntityDescriptor metadata = OpenSAMLTestBase.unmarshall(
      new ClassPathResource("metadata-ec-with-enc-method.xml").getInputStream(), EntityDescriptor.class);

    // Set up a MetadataCredentialResolver (a resolver that reads from SAML metadata)
    //
    MetadataCredentialResolver credentialResolver = new MetadataCredentialResolver();
    credentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
    credentialResolver.initialize();

    // Set up the criteria ...
    //

    // We need default algorithms (in case no are given in EncryptionMethod in metadata).
    EncryptionConfigurationCriterion encConfCriterion = new EncryptionConfigurationCriterion(
      ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration());

    // RoleDescriptorCriterion gives us the metadata. In a real case a RoleDescriptorResolver would
    // be used.
    RoleDescriptorCriterion rdCriterion = new RoleDescriptorCriterion(metadata.getRoleDescriptors().get(0));

    CriteriaSet criteriaSet = new CriteriaSet(encConfCriterion, rdCriterion);

    // Resolve encryption parameters and encrypt.
    //
    ExtendedSAMLMetadataEncryptionParametersResolver resolver = new ExtendedSAMLMetadataEncryptionParametersResolver(credentialResolver);

    EncryptionParameters params = resolver.resolveSingle(criteriaSet);

    // The metadata specifies which algorithms that should be used.
    // Let's assert that the peer's suggestions are used.
    //
    Assert.assertTrue(String.format("Expected KeyAgreementCredential for KeyTransportEncryptionCredential, but was '%s'", 
      params.getKeyTransportEncryptionCredential() != null ? params.getKeyTransportEncryptionCredential().getClass().getSimpleName() : "null"), 
      KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential()));

    Assert.assertEquals(String.format("Expected '%s' for data encryption algorithm", EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256),
      EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, params.getDataEncryptionAlgorithm());
    Assert.assertEquals(String.format("Expected '%s' for key transport encryption algorithm", EncryptionConstants.ALGO_ID_KEYWRAP_AES256),
      EncryptionConstants.ALGO_ID_KEYWRAP_AES256, params.getKeyTransportEncryptionAlgorithm());

    // The special KeyAgreementCredential holds the rest of the information ...
    Assert.assertEquals("AESWrap", params.getKeyTransportEncryptionCredential().getSecretKey().getAlgorithm());
    final KeyAgreementCredential kaCred = KeyAgreementCredential.class.cast(params.getKeyTransportEncryptionCredential());
    Assert.assertEquals(String.format("Expected KeyAgreement algorithm '%s'", EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES),
      EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES, kaCred.getAgreementMethodAlgorithm());
    Assert.assertEquals(String.format("Expected KeyDerivation algorithm '{}'", EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT),
      EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT, kaCred.getKeyDerivationMethod().getAlgorithm());

    org.opensaml.xmlsec.encryption.support.Encrypter encrypter = new org.opensaml.xmlsec.encryption.support.Encrypter();

    EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
      new DataEncryptionParameters(params), new KeyEncryptionParameters(params, metadata.getEntityID()));
    
    System.out.println("Encrypted data:\n" + OpenSAMLTestBase.toString(encryptedData));

    // OK, let's decrypt ...
    //
    Decrypter decrypter = new Decrypter(DecryptionUtils.createDecryptionParameters(ecCredential, rsaCredential));
    decrypter.setRootInNewDocument(true);

    Issuer decryptedObject = (Issuer) decrypter.decryptData(encryptedData);
    System.out.println(OpenSAMLTestBase.toString(decryptedObject));

    Assert.assertEquals(String.format("Expected '%s' as decrypted message", VALUE), VALUE, decryptedObject.getValue());
  }

}
