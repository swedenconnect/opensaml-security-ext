/*
 * Copyright 2016-2025 Sweden Connect
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.criterion.RoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLMetadataEncryptionParametersResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.EncryptionParametersResolver;
import org.opensaml.xmlsec.agreement.KeyAgreementCredential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.derivation.impl.ConcatKDF;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.springframework.core.io.ClassPathResource;

import net.shibboleth.shared.resolver.CriteriaSet;
import se.swedenconnect.opensaml.OpenSAMLTestBase;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.support.DecryptionUtils;

/**
 * Examples for different ways of encrypting and decrypting using key agreement. This functionality was previously part
 * of the opensaml-security-ext library, but since it was introduced in OpenSAML 4.1.0, it was removed and this class
 * illustrates how to use OpenSAML for encrypting and decrypting using key agreement.
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
   * @throws Exception for errors
   */
  @BeforeEach
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
   * Illustrates how we use the {@link EncryptionParametersResolver} to resolve encryption parameters before encrypting.
   *
   * @throws Exception for test errors
   */
  @Test
  public void resolvedEncryptionParameters() throws Exception {

    // We use the default encryption configuration.
    //
    BasicEncryptionConfiguration config = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

    // Install our key transport encryption credentials.
    //
    config.setKeyTransportEncryptionCredentials(Arrays.asList(this.ecPeerCredential, this.rsaPeerCredential));

    // Make our encryption configuration into a criteria for the resolver.
    //
    final CriteriaSet criteriaSet = new CriteriaSet(new EncryptionConfigurationCriterion(config));

    // Instantiate our extension of the EncryptionParametersResolver to get the parameters needed
    // for encryption.
    //
    final EncryptionParametersResolver resolver = new BasicEncryptionParametersResolver();
    EncryptionParameters params = resolver.resolveSingle(criteriaSet);

    // As you see above we have both an EC credential and a RSA credential. The EncryptionParametersResolver
    // will use the first credential that matches the supplied EncryptionConfigurationCriterion.
    // In this case it should be the EC credential. Let's assert that ...
    //
    Assertions.assertTrue(KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential()),
        "Expected KeyAgreementCredential for KeyTransportEncryptionCredential");

    // Encrypt
    // For this example we use the base Encrypter ...
    //
    final org.opensaml.xmlsec.encryption.support.Encrypter encrypter =
        new org.opensaml.xmlsec.encryption.support.Encrypter();

    final EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
        new DataEncryptionParameters(params), new KeyEncryptionParameters(params, "recipient"));

    System.out.println("Encrypted data:\n" + OpenSAMLTestBase.toString(encryptedData));

    // OK, let's decrypt ...
    //
    final Decrypter decrypter =
        new Decrypter(DecryptionUtils.createDecryptionParameters(this.ecCredential, this.rsaCredential));
    decrypter.setRootInNewDocument(true);

    final Issuer decryptedObject = (Issuer) decrypter.decryptData(encryptedData);
    System.out.println(OpenSAMLTestBase.toString(decryptedObject));

    Assertions.assertEquals(VALUE, decryptedObject.getValue(),
        String.format("Expected '%s' as decrypted message", VALUE));

    // OK, let's put the RSA credential first and verify that RSA OAEP is used instead.
    //
    config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    config.setKeyTransportEncryptionCredentials(Arrays.asList(this.rsaPeerCredential, this.ecPeerCredential));

    params = resolver.resolveSingle(new CriteriaSet(new EncryptionConfigurationCriterion(config)));

    Assertions.assertEquals("RSA", params.getKeyTransportEncryptionCredential().getPublicKey().getAlgorithm());
  }

  /**
   * Illustrates the "real" case where we resolve encryption parameters by parsing the peer metadata entry.
   *
   * @throws Exception for test errors
   */
  @Test
  public void resolvedEncryptionParametersFromMetadata() throws Exception {

    // The peer metadata.
    final EntityDescriptor metadata = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
        XMLObjectProviderRegistrySupport.getParserPool(),
        new ClassPathResource("metadata-ec-with-enc-method.xml").getInputStream());

    // Set up a MetadataCredentialResolver (a resolver that reads from SAML metadata)
    //
    final MetadataCredentialResolver credentialResolver = new MetadataCredentialResolver();
    credentialResolver.setKeyInfoCredentialResolver(
        DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
    credentialResolver.initialize();

    // Set up the criteria ...
    //

    // We need default algorithms (in case no are given in EncryptionMethod in metadata).
    final EncryptionConfigurationCriterion encConfCriterion = new EncryptionConfigurationCriterion(
        DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration());

    // RoleDescriptorCriterion gives us the metadata. In a real case a RoleDescriptorResolver would be used.
    final RoleDescriptorCriterion rdCriterion = new RoleDescriptorCriterion(metadata.getRoleDescriptors().get(0));

    final CriteriaSet criteriaSet = new CriteriaSet(encConfCriterion, rdCriterion);

    // Resolve encryption parameters and encrypt.
    //
    final SAMLMetadataEncryptionParametersResolver resolver =
        new SAMLMetadataEncryptionParametersResolver(credentialResolver);
    final EncryptionParameters params = resolver.resolveSingle(criteriaSet);

    // The metadata specifies which algorithms that should be used.
    // Let's assert that the peer's suggestions are used.
    //
    Assertions.assertTrue(
        KeyAgreementCredential.class.isInstance(params.getKeyTransportEncryptionCredential()),
        String.format("Expected KeyAgreementCredential for KeyTransportEncryptionCredential, but was '%s'",
            params.getKeyTransportEncryptionCredential() != null
                ? params.getKeyTransportEncryptionCredential().getClass().getSimpleName()
                : "null"));

    Assertions.assertEquals(
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, params.getDataEncryptionAlgorithm(),
        String.format("Expected '%s' for data encryption algorithm", EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256));
    Assertions.assertEquals(
        EncryptionConstants.ALGO_ID_KEYWRAP_AES256, params.getKeyTransportEncryptionAlgorithm(),
        String.format("Expected '%s' for key transport encryption algorithm",
            EncryptionConstants.ALGO_ID_KEYWRAP_AES256));

    // The special KeyAgreementCredential holds the rest of the information ...
    final KeyAgreementCredential kaCred =
        KeyAgreementCredential.class.cast(params.getKeyTransportEncryptionCredential());
    Assertions.assertEquals(
        EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES, kaCred.getAlgorithm(),
        String.format("Expected KeyAgreement algorithm '%s'", EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES));
    Assertions.assertTrue(kaCred.getParameters().contains(ConcatKDF.class),
        String.format("Expected KeyDerivation algorithm '{}'", EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF));

    final org.opensaml.xmlsec.encryption.support.Encrypter encrypter =
        new org.opensaml.xmlsec.encryption.support.Encrypter();

    final EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
        new DataEncryptionParameters(params), new KeyEncryptionParameters(params, metadata.getEntityID()));

    System.out.println("Encrypted data:\n" + OpenSAMLTestBase.toString(encryptedData));

    // OK, let's decrypt ...
    //
    final Decrypter decrypter =
        new Decrypter(DecryptionUtils.createDecryptionParameters(this.ecCredential, this.rsaCredential));
    decrypter.setRootInNewDocument(true);

    final Issuer decryptedObject = (Issuer) decrypter.decryptData(encryptedData);

    Assertions.assertEquals(VALUE, decryptedObject.getValue(),
        String.format("Expected '%s' as decrypted message", VALUE));
  }

}
