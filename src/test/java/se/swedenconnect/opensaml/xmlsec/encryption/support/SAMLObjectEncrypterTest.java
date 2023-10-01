/*
 * Copyright 2016-2023 Sweden Connect
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

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Test cases for {@link SAMLObjectEncrypter}.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class SAMLObjectEncrypterTest extends OpenSAMLTestBase {

  private static final String ENTITY_ID = "http://www.example.com/idp";
  private static final String CONTENTS = "This is the encrypted message";

  //
  // Test with default settings and a metadata entry that contains use="encryption".
  //
  @Test
  public void testDefault() throws Exception {

    final XSString msg = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
    msg.setValue(CONTENTS);

    // Setup metadata
    //
    final EntityDescriptor ed = this.createMetadata(
        new MetadataCertificate("credentials/litsec_auth.crt", UsageType.ENCRYPTION),
        new MetadataCertificate("credentials/litsec_sign.crt", UsageType.SIGNING));

    final MetadataResolver resolver = this.createMetadataResolver(ed);

    final SAMLObjectEncrypter encrypter = new SAMLObjectEncrypter(resolver);
    final EncryptedData encryptedData = encrypter.encrypt(msg, new SAMLObjectEncrypter.Peer(ENTITY_ID));

//    Element e = ObjectUtils.marshall(encryptedData);
//    System.out.println(SerializeSupport.prettyPrintXML(e));

    final String decryptedMsg =
        this.decrypt(encryptedData, new ClassPathResource("credentials/litsec_auth.jks"), "secret",
            "litsec_ab");

    Assertions.assertEquals(CONTENTS, decryptedMsg);
  }

  //
  // The same as above, but we don't have a metadata resolver. Instead we supply the peer metadata
  // in the call to encrypt.
  //
  @Test
  public void testDefaultNoProvider() throws Exception {

    final XSString msg = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
    msg.setValue(CONTENTS);

    // Setup metadata
    //
    final EntityDescriptor ed = this.createMetadata(
        new MetadataCertificate("credentials/litsec_auth.crt", UsageType.ENCRYPTION),
        new MetadataCertificate("credentials/litsec_sign.crt", UsageType.SIGNING));

    final SAMLObjectEncrypter encrypter = new SAMLObjectEncrypter();
    final EncryptedData encryptedData = encrypter.encrypt(msg, new SAMLObjectEncrypter.Peer(ed));

//    Element e = ObjectUtils.marshall(encryptedData);
//    System.out.println(SerializeSupport.prettyPrintXML(e));

    final String decryptedMsg =
        this.decrypt(encryptedData, new ClassPathResource("credentials/litsec_auth.jks"), "secret",
            "litsec_ab");

    Assertions.assertEquals(CONTENTS, decryptedMsg);
  }

  //
  // Tests that we find a encryption credential even if the metadata doesn't state encryption use.
  //
  @Test
  public void testUnspecifiedUse() throws Exception {

    final XSString msg = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
    msg.setValue(CONTENTS);

    // Setup metadata
    //
    final EntityDescriptor ed = this.createMetadata(new MetadataCertificate("credentials/litsec_auth.crt"));

    final MetadataResolver resolver = this.createMetadataResolver(ed);

    final SAMLObjectEncrypter encrypter = new SAMLObjectEncrypter(resolver);
    final EncryptedData encryptedData = encrypter.encrypt(msg, new SAMLObjectEncrypter.Peer(ENTITY_ID));

//    Element e = ObjectUtils.marshall(encryptedData);
//    System.out.println(SerializeSupport.prettyPrintXML(e));

    final String decryptedMsg =
        this.decrypt(encryptedData, new ClassPathResource("credentials/litsec_auth.jks"), "secret",
            "litsec_ab");

    Assertions.assertEquals(CONTENTS, decryptedMsg);
  }

  //
  // Tests that if we don't find any encryption credentials we fail.
  //
  @Test
  public void testNoEncryptionCredentials() throws Exception {

    final XSString msg = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
    msg.setValue(CONTENTS);

    final EntityDescriptor ed = this.createMetadata(
        new MetadataCertificate("credentials/litsec_sign.crt", UsageType.SIGNING));

    final MetadataResolver resolver = this.createMetadataResolver(ed);

    final SAMLObjectEncrypter encrypter = new SAMLObjectEncrypter(resolver);
    Assertions.assertThrows(EncryptionException.class, () -> {
      encrypter.encrypt(msg, new SAMLObjectEncrypter.Peer(ENTITY_ID));
    });
  }

  //
  // Test that we look at what the peer specifies about algorithms in its metadata.
  //
  @Test
  public void testPeerCapabilities() throws Exception {

    final XSString msg = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
    msg.setValue(CONTENTS);

    // Setup metadata
    //
    final EntityDescriptor ed = this.createMetadata(
        new MetadataCertificate("credentials/litsec_auth.crt", UsageType.ENCRYPTION,
            Arrays.asList(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
                EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15)),
        new MetadataCertificate("credentials/litsec_sign.crt", UsageType.SIGNING));

    final MetadataResolver resolver = this.createMetadataResolver(ed);

    // RSA 1.5 is black-listed in the default OpenSAML config, so we make our own config.
    final BasicEncryptionConfiguration customConfig =
        DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    customConfig.setExcludedAlgorithms(Collections.emptyList());

    final SAMLObjectEncrypter encrypter = new SAMLObjectEncrypter(resolver);
    final EncryptedData encryptedData = encrypter.encrypt(msg, new SAMLObjectEncrypter.Peer(ENTITY_ID), customConfig);

    Assertions.assertEquals(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
        encryptedData.getEncryptionMethod().getAlgorithm());
    Assertions.assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15,
        encryptedData.getKeyInfo().getEncryptedKeys().get(0).getEncryptionMethod().getAlgorithm());

//    Element e = ObjectUtils.marshall(encryptedData);
//    System.out.println(SerializeSupport.prettyPrintXML(e));

    final String decryptedMsg =
        this.decrypt(encryptedData, new ClassPathResource("credentials/litsec_auth.jks"), "secret",
            "litsec_ab");

    Assertions.assertEquals(CONTENTS, decryptedMsg);
  }

  //
  // Test with default settings and several matching keys
  //
  @Test
  public void testSeveralKeys() throws Exception {

    final XSString msg = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
    msg.setValue(CONTENTS);

    // Setup metadata
    //
    final EntityDescriptor ed = this.createMetadata(
        new MetadataCertificate("credentials/litsec_auth.crt", UsageType.ENCRYPTION),
        new MetadataCertificate("credentials/other.crt", UsageType.ENCRYPTION));

    final MetadataResolver resolver = this.createMetadataResolver(ed);

    final SAMLObjectEncrypter encrypter = new SAMLObjectEncrypter(resolver);
    final EncryptedData encryptedData = encrypter.encrypt(msg, new SAMLObjectEncrypter.Peer(ENTITY_ID));

//    Element e = XMLObjectSupport.marshall(encryptedData);
//    System.out.println(SerializeSupport.prettyPrintXML(e));

    // One should work
    String decryptedMsg = null;
    try {
      decryptedMsg = this.decrypt(encryptedData, new ClassPathResource("credentials/litsec_auth.jks"), "secret",
          "litsec_ab");
    }
    catch (final DecryptionException ex) {
      decryptedMsg = this.decrypt(encryptedData, new ClassPathResource("credentials/other.jks"), "secret",
          "Test");
    }

    Assertions.assertEquals(CONTENTS, decryptedMsg);
  }

  private String decrypt(final EncryptedData encrypted, final Resource jks, final String password, final String alias)
      throws Exception {
    final KeyStore keyStore = loadKeyStore(jks.getInputStream(), password, "JKS");
    final Credential cred = new KeyStoreX509CredentialAdapter(keyStore, alias, password.toCharArray());

    final SAMLObjectDecrypter decrypter = new SAMLObjectDecrypter(cred);
    final XSString str = decrypter.decrypt(encrypted, XSString.class);
    return str.getValue();
  }

  private EntityDescriptor createMetadata(final MetadataCertificate... descriptors) throws Exception {
    final EntityDescriptor ed = EntityDescriptor.class.cast(
        XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME));
    ed.setEntityID(ENTITY_ID);
    ed.setID("_id123456");

    final IDPSSODescriptor d = IDPSSODescriptor.class.cast(
        XMLObjectSupport.buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
    d.addSupportedProtocol(SAMLConstants.SAML20P_NS);
    ed.getRoleDescriptors().add(d);

    if (descriptors != null) {
      for (final MetadataCertificate mc : descriptors) {
        d.getKeyDescriptors().add(mc.toKeyDescriptor());
      }
    }
    return ed;
  }

  private static class MetadataCertificate {
    private final X509Certificate certificate;
    private final UsageType usageType;
    private final List<String> encryptionMethods;

    public MetadataCertificate(final String certificate) throws Exception {
      this(certificate, null, null);
    }

    public MetadataCertificate(final String certificate, final UsageType usageType) throws Exception {
      this(certificate, usageType, null);
    }

    public MetadataCertificate(final String certificate, final UsageType usageType,
        final List<String> encryptionMethods) throws Exception {
      this.usageType = usageType;
      this.certificate = OpenSAMLTestBase.decodeCertificate(new ClassPathResource(certificate).getInputStream());
      this.encryptionMethods = encryptionMethods;
    }

    public KeyDescriptor toKeyDescriptor() throws Exception {
      final KeyDescriptor kd = KeyDescriptor.class.cast(
          XMLObjectSupport.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME));
      if (UsageType.UNSPECIFIED.equals(this.usageType)) {
        kd.setUse(null);
      }
      else {
        kd.setUse(this.usageType);
      }
      final String encoding = Base64.getEncoder().encodeToString(this.certificate.getEncoded());
      kd.setKeyInfo((KeyInfo) XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME));
      final X509Data x509Data = (X509Data) XMLObjectSupport.buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
      final org.opensaml.xmlsec.signature.X509Certificate cert =
          (org.opensaml.xmlsec.signature.X509Certificate) XMLObjectSupport
              .buildXMLObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
      cert.setValue(encoding);
      x509Data.getX509Certificates().add(cert);
      kd.getKeyInfo().getX509Datas().add(x509Data);

      if (this.encryptionMethods != null) {
        for (final String algo : this.encryptionMethods) {
          final EncryptionMethod method = EncryptionMethod.class.cast(
              XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME));
          method.setAlgorithm(algo);
          kd.getEncryptionMethods().add(method);
        }
      }

      return kd;
    }
  }

  private MetadataResolver createMetadataResolver(final EntityDescriptor descriptor) throws Exception {
    final DOMMetadataResolver resolver = new DOMMetadataResolver(XMLObjectSupport.marshall(descriptor));
    resolver.setRequireValidMetadata(false);
    resolver.setId("dummy");
    resolver.initialize();
    return resolver;
  }

}
