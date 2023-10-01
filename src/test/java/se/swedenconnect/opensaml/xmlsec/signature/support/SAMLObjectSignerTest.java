/*
 * Copyright 2019-2023 Sweden Connect
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
package se.swedenconnect.opensaml.xmlsec.signature.support;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.core.io.ClassPathResource;

import net.shibboleth.shared.xml.SerializeSupport;
import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Test cases for the utility methods of {@code SAMLObjectSigner}.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class SAMLObjectSignerTest extends OpenSAMLTestBase {

  @Test
  public void testRSAPSS() throws Exception {
    final X509Credential rsaCredential = loadKeyStoreCredential(
        new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    final EntityDescriptor metadata = this.createMetadata(
        Arrays.asList(new DigestAlgorithm(false, SignatureConstants.ALGO_ID_DIGEST_SHA384)),
        Arrays.asList(new SignatureAlgorithm(true, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)));

    final AuthnRequest authnRequest = getMockAuthnRequest();

    SAMLObjectSigner.sign(authnRequest, rsaCredential,
        SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), metadata);

    Assertions.assertEquals(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1,
        authnRequest.getSignature().getSignatureAlgorithm());
    Assertions.assertTrue(toString(authnRequest).contains(
        "<ds:DigestMethod Algorithm=\"" + SignatureConstants.ALGO_ID_DIGEST_SHA384 + "\""));
  }

  @Test
  public void testNoPreferences() throws Exception {
    final X509Credential rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
        new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    final AuthnRequest authnRequest = getMockAuthnRequest();

    SAMLObjectSigner.sign(authnRequest, rsaCredential,
        SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), null);

    // Verify that the default algo is used if the recipient hasn't specified anything
    Assertions.assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
        authnRequest.getSignature().getSignatureAlgorithm());
  }

  @Test
  public void testECDSA() throws Exception {

    final X509Credential ecCredential = OpenSAMLTestBase.loadKeyStoreCredential(
        new ClassPathResource("eckey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    final X509Credential rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
        new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    final EntityDescriptor metadata = this.createMetadata(
        null, Arrays.asList(
            new SignatureAlgorithm(true, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512),
            new SignatureAlgorithm(true, SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512)));

    final AuthnRequest authnRequest = getMockAuthnRequest();

    SAMLObjectSigner.sign(authnRequest, ecCredential,
        SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), metadata);

    Assertions.assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512,
        authnRequest.getSignature().getSignatureAlgorithm());

    SAMLObjectSigner.sign(authnRequest, rsaCredential,
        SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), metadata);

    Assertions.assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
        authnRequest.getSignature().getSignatureAlgorithm());
  }

  @Test
  public void testBadAlgorithms() throws Exception {
    final X509Credential rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
        new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    final EntityDescriptor metadata = this.createMetadata(
        Arrays.asList(
            new DigestAlgorithm(false, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512),
            new DigestAlgorithm(false, SignatureConstants.ALGO_ID_DIGEST_SHA384)),
        Arrays.asList(
            new SignatureAlgorithm(true, SignatureConstants.ALGO_ID_DIGEST_SHA384),
            new SignatureAlgorithm(true, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)));

    final AuthnRequest authnRequest = getMockAuthnRequest();

    SAMLObjectSigner.sign(authnRequest, rsaCredential,
        SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), metadata);

    Assertions.assertEquals(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1,
        authnRequest.getSignature().getSignatureAlgorithm());
    Assertions.assertTrue(toString(authnRequest).contains(
        "<ds:DigestMethod Algorithm=\"" + SignatureConstants.ALGO_ID_DIGEST_SHA384 + "\""));
  }

  /**
   * Creates an {@link AuthnRequest} that we sign.
   *
   * @return an authentication request object
   */
  private static AuthnRequest getMockAuthnRequest() {
    final AuthnRequest authnRequest = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    authnRequest.setID("_BmPDpaRGHfHCsqRdeoTHVnsPhNvr3ulQdUoXGgnV");
    authnRequest.setIssueInstant(Instant.now());
    final Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setFormat(Issuer.ENTITY);
    issuer.setValue("http://www.fake.issuer.com");
    authnRequest.setIssuer(issuer);
    return authnRequest;
  }

  private EntityDescriptor createMetadata(final List<DigestAlgorithm> digestAlgos,
      final List<SignatureAlgorithm> signatureAlgs) throws Exception {
    final EntityDescriptor ed = EntityDescriptor.class.cast(
        XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME));
    ed.setEntityID("http://www.dummy.com/idp");
    ed.setID("_id123456");

    final IDPSSODescriptor d = IDPSSODescriptor.class.cast(
        XMLObjectSupport.buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
    d.addSupportedProtocol(SAMLConstants.SAML20P_NS);
    ed.getRoleDescriptors().add(d);

    if (digestAlgos != null) {
      for (final DigestAlgorithm da : digestAlgos) {
        Extensions extensions = da.isAddToRole() ? d.getExtensions() : ed.getExtensions();
        if (extensions == null) {
          extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
          if (da.isAddToRole()) {
            d.setExtensions(extensions);
          }
          else {
            ed.setExtensions(extensions);
          }
        }
        extensions.getUnknownXMLObjects().add(da.toDigestMethod());
      }
    }
    if (signatureAlgs != null) {
      for (final SignatureAlgorithm sa : signatureAlgs) {
        Extensions extensions = sa.isAddToRole() ? d.getExtensions() : ed.getExtensions();
        if (extensions == null) {
          extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
          if (sa.isAddToRole()) {
            d.setExtensions(extensions);
          }
          else {
            ed.setExtensions(extensions);
          }
        }
        extensions.getUnknownXMLObjects().add(sa.toSignatureMethod());
      }
    }

    return ed;
  }

  private abstract static class MetadataAlgoritm {
    private final boolean addToRole;
    protected String algorithm;

    public MetadataAlgoritm(final boolean addToRole, final String algorithm) {
      this.addToRole = addToRole;
      this.algorithm = algorithm;
    }

    public boolean isAddToRole() {
      return this.addToRole;
    }

  }

  private static class DigestAlgorithm extends MetadataAlgoritm {

    public DigestAlgorithm(final boolean addToRole, final String algorithm) {
      super(addToRole, algorithm);
    }

    public DigestMethod toDigestMethod() {
      final DigestMethod dm = DigestMethod.class.cast(
          XMLObjectSupport.buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME));
      dm.setAlgorithm(this.algorithm);
      return dm;
    }

  }

  private static class SignatureAlgorithm extends MetadataAlgoritm {

    public SignatureAlgorithm(final boolean addToRole, final String algorithm) {
      super(addToRole, algorithm);
    }

    public SigningMethod toSignatureMethod() {
      final SigningMethod sm = SigningMethod.class.cast(
          XMLObjectSupport.buildXMLObject(SigningMethod.DEFAULT_ELEMENT_NAME));
      sm.setAlgorithm(this.algorithm);
      return sm;
    }

  }

  private static <T extends SAMLObject> String toString(final T object) throws MarshallingException {
    return SerializeSupport.prettyPrintXML(XMLObjectSupport.marshall(object));
  }

}
