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

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.AbstractCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.criterion.SignatureValidationConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.impl.BasicSignatureSigningParametersResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Attr;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Verifies that the algorithm descriptors for RSA-PSS that this library registers works in action.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@RunWith(Parameterized.class)
public class RSAPSSSignatureTest extends OpenSAMLTestBase {

  /** The signature algorithm to use. */
  private String algorithm;

  /**
   * Constructor.
   * 
   * @param algorithm
   *          the signature algorithm to use for the test
   */
  public RSAPSSSignatureTest(String algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Tests sign and verify.
   * 
   * @throws Exception
   *           for test errors
   */
  @Test
  public void signAndVerify() throws Exception {

    X509Credential rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
      new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    AuthnRequest authnRequest = getMockAuthnRequest();

    sign(authnRequest, rsaCredential, this.algorithm);

    Assert.assertNotNull(authnRequest.getSignature());
    Assert.assertEquals(this.algorithm, authnRequest.getSignature().getSignatureAlgorithm());

    validate(authnRequest, rsaCredential.getEntityCertificate());
  }

  /**
   * Test data.
   * 
   * @return the algorithms to test
   */
  @Parameterized.Parameters
  public static Collection<?> algorithms() {
    return Arrays.asList(
      XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
      XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1,
      XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1);
  }

  /**
   * Creates an {@link AuthnRequest} that we sign.
   * 
   * @return an authentication request object
   */
  private static AuthnRequest getMockAuthnRequest() {
    AuthnRequest authnRequest = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    authnRequest.setID("_BmPDpaRGHfHCsqRdeoTHVnsPhNvr3ulQdUoXGgnV");
    authnRequest.setIssueInstant(new DateTime());
    Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setFormat(Issuer.ENTITY);
    issuer.setValue("http://www.fake.issuer.com");
    authnRequest.setIssuer(issuer);
    return authnRequest;
  }

  /**
   * Signs the supplied SAML object using the credentials.
   * 
   * @param object
   *          object to sign
   * @param signingCredentials
   *          signature credentials
   * @param signatureAlgorithm
   *          the signature algorithm to use
   * @param <T>
   *          the object type
   * @throws SignatureException
   *           for signature creation errors
   */
  public static <T extends SignableSAMLObject> void sign(T object, Credential signingCredentials, String signatureAlgorithm)
      throws SignatureException {
    try {
      object.setSignature(null);

      BasicSignatureSigningConfiguration signatureCreds = new BasicSignatureSigningConfiguration();
      signatureCreds.setSigningCredentials(Collections.singletonList(signingCredentials));
      signatureCreds.setSignatureAlgorithms(Arrays.asList(signatureAlgorithm));
            
      BasicSignatureSigningParametersResolver signatureParametersResolver = new BasicSignatureSigningParametersResolver();
      CriteriaSet criteriaSet = new CriteriaSet(new SignatureSigningConfigurationCriterion(
        signatureCreds,
        SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration()));

      SignatureSigningParameters parameters = signatureParametersResolver.resolveSingle(criteriaSet);
      SignatureSupport.signObject(object, parameters);
    }
    catch (ResolverException | org.opensaml.security.SecurityException | MarshallingException e) {
      throw new SignatureException(e);
    }
  }

  public static <T extends SignableSAMLObject> void validate(T object, X509Certificate cert) throws SignatureException, SecurityException {

    // Temporary code until we figure out how to make the OpenSAML unmarshaller to
    // mark the ID attribute as an ID.
    //
    Attr idAttr = object.getDOM().getAttributeNode("ID");
    if (idAttr != null) {
      idAttr.getOwnerElement().setIdAttributeNode(idAttr, true);
    }

    SignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(cert),
      DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());

    Signature signature = object.getSignature();
    if (signature == null) {
      throw new SignatureException("Object is not signed");
    }
    CriteriaSet criteriaSet = new CriteriaSet();
    criteriaSet.add(new SignatureValidationConfigurationCriterion(
      SecurityConfigurationSupport.getGlobalSignatureValidationConfiguration()));

    if (!trustEngine.validate(signature, criteriaSet)) {
      throw new SignatureException("Signature validation failed");
    }
  }

  public static class StaticCredentialResolver extends AbstractCredentialResolver {

    private X509Credential cred;

    public StaticCredentialResolver(X509Certificate cert) {
      this.cred = new BasicX509Credential(cert);
    }

    @Override
    public Iterable<Credential> resolve(CriteriaSet criteriaSet) throws ResolverException {
      return Arrays.asList(this.cred);
    }

  }

}
