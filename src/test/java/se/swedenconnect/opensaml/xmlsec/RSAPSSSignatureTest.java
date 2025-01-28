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
package se.swedenconnect.opensaml.xmlsec;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.stream.Stream;

import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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

import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Verifies that the algorithm descriptors for RSA-PSS that this library registers works in action.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class RSAPSSSignatureTest extends OpenSAMLTestBase {

  @BeforeAll
  public static void init() {
    // Test our implementation (even though we are not using HSM).
    System.setProperty("se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.testmode",
        "true");
  }

  @AfterAll
  public static void close() {
    System.clearProperty("se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.testmode");
  }

  /**
   * Tests sign and verify.
   *
   * @throws Exception for test errors
   */
  @ParameterizedTest
  @MethodSource("algorithms")
  public void signAndVerify(final String algorithm) throws Exception {

    final X509Credential rsaCredential = OpenSAMLTestBase.loadKeyStoreCredential(
        new ClassPathResource("rsakey.jks").getInputStream(), "Test1234", "key1", "Test1234");

    final AuthnRequest authnRequest = getMockAuthnRequest();

    sign(authnRequest, rsaCredential, algorithm);

    Assertions.assertNotNull(authnRequest.getSignature());
    Assertions.assertEquals(algorithm, authnRequest.getSignature().getSignatureAlgorithm());

    validate(authnRequest, rsaCredential.getEntityCertificate());
  }

  private static Stream<Arguments> algorithms() {
    return Stream.of(
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1),
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1),
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1),
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1),
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1),
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1),
        Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1));
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

  /**
   * Signs the supplied SAML object using the credentials.
   *
   * @param object object to sign
   * @param signingCredentials signature credentials
   * @param signatureAlgorithm the signature algorithm to use
   * @param <T> the object type
   * @throws SignatureException for signature creation errors
   */
  public static <T extends SignableSAMLObject> void sign(final T object, final Credential signingCredentials,
      final String signatureAlgorithm)
      throws SignatureException {
    try {
      object.setSignature(null);

      final BasicSignatureSigningConfiguration signatureCreds = new BasicSignatureSigningConfiguration();
      signatureCreds.setSigningCredentials(Collections.singletonList(signingCredentials));
      signatureCreds.setSignatureAlgorithms(Arrays.asList(signatureAlgorithm));

      final BasicSignatureSigningParametersResolver signatureParametersResolver =
          new BasicSignatureSigningParametersResolver();
      final CriteriaSet criteriaSet = new CriteriaSet(new SignatureSigningConfigurationCriterion(
          signatureCreds,
          SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration()));

      final SignatureSigningParameters parameters = signatureParametersResolver.resolveSingle(criteriaSet);
      SignatureSupport.signObject(object, parameters);
    }
    catch (ResolverException | org.opensaml.security.SecurityException | MarshallingException e) {
      throw new SignatureException(e);
    }
  }

  public static <T extends SignableSAMLObject> void validate(final T object, final X509Certificate cert)
      throws SignatureException, SecurityException {

    // Temporary code until we figure out how to make the OpenSAML unmarshaller to
    // mark the ID attribute as an ID.
    //
    final Attr idAttr = object.getDOM().getAttributeNode("ID");
    if (idAttr != null) {
      idAttr.getOwnerElement().setIdAttributeNode(idAttr, true);
    }

    final SignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(new StaticCredentialResolver(cert),
        DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());

    final Signature signature = object.getSignature();
    if (signature == null) {
      throw new SignatureException("Object is not signed");
    }
    final CriteriaSet criteriaSet = new CriteriaSet();
    criteriaSet.add(new SignatureValidationConfigurationCriterion(
        SecurityConfigurationSupport.getGlobalSignatureValidationConfiguration()));

    if (!trustEngine.validate(signature, criteriaSet)) {
      throw new SignatureException("Signature validation failed");
    }
  }

  public static class StaticCredentialResolver extends AbstractCredentialResolver {

    private final X509Credential cred;

    public StaticCredentialResolver(final X509Certificate cert) {
      this.cred = new BasicX509Credential(cert);
    }

    @Override
    public Iterable<Credential> resolve(final CriteriaSet criteriaSet) throws ResolverException {
      return Arrays.asList(this.cred);
    }

  }

}
