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
package se.swedenconnect.opensaml.xmlsec.keyinfo.provider;

import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.security.auth.x500.X500Principal;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.criteria.impl.EvaluableX509DigestCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableX509SubjectKeyIdentifierCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableX509SubjectNameCredentialCriterion;
import org.opensaml.security.x509.X509DigestCriterion;
import org.opensaml.security.x509.X509IssuerSerialCriterion;
import org.opensaml.security.x509.X509SubjectKeyIdentifierCriterion;
import org.opensaml.security.x509.X509SubjectNameCriterion;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import org.opensaml.xmlsec.encryption.RecipientKeyInfo;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoResolutionContext;
import org.opensaml.xmlsec.keyinfo.impl.provider.AbstractKeyInfoProvider;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.X509Digest;
import org.opensaml.xmlsec.signature.X509IssuerSerial;
import org.opensaml.xmlsec.signature.X509SKI;
import org.opensaml.xmlsec.signature.X509SubjectName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;

/**
 * A {@link KeyInfoProvider} that returns the key agreement key that is found in a {@code xenc:AgreementMethod} element
 * under a {@code ds:KeyInfo} element when the agreement method is
 * {@value EcEncryptionConstants#ALGO_ID_KEYAGREEMENT_ECDH_ES}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECDHAgreementMethodKeyInfoProvider extends AbstractKeyInfoProvider {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ECDHAgreementMethodKeyInfoProvider.class);

  /** List of credentials held by this resolver. */
  private List<Credential> ecCredentials;

  private CollectionKeyInfoCredentialResolver ecCredentialsResolver;

  public ECDHAgreementMethodKeyInfoProvider(@Nonnull @ParameterName(name = "credentials") final List<Credential> credentials) {
    Constraint.isNotNull(credentials, "Input credentials list cannot be null");

    // Only save those credentials that can be used ...
    List<Credential> filteredCredentials = credentials.stream().filter(c -> ECPrivateKey.class.isInstance(c.getPrivateKey())).collect(
      Collectors.toList());

    this.ecCredentialsResolver = new CollectionKeyInfoCredentialResolver(filteredCredentials);
    this.ecCredentialsResolver.setSatisfyAllPredicates(false);

    // Only save those credentials that can be used ...
    //
    this.ecCredentials = credentials.stream().filter(c -> ECPrivateKey.class.isInstance(c.getPrivateKey())).collect(Collectors.toList());
  }

  /** {@inheritDoc} */
  @Override
  public boolean handles(XMLObject keyInfoChild) {
    if (this.ecCredentials.isEmpty()) {
      log.debug("No EC private key credentials available for ECDH key agreement");
      return false;
    }
    if (AgreementMethod.class.isInstance(keyInfoChild)) {
      AgreementMethod am = (AgreementMethod) keyInfoChild;
      if (EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES.equals(am.getAlgorithm())) {
        // Currently we only support the ConcatKDF key derivation method.
        KeyDerivationMethod kdm = getKeyDerivationMethod(am);
        if (kdm == null) {
          log.info("No KeyDerivationMethod available for {}", EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
          return false;
        }
        if (EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT.equals(kdm.getAlgorithm())) {
          return true;
        }
        else {
          log.debug("KeyDerivationMethod {} is not supported for {}", kdm.getAlgorithm(),
            EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
          return false;
        }
      }
      else {
        log.debug("{} does not handle {} agreement method", am.getAlgorithm());
        return false;
      }
    }
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public Collection<Credential> process(KeyInfoCredentialResolver resolver, XMLObject keyInfoChild, CriteriaSet criteriaSet,
      KeyInfoResolutionContext kiContext) throws SecurityException {

    // Start with sanity checks (in case handles() wasn't called).
    //
    if (!this.handles(keyInfoChild)) {
      return null;
    }

    try {
      final AgreementMethod agreementMethod = (AgreementMethod) keyInfoChild;

      // Build criterias that helps us to find a EC credential.
      //
      CriteriaSet ecCriteriaSet = this.buildCriteriaSet(agreementMethod);

      // Loop over all available EC credentials and try to resolve the ECDH key agreement key.
      //
      for (Credential ecCred : this.ecCredentialsResolver.resolve(ecCriteriaSet)) {
        
      }

      return null;
    }
    catch (ResolverException e) {
      log.error("Failed to resolve credential for ECDH key agreement", e);
      throw new SecurityException("Resolver error", e);
    }
  }

  /**
   * Based on the {@code xenc:RecipientKeyInfo} (if available) we build a criteria set that helps us find the EC private
   * key to use. We make some simplifications. For example, we only handle one X509Data element.
   * </p>
   * <p>
   * We could probably do something with {@code OriginatorKeyInfo} also, but for now we only handle
   * {@code RecipientKeyInfo}.
   * </p>
   * 
   * @param agreementMethod
   *          the agreement method element
   * @return a criteria set
   */
  private CriteriaSet buildCriteriaSet(AgreementMethod agreementMethod) {
    CriteriaSet criterias = new CriteriaSet();

    if (agreementMethod.getRecipientKeyInfo() == null || agreementMethod.getRecipientKeyInfo().getX509Datas().isEmpty()) {
      return criterias;
    }
    final X509Data x509data = agreementMethod.getRecipientKeyInfo().getX509Datas().get(0);

    try {
      // Certificates
      if (!x509data.getX509Certificates().isEmpty()) {
        criterias.add(new EvaluableX509CertificatesCredentialCriterion(x509data.getX509Certificates()));
      }

      // Issuer and serial number
      if (!x509data.getX509IssuerSerials().isEmpty()) {
        final X509IssuerSerial is = x509data.getX509IssuerSerials().get(0);
        if (is.getX509IssuerName() != null && is.getX509SerialNumber() != null) {
          criterias.add(new X509IssuerSerialCriterion(new X500Principal(is.getX509IssuerName().getValue()), is.getX509SerialNumber()
            .getValue()));
        }
      }

      // Subject key info
      if (!x509data.getX509SKIs().isEmpty()) {
        final X509SKI ski = x509data.getX509SKIs().get(0);
        criterias.add(new EvaluableX509SubjectKeyIdentifierCredentialCriterion(new X509SubjectKeyIdentifierCriterion(Base64.getDecoder()
          .decode(ski.getValue()))));
      }

      // Subject name
      if (!x509data.getX509SubjectNames().isEmpty()) {
        final X509SubjectName sn = x509data.getX509SubjectNames().get(0);
        criterias.add(new EvaluableX509SubjectNameCredentialCriterion(new X509SubjectNameCriterion(new X500Principal(sn.getValue()))));
      }

      // Digest
      if (!x509data.getX509Digests().isEmpty()) {
        final X509Digest digest = x509data.getX509Digests().get(0);
        criterias.add(new EvaluableX509DigestCredentialCriterion(new X509DigestCriterion(digest.getAlgorithm(), Base64.getDecoder().decode(
          digest.getValue()))));
      }
    }
    catch (Exception e) {
      log.error("Error during building of criteria set for ECDHAgreementMethodKeyInfoProvider - {}", e.getMessage(), e);
    }

    return criterias;
  }

  private Collection<Credential> filterCredentials(AgreementMethod agreementMethod) {

    // If we only have one credential we assume that it is the one to use.
    if (this.ecCredentials.size() == 1) {
      return this.ecCredentials;
    }
    // If the KeyInfo contains a RecipientKeyInfo we may use that ...
    RecipientKeyInfo rki = agreementMethod.getRecipientKeyInfo();
    if (rki == null) {
      // We have no hint, lets try them all ...
      return this.ecCredentials;
    }

    // rki.getKeyValues().get(0).getECKeyValue()
    // rki.getX509Datas().isEmpty()

    return null;
  }

  private static KeyDerivationMethod getKeyDerivationMethod(AgreementMethod agreementMethod) {
    List<XMLObject> methods = agreementMethod.getUnknownXMLObjects(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
    if (methods.isEmpty()) {
      return null;
    }
    return (KeyDerivationMethod) methods.get(0);
  }

}
