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
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContext;
import org.opensaml.security.credential.criteria.impl.EvaluableX509DigestCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableX509SubjectKeyIdentifierCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableX509SubjectNameCredentialCriterion;
import org.opensaml.security.x509.X509DigestCriterion;
import org.opensaml.security.x509.X509IssuerSerialCriterion;
import org.opensaml.security.x509.X509SubjectKeyIdentifierCriterion;
import org.opensaml.security.x509.X509SubjectNameCriterion;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.EncryptionMethod;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoResolutionContext;
import org.opensaml.xmlsec.keyinfo.impl.provider.AbstractKeyInfoProvider;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.X509Digest;
import org.opensaml.xmlsec.signature.X509IssuerSerial;
import org.opensaml.xmlsec.signature.X509SKI;
import org.opensaml.xmlsec.signature.X509SubjectName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.collection.LazySet;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHSupport;
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
    List<Credential> filteredCredentials = credentials.stream()
      .filter(c -> ECPrivateKey.class.isInstance(c.getPrivateKey()))
      .collect(
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

    final AgreementMethod agreementMethod = (AgreementMethod) keyInfoChild;

    // OpenSAML doesn't give us the encryption method, so we implement a work-around
    // that gives us this info.
    //
    EncryptionMethodCriterion encryptionMethod = this.getEncryptionMethod(agreementMethod);
    if (encryptionMethod == null) {
      log.error("Could not locate EncryptionMethod - ECDHAgreementMethodKeyInfoProvider cannot derive key agreement key");
      throw new SecurityException("Could not locate EncryptionMethod");
    }

    try {
      // Build criterias that helps us to find a EC credential.
      //
      CriteriaSet ecCriteriaSet = this.buildCriteriaSet(agreementMethod);

      // Loop over all available EC credentials and try to resolve the ECDH key agreement key.
      //
      for (Credential ecCred : this.ecCredentialsResolver.resolve(ecCriteriaSet)) {
        try {
          SecretKey keyAgreementKey = ECDHSupport.getKeyAgreementKey(ecCred.getPrivateKey(),
            encryptionMethod.getEncryptionMethod().getAlgorithm(), agreementMethod);

          log.debug("Successfully derived key agreement key using key wrapping method '{}'",
            encryptionMethod.getEncryptionMethod().getAlgorithm());

          BasicCredential kakCred = new BasicCredential(keyAgreementKey);
          CredentialContext credContext = this.buildCredentialContext(kiContext);
          if (credContext != null) {
            kakCred.getCredentialContextSet().add(credContext);
          }

          LazySet<Credential> credentialSet = new LazySet<>();
          credentialSet.add(kakCred);
          return credentialSet;
        }
        catch (SecurityException e) {
          log.error("Failed to get key agreement key - " + e.getMessage(), e);
        }
      }

      log.info("Could not derive a key agreement key - no matching credentials found");
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
        criterias.add(new EvaluableX509DigestCredentialCriterion(new X509DigestCriterion(digest.getAlgorithm(), Base64.getDecoder()
          .decode(
            digest.getValue()))));
      }
    }
    catch (Exception e) {
      log.error("Error during building of criteria set for ECDHAgreementMethodKeyInfoProvider - {}", e.getMessage(), e);
    }

    return criterias;
  }

  /**
   * Given the {@link AgreementMethod} the method follows the parent-pointers and locates the encryption method that we
   * need.
   * 
   * @param agreementMethod
   *          the key info child (agreement method)
   * @return the encryption method element, or {@code null}
   */
  private EncryptionMethodCriterion getEncryptionMethod(AgreementMethod agreementMethod) {
    if (KeyInfo.class.isInstance(agreementMethod.getParent())) {
      if (EncryptedKey.class.isInstance(agreementMethod.getParent().getParent())) {
        EncryptionMethod method = ((EncryptedKey) agreementMethod.getParent().getParent()).getEncryptionMethod();
        if (method != null) {
          return new EncryptionMethodCriterion(method);
        }
      }
    }
    return null;
  }

  /**
   * Returns the key derivation method.
   * 
   * @param agreementMethod
   *          the agreement method element.
   * @return the key derivation method
   */
  private static KeyDerivationMethod getKeyDerivationMethod(AgreementMethod agreementMethod) {
    List<XMLObject> methods = agreementMethod.getUnknownXMLObjects(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
    if (methods.isEmpty()) {
      return null;
    }
    return (KeyDerivationMethod) methods.get(0);
  }

}
