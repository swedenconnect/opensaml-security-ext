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

import java.security.Key;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLMDCredentialContext;
import org.opensaml.saml.security.impl.SAMLMetadataEncryptionParametersResolver;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmRegistry;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.security.credential.KeyAgreementCredential;
import se.swedenconnect.opensaml.xmlsec.algorithm.ExtendedAlgorithmSupport;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ECDHSupport;
import se.swedenconnect.opensaml.xmlsec.encryption.support.EcEncryptionConstants;

/**
 * An extension of {@link SAMLMetadataEncryptionParametersResolver} that also lets us resolve encryption parameters for
 * key agreement algorithms.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedSAMLMetadataEncryptionParametersResolver extends SAMLMetadataEncryptionParametersResolver {

  /** Logger. */
  private Logger log = LoggerFactory.getLogger(ExtendedSAMLMetadataEncryptionParametersResolver.class);

  /**
   * We really would like to inherit from both {@link SAMLMetadataEncryptionParametersResolver} and
   * {@link ExtendedEncryptionParametersResolver}, but that's not possible, so we fake it.
   */
  private ExtendedEncryptionParametersResolver realSuper;

  /**
   * Constructor.
   *
   * @param resolver
   *          the metadata credential resolver instance to use to resolve encryption credentials
   */
  public ExtendedSAMLMetadataEncryptionParametersResolver(MetadataCredentialResolver resolver) {
    super(resolver);
    this.realSuper = new ExtendedEncryptionParametersResolver();
  }

  /**
   * A copy of SAMLMetadataEncryptionParametersResolver's implementation with some changes for key agreement.
   */
  @Override
  protected void resolveAndPopulateCredentialsAndAlgorithms(@Nonnull final EncryptionParameters params,
      @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    // Create a new CriteriaSet for input to the metadata credential resolver, explicitly
    // setting/forcing an encryption usage criterion.
    final CriteriaSet mdCredResolverCriteria = new CriteriaSet();
    mdCredResolverCriteria.addAll(criteria);
    mdCredResolverCriteria.add(new UsageCriterion(UsageType.ENCRYPTION), true);

    // Note: Here we assume that we will only ever resolve a key transport credential from metadata.
    // Even if it's a symmetric key credential (via a key agreement protocol, or resolved from a KeyName, etc),
    // it ought to be used for symmetric key wrap, not direct data encryption.
    try {
      for (final Credential keyTransportCredential : getMetadataCredentialResolver().resolve(mdCredResolverCriteria)) {

        if (log.isTraceEnabled()) {
          final Key key = CredentialSupport.extractEncryptionKey(keyTransportCredential);
          log.trace("Evaluating key transport encryption credential from SAML metadata of type: {}",
            key != null ? key.getAlgorithm() : "n/a");
        }

        final SAMLMDCredentialContext metadataCredContext = keyTransportCredential.getCredentialContextSet()
          .get(SAMLMDCredentialContext.class);

        final Pair<String, EncryptionMethod> dataEncryptionAlgorithmAndMethod = resolveDataEncryptionAlgorithm(
          criteria, whitelistBlacklistPredicate, metadataCredContext);

        final ResolvedKeyTransport keyTransportAlgorithmAndMethod = this.resolveKeyTransport(
          keyTransportCredential, mdCredResolverCriteria, whitelistBlacklistPredicate,
          dataEncryptionAlgorithmAndMethod.getFirst(), metadataCredContext);

        if (keyTransportAlgorithmAndMethod.getAlgorithm() == null) {
          log.debug("Unable to resolve key transport algorithm for credential with key type '{}', "
              + "considering other credentials",
            CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
          continue;
        }

        params.setKeyTransportEncryptionCredential(keyTransportAlgorithmAndMethod.getCredential());
        params.setKeyTransportEncryptionAlgorithm(keyTransportAlgorithmAndMethod.getAlgorithm());
        params.setDataEncryptionAlgorithm(dataEncryptionAlgorithmAndMethod.getFirst());

        resolveAndPopulateRSAOAEPParams(params, criteria, whitelistBlacklistPredicate,
          keyTransportAlgorithmAndMethod.getEncryptionMethod());

        processDataEncryptionCredentialAutoGeneration(params);

        return;
      }
    }
    catch (final ResolverException e) {
      log.warn("Problem resolving credentials from metadata, falling back to local configuration", e);
    }

    log.debug("Could not resolve encryption parameters based on SAML metadata, "
        + "falling back to locally configured credentials and algorithms");

    this.realSuper.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
  }

  /**
   * Resolver that handles both key transport algorithm and key agreement.
   * 
   * @param keyTransportCredential
   *          the peer credential
   * @param criteria
   *          the criteria
   * @param whitelistBlacklistPredicate
   *          the whitelist/blacklist predicate to use
   * @param dataEncryptionAlgorithm
   *          the data encryption algorithm to use
   * @param metadataCredContext
   *          the metadata credential context (EncryptionMethod elements)
   * @return the algorithm and credential that is the result of the process
   */
  protected ResolvedKeyTransport resolveKeyTransport(
      @Nonnull final Credential keyTransportCredential,
      @Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate,
      @Nullable final String dataEncryptionAlgorithm,
      @Nullable final SAMLMDCredentialContext metadataCredContext) {

    // Invoke the super implementation. It covers all cases except for key agreement scenarios ...
    //
    Pair<String, EncryptionMethod> pair = super.resolveKeyTransportAlgorithm(
      keyTransportCredential, criteria, whitelistBlacklistPredicate, dataEncryptionAlgorithm, metadataCredContext);

    if (pair.getFirst() != null) {
      return new ResolvedKeyTransport(pair.getFirst(), pair.getSecond(), keyTransportCredential);
    }

    // Check to see if this is a credential that can be used for key agreement ...
    //
    if (!ExtendedAlgorithmSupport.peerCredentialSupportsKeyAgreement(keyTransportCredential)) {
      // Nope, nothing we can do ...
      return new ResolvedKeyTransport();
    }

    String keyWrappingAlgorithm = this.resolveKeyWrappingAlgorithm(keyTransportCredential, criteria, whitelistBlacklistPredicate,
      metadataCredContext);
    if (keyWrappingAlgorithm == null) {
      log.debug("No key wrapping algorithm could be resolved - can not perform key agreement for credential of type '{}'",
        CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
      return new ResolvedKeyTransport();
    }

    Pair<String, KeyDerivationMethod> keyAgreement = this.resolveKeyAgreementAlgorithm(
      keyTransportCredential, criteria, whitelistBlacklistPredicate, metadataCredContext);
    if (keyAgreement == null) {
      log.debug("No key agreement algorithm could be resolved - can not perform key agreement for credential of type '{}'",
        CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
      return new ResolvedKeyTransport();
    }

    // OK, now it is time to create a key agreement credential ...
    //
    try {
      KeyAgreementCredential keyAgreementCredential = ECDHSupport.createKeyAgreementCredential(
        keyTransportCredential, keyWrappingAlgorithm, keyAgreement.getSecond());

      return new ResolvedKeyTransport(keyWrappingAlgorithm, null, keyAgreementCredential);
    }
    catch (SecurityException e) {
      log.error("Failed to get a key agreement credential using '{}' ({}) - {}",
        EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES, EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT, e.getMessage(), e);
      return new ResolvedKeyTransport();
    }
  }

  /**
   * Resolves the key wrapping algorithm to use. The method first looks among the EncryptionMethod elements and if no
   * suitable algorithm is found there the local configuration is used.
   * 
   * @param keyTransportCredential
   *          the credential we are resolving for
   * @param criteria
   *          the criteria
   * @param whitelistBlacklistPredicate
   *          the whitelist/blacklist predicate to use
   * @param metadataCredContext
   *          the metadata credential context
   * @return the key wrapping algorithm to use (or {@code null} if none is found)
   */
  protected String resolveKeyWrappingAlgorithm(
      @Nonnull final Credential keyTransportCredential,
      @Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate,
      @Nullable final SAMLMDCredentialContext metadataCredContext) {

    // First try to resolve a key wrapping method from the peer metadata.
    //
    if (metadataCredContext != null) {
      for (final EncryptionMethod encryptionMethod : metadataCredContext.getEncryptionMethods()) {
        final AlgorithmDescriptor algorithmDescriptor = this.getAlgorithmRegistry().get(encryptionMethod.getAlgorithm());
        if (algorithmDescriptor == null) {
          continue;
        }

        if (ExtendedAlgorithmSupport.isKeyWrappingAlgorithm(algorithmDescriptor)) {
          if (Predicates.and(this.getAlgorithmRuntimeSupportedPredicate(), whitelistBlacklistPredicate)
            .apply(algorithmDescriptor.getURI())) {
            log.debug("Found key wrapping algorithm '{}' under EncryptionMethod for credential of type '{}'",
              algorithmDescriptor.getURI(), CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
            return algorithmDescriptor.getURI();
          }
          else {
            log.debug("Key wrapping algorithm '{}' found under EncryptionMethod for credential of type '{}' is not "
                + "allowed according to white/black list configuration", algorithmDescriptor.getURI(),
              CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
          }
        }
      }
    }

    log.debug("No key wrapping algorithm specified under EncryptionMethod for credential of type '{}' - trying local configuration",
      CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());

    final List<String> keyTransportAlgorithms = this.getEffectiveKeyTransportAlgorithms(criteria, whitelistBlacklistPredicate);

    String keyWrappingAlgorithm = keyTransportAlgorithms.stream()
      .map(this.getAlgorithmRegistry()::get)
      .filter(ExtendedAlgorithmSupport::isKeyWrappingAlgorithm)
      .map(AlgorithmDescriptor::getURI)
      .findFirst()
      .orElse(null);

    if (keyWrappingAlgorithm != null) {
      log.debug("Found key wrapping algorithm '{}' in local configuration", keyWrappingAlgorithm);
    }
    else {
      log.debug("No key wrapping algorithm was found in metadata or local configuration");
    }
    return keyWrappingAlgorithm;
  }

  /**
   * Resolves the key agreement algorithm to use. The method first looks among the EncryptionMethod elements and if no
   * suitable algorithm is found there the local configuration is used.
   * 
   * @param keyTransportCredential
   *          the credential we are resolving for
   * @param criteria
   *          the criteria
   * @param whitelistBlacklistPredicate
   *          the whitelist/blacklist predicate to use
   * @param metadataCredContext
   *          the metadata credential context
   * @return the key wrapping agreement to use along with its derivation method (or {@code null} if none is found)
   */
  protected Pair<String, KeyDerivationMethod> resolveKeyAgreementAlgorithm(
      @Nonnull final Credential keyTransportCredential,
      @Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate,
      @Nullable final SAMLMDCredentialContext metadataCredContext) {

    // First try to resolve a key agreement method from the peer metadata.
    //
    String keyAgreementAlgorithm = null;
    KeyDerivationMethod keyDerivationMethod = null;

    if (metadataCredContext != null) {
      for (final EncryptionMethod encryptionMethod : metadataCredContext.getEncryptionMethods()) {
        final AlgorithmDescriptor algorithmDescriptor = this.getAlgorithmRegistry().get(encryptionMethod.getAlgorithm());
        if (algorithmDescriptor == null) {
          continue;
        }

        if (ExtendedAlgorithmSupport.isKeyAgreementAlgorithm(algorithmDescriptor)) {
          keyAgreementAlgorithm = algorithmDescriptor.getURI();
          log.debug("Found key agreement algorithm '{}' under EncryptionMethod for credential of type '{}'",
            keyAgreementAlgorithm, CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());

          // Check to see if a key derivation method is given ...
          keyDerivationMethod = encryptionMethod.getUnknownXMLObjects(KeyDerivationMethod.DEFAULT_ELEMENT_NAME)
            .stream()
            .map(KeyDerivationMethod.class::cast)
            .findFirst()
            .orElse(null);

          if (keyDerivationMethod != null) {
            log.debug("KeyDerivationMethod '{}' was found under EncryptionMethod for '{}' for credential of type '{}'",
              keyDerivationMethod.getAlgorithm(), keyAgreementAlgorithm,
              CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());

            // This should be made more generic.
            if (EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT.equals(keyDerivationMethod.getAlgorithm())) {
              if (!keyDerivationMethod.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).isEmpty()) {
                return new Pair<>(keyAgreementAlgorithm, keyDerivationMethod);
              }
              else {
                log.debug("ConcatKDFParams not specified in metadata - will look for it in local configuration");
                break;
              }
            }
            else {
              return new Pair<>(keyAgreementAlgorithm, keyDerivationMethod);
            }
          }
          else {
            log.debug("No KeyDerivationMethod was found under EncryptionMethod for '{}' for credential of type '{}'",
              algorithmDescriptor.getURI(), CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());

            // Don't return yet. See if the local configuration gives us a KeyDerivation method.
            break;
          }
        }
      }
    }

    if (keyAgreementAlgorithm == null) {
      log.debug("No key agreement algorithm specified under EncryptionMethod for credential of type '{}' - trying local configuration",
        CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
    }
    else {
      log.debug("Key agreement algorithm '{}' was specified under EncryptionMethod for credential of type '{}' - "
          + "trying local configuration to find KeyDerivationMethod",
        keyAgreementAlgorithm, CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
    }

    if (keyAgreementAlgorithm == null) {
      List<String> keyAgreementAlgorithms = this.realSuper.getEffectiveKeyAgreementMethods(criteria, whitelistBlacklistPredicate);
      if (keyAgreementAlgorithms.isEmpty()) {
        log.debug("No key agreement algorithms found in local configuration");
        return null;
      }
      log.debug("Key agreement algorithm(s) {} resolved from local configuration, using '{}'",
        keyAgreementAlgorithms, keyAgreementAlgorithms.get(0));
      keyAgreementAlgorithm = keyAgreementAlgorithms.get(0);
    }

    if (keyDerivationMethod == null) {
      List<String> keyDerivationMethods = this.realSuper.getEffectiveKeyDerivationAlgorithms(criteria, whitelistBlacklistPredicate);
      if (keyDerivationMethods.isEmpty()) {
        log.debug("No key derivation methods found in local configuration");
        return null;
      }
      log.debug("Key derivation method(s) {} resolved from local configuration, using '{}'",
        keyDerivationMethods, keyDerivationMethods.get(0));

      keyDerivationMethod = (KeyDerivationMethod) XMLObjectSupport.buildXMLObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
      keyDerivationMethod.setAlgorithm(keyDerivationMethods.get(0));
    }

    // Special hack - shouldn't be here.
    if (EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT.equals(keyDerivationMethod.getAlgorithm())
        && keyDerivationMethod.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME).isEmpty()) {

      ConcatKDFParameters concatKDFParameters = this.realSuper.getConcatKDFParameters(criteria, whitelistBlacklistPredicate);
      if (concatKDFParameters == null) {
        log.info("Could not get ConcatKDFParams for '{}' from local configuration", EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT);
        return null;
      }
      keyDerivationMethod.getUnknownXMLObjects().add(concatKDFParameters.toXMLObject());
    }

    return new Pair<>(keyAgreementAlgorithm, keyDerivationMethod);
  }
  
  /** {@inheritDoc} */
  @Override
  @Nullable
  protected KeyInfoGenerator resolveKeyTransportKeyInfoGenerator(@Nonnull final CriteriaSet criteria,
      @Nullable final Credential keyTransportEncryptionCredential) {
    return this.realSuper.resolveKeyTransportKeyInfoGenerator(criteria, keyTransportEncryptionCredential);
  }

  /** {@inheritDoc} */
  @Override
  public void setAlgorithmRegistry(AlgorithmRegistry registry) {
    super.setAlgorithmRegistry(registry);
    this.realSuper.setAlgorithmRegistry(registry);
  }

  /** {@inheritDoc} */
  @Override
  public void setAutoGenerateDataEncryptionCredential(boolean flag) {
    super.setAutoGenerateDataEncryptionCredential(flag);
    this.realSuper.setAutoGenerateDataEncryptionCredential(flag);
  }

  /**
   * Tells whether we should rely on that we received an {@link ExtendedEncryptionConfiguration} object among the
   * criteria. If we want to function in an environment where the caller doesn't know anything about
   * {@link ExtendedEncryptionConfiguration} we can set this property to {@code true}. In that case, our resolving will
   * assume that default key agreement methods are available if no {@code ExtendedEncryptionConfiguration} is passed
   * among the criteria.
   * 
   * @param flag
   *          whether we should assume a set of key agreement methods (if no {@code ExtendedEncryptionConfiguration} is
   *          passed)
   */
  public void setUseKeyAgreementDefaults(boolean flag) {
    this.realSuper.setUseKeyAgreementDefaults(flag);
  }

  private static class ResolvedKeyTransport {
    private String algorithm;
    private EncryptionMethod encryptionMethod;
    private Credential credential;

    public ResolvedKeyTransport() {
    }

    public ResolvedKeyTransport(String algorithm, EncryptionMethod encryptionMethod, Credential credential) {
      this.algorithm = algorithm;
      this.encryptionMethod = encryptionMethod;
      this.credential = credential;
    }

    public String getAlgorithm() {
      return this.algorithm;
    }

    public EncryptionMethod getEncryptionMethod() {
      return this.encryptionMethod;
    }

    public Credential getCredential() {
      return this.credential;
    }

  }
}
