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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.KeyTransportAlgorithmPredicate;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import se.swedenconnect.opensaml.xmlsec.algorithm.ExtendedAlgorithmSupport;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHSupport;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;

/**
 * Extends OpenSAML's {@link BasicEncryptionParametersResolver} with support for key agreement.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedBasicEncryptionParametersResolver extends BasicEncryptionParametersResolver {

  /** Logger. */
  private Logger log = LoggerFactory.getLogger(ExtendedBasicEncryptionParametersResolver.class);

  /**
   * A setting that tells whether we should rely on that we received an {@link ExtendedEncryptionConfiguration} object
   * among the criteria. If we want to function in an environment where the caller doesn't know anything about
   * {@link ExtendedEncryptionConfiguration} we can set this property to {@code true}. In that case, our resolving will
   * assume that default key agreement methods are available.
   */
  private boolean useDefaultKeyAgreementMethods = true;

  /**
   * Constructor.
   */
  public ExtendedBasicEncryptionParametersResolver() {
  }

  /**
   * Extends the default implementation with support for encrypting the data encrypting key using a key wrapping key
   * that is created using a key agreement protocol.
   */
  @Override
  protected void resolveAndPopulateCredentialsAndAlgorithms(@Nonnull final EncryptionParameters params,
      @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    List<Credential> keyTransportCredentials = this.getEffectiveKeyTransportCredentials(criteria);
    final List<String> keyTransportAlgorithms = this.getEffectiveKeyTransportAlgorithms(criteria, whitelistBlacklistPredicate);
    log.trace("Resolved effective key transport algorithms: {}", keyTransportAlgorithms);

    // If we have any credentials that can be used for key agreement, we add them first in the list.
    keyTransportCredentials.addAll(0, this.getEffectivePeerKeyAgreementCredentials(criteria));

    // Some of the key transport algorithms may be used for key wrapping. Get them in a list...
    final List<String> keyWrappingAlgorithms = keyTransportAlgorithms.stream()
      .map(this.getAlgorithmRegistry()::get)
      .filter(ExtendedAlgorithmSupport::isKeyWrappingAlgorithm)
      .map(AlgorithmDescriptor::getURI)
      .collect(Collectors.toList());

    final List<Credential> dataEncryptionCredentials = getEffectiveDataEncryptionCredentials(criteria);
    final List<String> dataEncryptionAlgorithms = getEffectiveDataEncryptionAlgorithms(criteria,
      whitelistBlacklistPredicate);
    log.trace("Resolved effective data encryption algorithms: {}", dataEncryptionAlgorithms);

    // Select the data encryption algorithm, and credential if exists
    if (dataEncryptionCredentials.isEmpty()) {
      params.setDataEncryptionAlgorithm(this.resolveDataEncryptionAlgorithm(null, dataEncryptionAlgorithms));
    }
    else {
      for (final Credential dataEncryptionCredential : dataEncryptionCredentials) {
        final String dataEncryptionAlgorithm = this.resolveDataEncryptionAlgorithm(dataEncryptionCredential, dataEncryptionAlgorithms);
        if (dataEncryptionAlgorithm != null) {
          params.setDataEncryptionCredential(dataEncryptionCredential);
          params.setDataEncryptionAlgorithm(dataEncryptionAlgorithm);
          break;
        }
        else {
          log.debug("Unable to resolve data encryption algorithm for credential with key type '{}', "
              + "considering other credentials",
            CredentialSupport.extractEncryptionKey(dataEncryptionCredential).getAlgorithm());
        }
      }
    }

    // Resolve the key agreement methods to consider ...
    final List<String> keyAgreementMethods = this.getEffectiveKeyAgreementMethods(criteria, whitelistBlacklistPredicate);
    if (keyAgreementMethods.isEmpty()) {
      log.debug("No key agreement methods found in configuration ...");
    }

    final List<String> keyDerivationAlgorithms = this.getEffectiveKeyDerivationAlgorithms(criteria, whitelistBlacklistPredicate);
    if (keyDerivationAlgorithms.isEmpty()) {
      log.debug("No key derivation algorithms found in configuration ...");
    }
    final ConcatKDFParameters concatKDFParameters = keyDerivationAlgorithms.contains(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT)
        ? this.getConcatKDFParameters(criteria, whitelistBlacklistPredicate)
        : null;

    // Check if we have any peer credentials that can be used for key agreement ...
    //
    final List<Credential> peerKeyAgreementCredentials = this.getEffectivePeerKeyAgreementCredentials(criteria);
    if (peerKeyAgreementCredentials.isEmpty()) {
      log.debug("No credentials found that can be used in a key agreement protocol ...");
      return;
    }

    final KeyTransportAlgorithmPredicate keyTransportPredicate = resolveKeyTransportAlgorithmPredicate(criteria);

    // Select key encryption cred and algorithm
    for (final Credential keyTransportCredential : keyTransportCredentials) {
      final String keyTransportAlgorithm = this.resolveKeyTransportAlgorithm(keyTransportCredential,
        keyTransportAlgorithms, params.getDataEncryptionAlgorithm(), keyTransportPredicate);

      if (keyTransportAlgorithm != null) {
        params.setKeyTransportEncryptionCredential(keyTransportCredential);
        params.setKeyTransportEncryptionAlgorithm(keyTransportAlgorithm);

        this.resolveAndPopulateRSAOAEPParams(params, criteria, whitelistBlacklistPredicate);
        break;
      }
      // See if the credential can be used for key agreement ...
      else if (ExtendedAlgorithmSupport.peerCredentialSupportsKeyAgreement(keyTransportCredential)) {
        for (final String keyWrappingAlgo : keyWrappingAlgorithms) {
          try {
            Credential keyAgreementCredential = this.generateKeyAgreementCredential(
              keyTransportCredential, keyWrappingAlgo, keyAgreementMethods, keyDerivationAlgorithms, concatKDFParameters);

            params.setKeyTransportEncryptionCredential(keyAgreementCredential);
            params.setKeyTransportEncryptionAlgorithm(keyWrappingAlgo);
            break;
          }
          catch (SecurityException e) {
            log.error("Failed to create key agreement credential using {} key wrapping - {}", keyWrappingAlgo, e.getMessage(), e);
          }
        }
        if (params.getKeyTransportEncryptionAlgorithm() != null) {
          break;
        }
      }
      else {
        log.debug("Unable to resolve key transport algorithm for credential with key type '{}', "
            + "considering other credentials",
          CredentialSupport.extractEncryptionKey(keyTransportCredential).getAlgorithm());
      }
    }

    // Auto-generate data encryption cred if configured and possible
    this.processDataEncryptionCredentialAutoGeneration(params);
  }


  /**
   * Generates a key agreement credential based on the resolved algorithms.
   * 
   * @param credential
   *          the peer credential
   * @param keyWrappingAlgorithms
   *          key wrapping algorithms
   * @param keyAgreementMethods
   *          key agreement methods
   * @param keyDerivationAlgorithms
   *          key derivation algorithms
   * @param concatKDFParameters
   *          concat KDF parameters
   * @return a key key agreement credential or {@code null}
   * @throws SecurityException
   *           for key generation errors
   */
  protected Credential generateKeyAgreementCredential(@Nonnull final Credential credential,
      @Nonnull final String keyWrappingAlgorithm,
      @Nonnull final List<String> keyAgreementMethods,
      @Nonnull final List<String> keyDerivationAlgorithms,
      ConcatKDFParameters concatKDFParameters) throws SecurityException {

    //
    // Note: This code should be made more generic, but since we only support ECDH-ES agreement and
    // ConcatKDF key derivation at the moment, it is a bit static ... to say the least
    //

    if (!keyAgreementMethods.contains(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES)) {
      log.info("{} not among configured key agreement methods - it's the only supported key agreement method at the moment",
        EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
      return null;
    }
    if (!keyDerivationAlgorithms.contains(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT)) {
      log.info("{} not among configured key derivation algorithms - it's the only supported algorithm at the moment",
        EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT);
      return null;
    }
    if (concatKDFParameters == null) {
      log.debug("No ConcatKDFPars found in configuration, using default parameters ...");
      concatKDFParameters = ((ExtendedEncryptionConfiguration) ExtendedDefaultSecurityConfigurationBootstrap
        .buildDefaultDecryptionConfiguration()).getConcatKDFParameters();
    }

    return ECDHSupport.createKeyAgreementCredential(credential, keyWrappingAlgorithm, concatKDFParameters.toXMLObject());
  }

  /**
   * Get the effective list of key agreement method URIs to consider, including application of whitelist/blacklist
   * policy.
   * 
   * @param criteria
   *          the input criteria being evaluated
   * @param whitelistBlacklistPredicate
   *          the whitelist/blacklist predicate to use
   * 
   * @return the list of effective algorithm URIs
   */
  @Nonnull
  protected List<String> getEffectiveKeyAgreementMethods(@Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    final ArrayList<String> methods = new ArrayList<>();
    List<ExtendedEncryptionConfiguration> cfgList = this.getExtendedConfiguration(criteria);

    if (cfgList.isEmpty()) {
      if (this.useDefaultKeyAgreementMethods) {
        methods.addAll(((ExtendedEncryptionConfiguration) ExtendedDefaultSecurityConfigurationBootstrap
          .buildDefaultDecryptionConfiguration()).getAgreementMethodAlgorithms());
        log.debug("Assuming default key agreement methods: {}", methods);
      }
      else {
        log.info("useDefaultKeyAgreementMethods is not set and criteria contains no ExtendedEncryptionConfiguration - "
            + "No key agreement methods can be found");
      }
      return methods;
    }

    cfgList.stream()
      .map(c -> Collections2.filter(c.getAgreementMethodAlgorithms(),
        Predicates.and(getAlgorithmRuntimeSupportedPredicate(), whitelistBlacklistPredicate)))
      .forEach(methods::addAll);

    return methods;
  }

  /**
   * Get the effective list of key derivation algorithm URIs to consider, including application of whitelist/blacklist
   * policy.
   * 
   * @param criteria
   *          the input criteria being evaluated
   * @param whitelistBlacklistPredicate
   *          the whitelist/blacklist predicate to use
   * 
   * @return the list of effective algorithm URIs
   */
  @Nonnull
  protected List<String> getEffectiveKeyDerivationAlgorithms(@Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    final ArrayList<String> algos = new ArrayList<>();
    List<ExtendedEncryptionConfiguration> cfgList = this.getExtendedConfiguration(criteria);

    if (cfgList.isEmpty()) {
      if (this.useDefaultKeyAgreementMethods) {
        algos.addAll(((ExtendedEncryptionConfiguration) ExtendedDefaultSecurityConfigurationBootstrap
          .buildDefaultDecryptionConfiguration()).getKeyDerivationAlgorithms());
        log.debug("Assuming default key derivation algorithms: {}", algos);
      }
      else {
        log.info("useDefaultKeyAgreementMethods is not set and criteria contains no ExtendedEncryptionConfiguration - "
            + "No key derivation methods can be found");
      }
      return algos;
    }

    cfgList.stream()
      .map(ExtendedEncryptionConfiguration::getKeyDerivationAlgorithms)
      .forEach(algos::addAll);

    return algos;
  }

  /**
   * Obtains the {@link ConcatKDFParameters} to use for ConcatKDF key derivation.
   * 
   * @param criteria
   *          the criteria
   * @param whitelistBlacklistPredicate
   *          the whitelist/blacklist predicate to use
   * @return the {@link ConcatKDFParameters} object or {@code null}
   */
  @Nonnull
  protected ConcatKDFParameters getConcatKDFParameters(@Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    List<ExtendedEncryptionConfiguration> cfgList = this.getExtendedConfiguration(criteria);
    for (final ExtendedEncryptionConfiguration config : cfgList) {
      ConcatKDFParameters pars = config.getConcatKDFParameters();
      // Ensure that the digest method is not black listed ...
      if (!whitelistBlacklistPredicate.apply(pars.getDigestMethod())) {
        log.info("ConcatKDFParams found in criteria states digest method '{}' - this is not valid according to white/black list",
          pars.getDigestMethod());
        continue;
      }
      return pars;
    }
    return null;
  }

  /**
   * Get the effective list of peer key agreement credentials to consider.
   * 
   * @param criteria
   *          the input criteria being evaluated
   * 
   * @return the list of credentials
   */
  @Nonnull
  protected List<Credential> getEffectivePeerKeyAgreementCredentials(@Nonnull final CriteriaSet criteria) {
    final ArrayList<Credential> credentials = new ArrayList<>();
    final List<ExtendedEncryptionConfiguration> extCfg = this.getExtendedConfiguration(criteria);
    extCfg.stream()
      .map(ExtendedEncryptionConfiguration::getKeyAgreementCredentials)
      .forEach(credentials::addAll);
    return credentials;
  }

  /**
   * Extracts a list of {@link ExtendedEncryptionConfiguration} objects from the supplied criteria.
   * 
   * @param criteria
   *          the criteria
   * @return a (possibly empty) list of {@link ExtendedEncryptionConfiguration} objects
   */
  private List<ExtendedEncryptionConfiguration> getExtendedConfiguration(@Nonnull final CriteriaSet criteria) {
    final EncryptionConfigurationCriterion encryptionConfigurationCriterion = criteria.get(EncryptionConfigurationCriterion.class);
    if (encryptionConfigurationCriterion == null) {
      log.info("No EncryptionConfigurationCriterion available");
      return Collections.emptyList();
    }
    return encryptionConfigurationCriterion.getConfigurations()
      .stream()
      .filter(ExtendedEncryptionConfiguration.class::isInstance)
      .map(ExtendedEncryptionConfiguration.class::cast)
      .collect(Collectors.toList());
  }

  /**
   * Tells whether we should rely on that we received an {@link ExtendedEncryptionConfiguration} object among the
   * criteria. If we want to function in an environment where the caller doesn't know anything about
   * {@link ExtendedEncryptionConfiguration} we can set this property to {@code true}. In that case, our resolving will
   * assume that default key agreement methods are available if no {@code ExtendedEncryptionConfiguration} is passed
   * among the criteria.
   * 
   * @param useDefaultKeyAgreementMethods
   *          whether we should assume a set of key agreement methods (if no {@code ExtendedEncryptionConfiguration} is
   *          passed)
   */
  public void setUseDefaultKeyAgreementMethods(boolean useDefaultKeyAgreementMethods) {
    this.useDefaultKeyAgreementMethods = useDefaultKeyAgreementMethods;
  }

}
