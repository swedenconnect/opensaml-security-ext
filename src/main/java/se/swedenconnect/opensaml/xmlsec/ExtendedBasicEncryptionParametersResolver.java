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
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.criterion.EncryptionConfigurationCriterion;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.swedenconnect.opensaml.xmlsec.algorithm.ExtendedAlgorithmSupport;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHSupport;
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

  // Auto-generate key wrapping key?
  private boolean autoGenerateKeyWrappingKey;

  /**
   * Flag indicating whether the resolver should auto-generate key agreement keys when a resolved credential may be used
   * for key agreement but not for key transport (i.e., EC instead of RSA).
   */
  private boolean autoGenerateKeyAgreementKey;

  public ExtendedBasicEncryptionParametersResolver() {
    // TODO Auto-generated constructor stub
  }

  @Override
  public EncryptionParameters resolveSingle(CriteriaSet criteria) throws ResolverException {
    Constraint.isNotNull(criteria, "CriteriaSet was null");
    Constraint.isNotNull(criteria.get(EncryptionConfigurationCriterion.class),
      "Resolver requires an instance of EncryptionConfigurationCriterion");

    return super.resolveSingle(criteria);
  }

  /**
   * Extends the default implementation with support for encrypting the data encrypting key using a key wrapping key
   * that is created using a key agreement protocol.
   */
  @Override
  protected void resolveAndPopulateCredentialsAndAlgorithms(@Nonnull final EncryptionParameters params,
      @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);

    if (params.getKeyTransportEncryptionCredential() != null) {
      // The original implementation did its work, and we don't have to apply our extension for key agreement.
      return;
    }

    // Resolve the key agreement methods to consider ...
    //
    List<String> keyAgreementMethods = this.getEffectiveKeyAgreementMethods(criteria, whitelistBlacklistPredicate);
    if (keyAgreementMethods.isEmpty()) {
      log.debug("No key agreement methods found in configuration ...");
      if (this.useDefaultKeyAgreementMethods) {
        keyAgreementMethods = ((ExtendedEncryptionConfiguration) ExtendedDefaultSecurityConfigurationBootstrap
          .buildDefaultDecryptionConfiguration()).getAgreementMethodAlgorithms();
        log.debug("Assuming default key agreement methods: {}", keyAgreementMethods);
      }
      else {
        return;
      }
    }
    List<String> keyDerivationAlgorithms = this.getEffectiveKeyDerivationAlgorithms(criteria, whitelistBlacklistPredicate);
    if (keyDerivationAlgorithms.isEmpty()) {
      log.debug("No key derivation algorithms found in configuration ...");
      if (this.useDefaultKeyAgreementMethods) {
        keyDerivationAlgorithms = ((ExtendedEncryptionConfiguration) ExtendedDefaultSecurityConfigurationBootstrap
          .buildDefaultDecryptionConfiguration()).getKeyDerivationAlgorithms();
        log.debug("Assuming default key derivation algorithms: {}", keyDerivationAlgorithms);
      }
      // Else, we don't fail since some agreement methods may do without a derivation method.
    }

    // See if any of the algorithms listed among the key transport algorithms
    // can be used for key wrapping.
    //
    final List<String> keyWrappingAlgorithms = this.getEffectiveKeyWrappingAlgorithms(criteria, whitelistBlacklistPredicate);
    if (keyWrappingAlgorithms.isEmpty()) {
      log.debug("Configuration does not define any key wrapping algorithms ...");
      return;
    }

    // Check if we have any peer credentials that can be used for key agreement ...
    //
    final List<Credential> peerKeyAgreementCredentials = this.getEffectivePeerKeyAgreementCredentials(criteria);
    if (peerKeyAgreementCredentials.isEmpty()) {
      log.debug("No credentials found that can be used in a key agreement protocol ...");
      return;
    }

    // TODO: generate key wrapping key
    // TODO: Iterate
    try {
      params.setKeyTransportEncryptionCredential(
        ECDHSupport.createKeyAgreementCredential(peerKeyAgreementCredentials.get(0), keyWrappingAlgorithms.get(0),
          new ConcatKDFParameters(EncryptionConstants.ALGO_ID_DIGEST_SHA256).toXMLObject()));
      params.setKeyTransportEncryptionAlgorithm(keyWrappingAlgorithms.get(0));
    }
    catch (SecurityException e) {
      log.error("Failed to create XXX", e);
      return;
    }

    // ECDHSupport.createKeyAgreementCredential(peerKeyAgreementCredentials.get(0), keyWrappingAlgorithms.get(0),
    // concatKDFParams)

    // Auto-generate data encryption cred if configured and possible
    this.processDataEncryptionCredentialAutoGeneration(params);
  }

  protected Credential generateKeyAgreementCredential(@Nonnull final Credential credential,
      @Nonnull final String keyWrappingAlgorithm,
      @Nonnull final List<String> keyAgreementMethods) {

    if (!ExtendedAlgorithmSupport.peerCredentialSupportsKeyAgreement(credential)) {
      log.error("Cannot generate key agreement credential - supplied peer credential does not support key agreement");
      return null;
    }

    return null;
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

    final ArrayList<String> accumulator = new ArrayList<>();
    for (final EncryptionConfiguration config : criteria.get(EncryptionConfigurationCriterion.class).getConfigurations()) {

      if (ExtendedEncryptionConfiguration.class.isInstance(config)) {
        accumulator.addAll(Collections2.filter(((ExtendedEncryptionConfiguration) config).getAgreementMethodAlgorithms(),
          Predicates.and(getAlgorithmRuntimeSupportedPredicate(), whitelistBlacklistPredicate)));
      }
    }
    return accumulator;
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

    final ArrayList<String> accumulator = new ArrayList<>();
    for (final EncryptionConfiguration config : criteria.get(EncryptionConfigurationCriterion.class).getConfigurations()) {

      if (ExtendedEncryptionConfiguration.class.isInstance(config)) {
        accumulator.addAll(((ExtendedEncryptionConfiguration) config).getKeyDerivationAlgorithms());
      }
    }
    return accumulator;
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
    final ArrayList<Credential> accumulator = new ArrayList<>();
    for (final EncryptionConfiguration config : criteria.get(EncryptionConfigurationCriterion.class).getConfigurations()) {

      if (ExtendedEncryptionConfiguration.class.isInstance(config)) {
        accumulator.addAll(((ExtendedEncryptionConfiguration) config).getKeyAgreementCredentials());
      }
      else {
        config.getKeyTransportEncryptionCredentials()
          .stream()
          .filter(ExtendedAlgorithmSupport::peerCredentialSupportsKeyAgreement)
          .forEach(accumulator::add);
      }
    }
    return accumulator;
  }

  /**
   * Get the effective list of key wrapping algorithm URIs to consider, including application of whitelist/blacklist
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
  protected List<String> getEffectiveKeyWrappingAlgorithms(@Nonnull final CriteriaSet criteria,
      @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

    final List<String> keyTransportAlgorithms = this.getEffectiveKeyTransportAlgorithms(criteria, whitelistBlacklistPredicate);
    return keyTransportAlgorithms.stream()
      .map(this.getAlgorithmRegistry()::get)
      .filter(ExtendedAlgorithmSupport::isKeyWrappingAlgorithm)
      .map(AlgorithmDescriptor::getURI)
      .collect(Collectors.toList());
  }

  @Override
  @Nullable
  protected KeyInfoGenerator resolveKeyTransportKeyInfoGenerator(@Nonnull final CriteriaSet criteria,
      @Nullable final Credential keyTransportEncryptionCredential) {

    return super.resolveKeyTransportKeyInfoGenerator(criteria, keyTransportEncryptionCredential);
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
