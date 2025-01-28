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
package se.swedenconnect.opensaml.xmlsec.signature.support;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor.AlgorithmType;
import org.opensaml.xmlsec.algorithm.AlgorithmRegistry;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.impl.BasicSignatureSigningParametersResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;

import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Utility methods for signatures.
 *
 * @author Martin Lindström (martin@idsec.se)
 */
public class SAMLObjectSigner {

  /**
   * Signs the supplied SAML object using the supplied credentials and signature configuration(s).
   * <p>
   * Note: If you have obtained the peer's prefered signature credentials, this configuration should be supplied first
   * ...
   * </p>
   *
   * @param object object to sign
   * @param signingCredentials signature credentials
   * @param configs signature configuration
   * @param <T> the object type
   * @throws SignatureException for signature creation errors
   */
  public static <T extends SignableSAMLObject> void sign(
      final T object, final Credential signingCredentials, final SignatureSigningConfiguration... configs)
      throws SignatureException {

    try {
      object.setSignature(null);

      final SignatureSigningConfiguration[] criteriaConfig;
      if (configs == null || configs.length == 0) {
        criteriaConfig = new SignatureSigningConfiguration[2];
        criteriaConfig[0] = SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration();
      }
      else {
        criteriaConfig = new SignatureSigningConfiguration[configs.length + 1];
        System.arraycopy(configs, 0, criteriaConfig, 0, configs.length);
      }
      final BasicSignatureSigningConfiguration signatureCreds = new BasicSignatureSigningConfiguration();
      signatureCreds.setSigningCredentials(Collections.singletonList(signingCredentials));
      criteriaConfig[criteriaConfig.length - 1] = signatureCreds;

      final BasicSignatureSigningParametersResolver signatureParametersResolver =
          new BasicSignatureSigningParametersResolver();
      final CriteriaSet criteriaSet = new CriteriaSet(new SignatureSigningConfigurationCriterion(criteriaConfig));
      final SignatureSigningParameters parameters = signatureParametersResolver.resolveSingle(criteriaSet);

      SignatureSupport.signObject(object, parameters);
    }
    catch (final ResolverException | org.opensaml.security.SecurityException | MarshallingException e) {
      throw new SignatureException(e);
    }
  }

  /**
   * Signs the supplied SAML object using the supplied credentials and signature configuration and also handles the peer
   * signature requirements.
   * <p>
   * This method corresponds to:
   * {@code SignatureSigningConfiguration peerConfig = getSignaturePreferences(recipientMetadata);} followed by
   * {@code sign(object, signingCredentials, config, peerConfig);}. If no peer config is found, this is not passed.
   * </p>
   *
   * @param object object to sign
   * @param signingCredentials signature credentials
   * @param config signature configuration
   * @param recipientMetadata recipient's metadata
   * @param <T> the object type
   * @throws SignatureException for signature errors
   */
  public static <T extends SignableSAMLObject> void sign(final T object, final Credential signingCredentials,
      final SignatureSigningConfiguration config, final EntityDescriptor recipientMetadata) throws SignatureException {

    final SignatureSigningConfiguration peerConfig = getSignaturePreferences(recipientMetadata);
    final SignatureSigningConfiguration[] configs = new SignatureSigningConfiguration[1 + (peerConfig != null ? 1 : 0)];

    int pos = 0;
    if (peerConfig != null) {
      configs[pos++] = peerConfig;
    }
    if (config != null) {
      configs[pos] = config;
    }
    else {
      configs[pos] = SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration();
    }

    sign(object, signingCredentials, configs);
  }

  /**
   * A recipient of a signed message may specify the signature algorithm it prefers by including the
   * {@code <alg:SigningMethod>} element in its metadata. This method locates these elements, and if present, creates a
   * {@link SignatureSigningConfiguration} object that should be supplied to
   * {@link #sign(SignableSAMLObject, Credential, SignatureSigningConfiguration...)}.
   *
   * @param metadata the recipient's metadata
   * @return a {@link SignatureSigningConfiguration} element, or {@code null} if no preferred signing algorithms were
   *     specified
   */
  public static SignatureSigningConfiguration getSignaturePreferences(final EntityDescriptor metadata) {

    if (metadata == null) {
      return null;
    }

    List<SigningMethod> signingMethods = Collections.emptyList();
    List<DigestMethod> digestMethods = Collections.emptyList();

    // First check the extensions under the role descriptor ...
    //
    final SSODescriptor descriptor = getSSODescriptor(metadata);
    if (descriptor != null) {
      signingMethods = getMetadataExtensions(descriptor.getExtensions(), SigningMethod.class);
      digestMethods = getMetadataExtensions(descriptor.getExtensions(), DigestMethod.class);
    }
    // If no extensions are specified under the role descriptor, check the entity descriptor extensions ...
    //
    if (signingMethods.isEmpty()) {
      signingMethods = getMetadataExtensions(metadata.getExtensions(), SigningMethod.class);
    }
    if (digestMethods.isEmpty()) {
      digestMethods = getMetadataExtensions(metadata.getExtensions(), DigestMethod.class);
    }

    // Filter those that we don't support
    //
    final AlgorithmRegistry registry = AlgorithmSupport.getGlobalAlgorithmRegistry();
    if (!signingMethods.isEmpty()) {
      signingMethods = signingMethods.stream().filter(s -> {
        final AlgorithmDescriptor ad = registry.get(s.getAlgorithm());
        if (ad != null) {
          return AlgorithmType.Signature.equals(ad.getType());
        }
        return false;
      }).collect(Collectors.toList());
    }
    if (!digestMethods.isEmpty()) {
      digestMethods = digestMethods.stream().filter(s -> {
        final AlgorithmDescriptor ad = registry.get(s.getAlgorithm());
        if (ad != null) {
          return AlgorithmType.MessageDigest.equals(ad.getType());
        }
        return false;
      }).collect(Collectors.toList());
    }

    if (signingMethods.isEmpty() && digestMethods.isEmpty()) {
      return null;
    }

    final BasicSignatureSigningConfiguration config = new BasicSignatureSigningConfiguration();
    if (!signingMethods.isEmpty()) {
      // We can't handle key lengths here!
      config.setSignatureAlgorithms(
          signingMethods.stream().map(SigningMethod::getAlgorithm).collect(Collectors.toList()));
    }
    if (!digestMethods.isEmpty()) {
      config.setSignatureReferenceDigestMethods(
          digestMethods.stream().map(DigestMethod::getAlgorithm).collect(Collectors.toList()));
    }

    return config;
  }

  /**
   * Returns the SSODescriptor for the supplied SP or IdP entity descriptor.
   *
   * @param ed the entity descriptor
   * @return the SSODescriptor
   */
  private static SSODescriptor getSSODescriptor(final EntityDescriptor ed) {
    if (ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS) != null) {
      return ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    }
    else {
      return ed.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    }
  }

  /**
   * Finds all extensions matching the supplied type.
   *
   * @param extensions the {@link Extensions} to search
   * @param clazz the extension type
   * @param <T> the type of the extension
   * @return a (possibly empty) list of extensions elements of the given type
   */
  private static <T> List<T> getMetadataExtensions(final Extensions extensions, final Class<T> clazz) {
    if (extensions == null) {
      return Collections.emptyList();
    }
    return extensions.getUnknownXMLObjects()
        .stream()
        .filter(e -> clazz.isAssignableFrom(e.getClass()))
        .map(clazz::cast)
        .collect(Collectors.toList());
  }

  // Hidden constructor.
  private SAMLObjectSigner() {
  }

}
