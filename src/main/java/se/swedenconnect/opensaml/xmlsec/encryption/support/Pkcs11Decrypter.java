/*
 * Copyright 2019-2024 Sweden Connect
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import java.util.Optional;
import java.util.function.Predicate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherInput;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.EncryptedType;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCriterion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.google.common.base.Strings;

import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * An extension to OpenSAML's {@link Decrypter} class implementing a workaround for the problem that when using the
 * SunPKCS11 crypto provider OAEPPadding does not work.
 * <p>
 * See this post on <a href=
 * "https://stackoverflow.com/questions/23844694/bad-padding-exception-rsa-ecb-oaepwithsha-256andmgf1padding-in-pkcs11">
 * Stack overflow</a>.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class Pkcs11Decrypter extends Decrypter {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(Pkcs11Decrypter.class);

  /** Test mode allows us to test the SunPKCS11 workround with a soft key. */
  private boolean testMode = false;

  /** Resolver for key encryption keys. */
  private final KeyInfoCredentialResolver _kekResolver;

  /** Predicate for checking for RSAOAEP. */
  private final static Predicate<EncryptedKey> isRSAOAEP = ek ->
      Optional.ofNullable(ek.getEncryptionMethod())
          .map(org.opensaml.xmlsec.encryption.EncryptionMethod::getAlgorithm)
          .map(AlgorithmSupport::isRSAOAEP)
          .orElse(false);

  /**
   * Constructor.
   *
   * @param params decryption parameters to use
   */
  public Pkcs11Decrypter(final DecryptionParameters params) {
    super(params);
    this._kekResolver = params.getKEKKeyInfoCredentialResolver();
  }

  /**
   * Constructor.
   *
   * @param newResolver resolver for data encryption keys.
   * @param newKEKResolver resolver for key encryption keys.
   * @param newEncKeyResolver resolver for EncryptedKey elements
   */
  public Pkcs11Decrypter(final KeyInfoCredentialResolver newResolver, final KeyInfoCredentialResolver newKEKResolver,
      final EncryptedKeyResolver newEncKeyResolver) {
    super(newResolver, newKEKResolver, newEncKeyResolver);
    this._kekResolver = newKEKResolver;
  }

  /**
   * Constructor.
   *
   * @param newResolver resolver for data encryption keys.
   * @param newKEKResolver resolver for key encryption keys.
   * @param newEncKeyResolver resolver for EncryptedKey elements
   * @param whitelistAlgos collection of whitelisted algorithm URIs
   * @param blacklistAlgos collection of blacklisted algorithm URIs
   */
  public Pkcs11Decrypter(final KeyInfoCredentialResolver newResolver, final KeyInfoCredentialResolver newKEKResolver,
      final EncryptedKeyResolver newEncKeyResolver, final Collection<String> whitelistAlgos,
      final Collection<String> blacklistAlgos) {
    super(newResolver, newKEKResolver, newEncKeyResolver, whitelistAlgos, blacklistAlgos);
    this._kekResolver = newKEKResolver;
  }

  /**
   * Extends {@link Decrypter#decryptKey(EncryptedKey, String, Key)} with an implementation for missing OAEP padding in
   * the SunPKCS11 provider.
   */
  @Override
  @Nonnull
  public Key decryptKey(@Nonnull final EncryptedKey encryptedKey, @Nonnull final String algorithm,
      @Nonnull final Key kek) throws DecryptionException {

    if (kek != null) {
      if (isRSAOAEP.test(encryptedKey) && this.testMode || isP11PrivateKey(kek)) {
        // Work-around for OAEP padding - we don't know the keysize since we only have
        // a private key object from the HSM ... So, we'll have to list all possible credentials ...
        //
        final CriteriaSet criteriaSet = this.buildCredentialCriteria(encryptedKey, this.getKEKResolverCriteria());
        try {
          for (final Credential cred : this._kekResolver.resolve(criteriaSet)) {
            try {
              if (cred.getPublicKey() instanceof RSAPublicKey) {
                return this.decryptKey(encryptedKey, algorithm, CredentialSupport.extractDecryptionKey(cred),
                    ((RSAPublicKey) cred.getPublicKey()).getModulus().bitLength());
              }
            }
            catch (final DecryptionException e) {
              final String msg = "Attempt to decrypt EncryptedKey using credential from KEK KeyInfo resolver failed: ";
              log.debug(msg, e);
            }
          }
        }
        catch (final ResolverException e) {
          log.error("Error resolving credentials from EncryptedKey KeyInfo", e);
        }
        log.error("Failed to decrypt EncryptedKey, failed to find out the keylength for private key");
        throw new DecryptionException("Valid decryption key for EncryptedKey could not be resolved");
      }
    }
    return super.decryptKey(encryptedKey, algorithm, kek);
  }

  /**
   * Extends {@link Decrypter#decryptKey(EncryptedKey, String)} so that we may get hold of the corresponding RSA
   * certificate. We need that since we need to figure out the key length of the RSA private key (and we can't ask a
   * SunPKCS11 private key for its key length).
   */
  @Override
  @Nonnull
  public Key decryptKey(@Nonnull final EncryptedKey encryptedKey, @Nonnull final String algorithm)
      throws DecryptionException {

    if (isRSAOAEP.test(encryptedKey)) {
      if (this._kekResolver == null) {
        log.warn("No KEK KeyInfo credential resolver is available, cannot attempt EncryptedKey decryption");
        throw new DecryptionException("No KEK KeyInfo resolver is available for EncryptedKey decryption");
      }
      else if (Strings.isNullOrEmpty(algorithm)) {
        log.error("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
        throw new DecryptionException("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
      }
      final CriteriaSet criteriaSet = this.buildCredentialCriteria(encryptedKey, this.getKEKResolverCriteria());
      try {
        for (final Credential cred : this._kekResolver.resolve(criteriaSet)) {
          try {
            if (cred.getPublicKey() instanceof RSAPublicKey) {
              return this.decryptKey(encryptedKey, algorithm, CredentialSupport.extractDecryptionKey(cred),
                  ((RSAPublicKey) cred.getPublicKey()).getModulus().bitLength());
            }
            else {
              return super.decryptKey(encryptedKey, algorithm, CredentialSupport.extractDecryptionKey(cred));
            }
          }
          catch (final DecryptionException e) {
            final String msg = "Attempt to decrypt EncryptedKey using credential from KEK KeyInfo resolver failed: ";
            log.debug(msg, e);
          }
        }
      }
      catch (final ResolverException e) {
        log.error("Error resolving credentials from EncryptedKey KeyInfo", e);
      }

      log.error("Failed to decrypt EncryptedKey, valid decryption key could not be resolved");
      throw new DecryptionException("Valid decryption key for EncryptedKey could not be resolved");
    }
    else {
      return super.decryptKey(encryptedKey, algorithm);
    }
  }

  /**
   * Decrypts the key (work-around for OAEP padding).
   *
   * @param encryptedKey encrypted key element containing the encrypted key to be decrypted
   * @param algorithm the algorithm associated with the decrypted key
   * @param kek the key encryption key with which to attempt decryption of the encrypted key
   * @param keysize the key length
   * @return the decrypted key
   * @throws DecryptionException for decryption errors
   */
  @Nonnull
  protected Key decryptKey(@Nonnull final EncryptedKey encryptedKey, @Nonnull final String algorithm,
      @Nonnull final Key kek, final int keysize) throws DecryptionException {

    if (!(this.testMode || isP11PrivateKey(kek))) {
      return super.decryptKey(encryptedKey, algorithm, kek);
    }

    if (Strings.isNullOrEmpty(algorithm)) {
      log.error("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
      throw new DecryptionException("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
    }
    this.validateAlgorithms(encryptedKey);

    try {
      this.checkAndMarshall(encryptedKey);
    }
    catch (final DecryptionException e) {
      log.error("Error marshalling EncryptedKey for decryption", e);
      throw e;
    }
    this.preProcessEncryptedKey(encryptedKey, algorithm, kek);

    final XMLCipher xmlCipher;
    try {
      if (this.getJCAProviderName() != null) {
        xmlCipher = XMLCipher.getProviderInstance(this.getJCAProviderName());
      }
      else {
        xmlCipher = XMLCipher.getInstance();
      }
      xmlCipher.init(XMLCipher.UNWRAP_MODE, kek);
    }
    catch (final XMLEncryptionException e) {
      log.error("Error initialzing cipher instance on key decryption", e);
      throw new DecryptionException("Error initialzing cipher instance on key decryption", e);
    }

    final org.apache.xml.security.encryption.EncryptedKey encKey;
    try {
      final Element targetElement = encryptedKey.getDOM();
      encKey = xmlCipher.loadEncryptedKey(targetElement.getOwnerDocument(), targetElement);
    }
    catch (final XMLEncryptionException e) {
      log.error("Error when loading library native encrypted key representation", e);
      throw new DecryptionException("Error when loading library native encrypted key representation", e);
    }

    if (keysize == -1) {
      log.debug("Keysize of private key is not known, will have to find corresponding certificate ...");

    }

    try {
      final Key key = this.customizedDecryptKey(encKey, algorithm, kek, keysize);
      if (key == null) {
        throw new DecryptionException("Key could not be decrypted");
      }
      return key;
    }
    catch (final XMLEncryptionException e) {
      log.error("Error decrypting encrypted key", e);
      throw new DecryptionException("Error decrypting encrypted key", e);
    }
    catch (final Exception e) {
      throw new DecryptionException("Probable runtime exception on decryption:" + e.getMessage(), e);
    }
  }

  /**
   * Performs the actual key decryption.
   *
   * @param encryptedKey the encrypted key
   * @param algorithm the algorithm
   * @param kek the private key
   * @param keysize the keysize
   * @return a secret key
   * @throws XMLEncryptionException for errors
   */
  private Key customizedDecryptKey(final org.apache.xml.security.encryption.EncryptedKey encryptedKey,
      final String algorithm, final Key kek, final int keysize) throws XMLEncryptionException {

    // Obtain the encrypted octets
    final byte[] encryptedBytes = (new XMLCipherInput(encryptedKey)).getBytes();

    try {
      final String provider = this.getJCAProviderName();
      final Cipher c = provider != null
          ? Cipher.getInstance("RSA/ECB/NoPadding", provider)
          : Cipher.getInstance("RSA/ECB/NoPadding");

      c.init(Cipher.DECRYPT_MODE, kek);
      byte[] paddedPlainText = c.doFinal(encryptedBytes);

      /* Ensure leading zeros not stripped */
      if (paddedPlainText.length < keysize / 8) {
        final byte[] tmp = new byte[keysize / 8];
        System.arraycopy(paddedPlainText, 0, tmp, tmp.length - paddedPlainText.length, paddedPlainText.length);
        paddedPlainText = tmp;
      }

      final EncryptionMethod encMethod = encryptedKey.getEncryptionMethod();
      final OAEPParameterSpec oaepParameters =
          this.constructOAEPParameters(encMethod.getAlgorithm(), encMethod.getDigestAlgorithm(),
              encMethod.getMGFAlgorithm(), encMethod.getOAEPparams());

      final RsaOaepMgf1Padding unpadder = new RsaOaepMgf1Padding(oaepParameters, keysize);
      final byte[] secretKeyBytes = unpadder.unpad(paddedPlainText);

      final String jceKeyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);

      return new SecretKeySpec(secretKeyBytes, jceKeyAlgorithm);
    }
    catch (final NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException |
        IllegalBlockSizeException | BadPaddingException e) {
      throw new XMLEncryptionException(e);
    }
  }

  /**
   * Construct an OAEPParameterSpec object from the given parameters
   */
  private OAEPParameterSpec constructOAEPParameters(final String encryptionAlgorithm, final String digestAlgorithm,
      final String mgfAlgorithm, final byte[] oaepParams) {

    String jceDigestAlgorithm = "SHA-1";
    if (digestAlgorithm != null) {
      jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgorithm);
    }

    PSource.PSpecified pSource = PSource.PSpecified.DEFAULT;
    if (oaepParams != null) {
      pSource = new PSource.PSpecified(oaepParams);
    }

    MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
    if (XMLCipher.RSA_OAEP_11.equals(encryptionAlgorithm)) {
      if (EncryptionConstants.MGF1_SHA256.equals(mgfAlgorithm)) {
        mgfParameterSpec = new MGF1ParameterSpec("SHA-256");
      }
      else if (EncryptionConstants.MGF1_SHA384.equals(mgfAlgorithm)) {
        mgfParameterSpec = new MGF1ParameterSpec("SHA-384");
      }
      else if (EncryptionConstants.MGF1_SHA512.equals(mgfAlgorithm)) {
        mgfParameterSpec = new MGF1ParameterSpec("SHA-512");
      }
    }
    return new OAEPParameterSpec(jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource);
  }

  /**
   * Copied from {@link org.opensaml.xmlsec.encryption.support.Decrypter} ...
   *
   * @param encryptedType an EncryptedData or EncryptedKey for which to resolve decryption credentials
   * @param staticCriteria static set of credential criteria to add to the new criteria set
   * @return the new credential criteria set
   */
  private CriteriaSet buildCredentialCriteria(@Nonnull final EncryptedType encryptedType,
      @Nullable final CriteriaSet staticCriteria) {

    final CriteriaSet newCriteriaSet = new CriteriaSet();
    newCriteriaSet.add(new KeyInfoCriterion(encryptedType.getKeyInfo()));
    if (staticCriteria != null && !staticCriteria.isEmpty()) {
      newCriteriaSet.addAll(staticCriteria);
    }
    if (!newCriteriaSet.contains(UsageCriterion.class)) {
      newCriteriaSet.add(new UsageCriterion(UsageType.ENCRYPTION));
    }
    return newCriteriaSet;
  }

  /**
   * Should we run this class in test mode? By using test mode, the customized code where we handle padding for OAEP is
   * executed even if the SunPKCS11 provider is not in use.
   *
   * @param testMode test mode flag
   */
  public void setTestMode(final boolean testMode) {
    this.testMode = testMode;
  }

  /**
   * Predicate that tells whether the supplied {@link Key} is a PKCS#11 private key.
   *
   * @param key the key to test
   * @return {@code true} if the supplied key is a PKCS#11 private key, and {@code false} otherwise
   */
  private static boolean isP11PrivateKey(final Key key) {
    return "sun.security.pkcs11.P11Key$P11PrivateKey".equals(key.getClass().getName())
        || "sun.security.pkcs11.P11Key$P11RSAPrivateKeyInternal".equals(key.getClass().getName());
  }

}
