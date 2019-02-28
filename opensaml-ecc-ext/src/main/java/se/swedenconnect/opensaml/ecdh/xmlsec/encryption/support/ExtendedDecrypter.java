package se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support;

import com.google.common.base.Strings;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.util.Collection;

public class ExtendedDecrypter extends Decrypter {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ExtendedDecrypter.class);


  public ExtendedDecrypter(DecryptionParameters params) {
    super(params);
  }

  public ExtendedDecrypter(@Nullable KeyInfoCredentialResolver newResolver,
    @Nullable KeyInfoCredentialResolver newKEKResolver,
    @Nullable EncryptedKeyResolver newEncKeyResolver) {
    super(newResolver, newKEKResolver, newEncKeyResolver);
  }

  public ExtendedDecrypter(@Nullable KeyInfoCredentialResolver newResolver,
    @Nullable KeyInfoCredentialResolver newKEKResolver,
    @Nullable EncryptedKeyResolver newEncKeyResolver, @Nullable Collection<String> whitelistAlgos,
    @Nullable Collection<String> blacklistAlgos) {
    super(newResolver, newKEKResolver, newEncKeyResolver, whitelistAlgos, blacklistAlgos);
  }

  /**
   * Decrypts the supplied EncryptedKey and returns the resulting Java security Key object. The algorithm of the
   * decrypted key must be supplied by the caller based on knowledge of the associated EncryptedData information.
   *
   * @param encryptedKey encrypted key element containing the encrypted key to be decrypted
   * @param algorithm the algorithm associated with the decrypted key
   * @param kek the key encryption key with which to attempt decryption of the encrypted key
   * @return the decrypted key
   * @throws DecryptionException exception indicating a decryption error
   */
  @Override
  @Nonnull public Key decryptKey(@Nonnull final EncryptedKey encryptedKey, @Nonnull final String algorithm,
    @Nonnull Key kek) throws DecryptionException {
    if (kek == null) {
      log.error("Data encryption key was null");
      throw new IllegalArgumentException("Data encryption key cannot be null");
    } else if (Strings.isNullOrEmpty(algorithm)) {
      log.error("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
      throw new DecryptionException("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
    }

    validateAlgorithms(encryptedKey);

    try {
      checkAndMarshall(encryptedKey);
    } catch (final DecryptionException e) {
      log.error("Error marshalling EncryptedKey for decryption", e);
      throw e;
    }
    preProcessEncryptedKey(encryptedKey, algorithm, kek);

    /**
     * ECDH Amendment. Main modification to support ECDH key agreement. This deploy function reconstructs the agreed key encryption key.
     */
    if (kek instanceof ECPrivateKey){
      // Replace the kek with the DH agreed key.
      kek = ECDHKeyAgreementBase.getECDHKeyAgreementKey(encryptedKey, kek);
    }

    final XMLCipher xmlCipher;
    try {
      if (getJCAProviderName() != null) {
        xmlCipher = XMLCipher.getProviderInstance(getJCAProviderName());
      } else {
        xmlCipher = XMLCipher.getInstance();
      }
      xmlCipher.init(XMLCipher.UNWRAP_MODE, kek);
    } catch (final XMLEncryptionException e) {
      log.error("Error initialzing cipher instance on key decryption", e);
      throw new DecryptionException("Error initialzing cipher instance on key decryption", e);
    }

    final org.apache.xml.security.encryption.EncryptedKey encKey;
    try {
      final Element targetElement = encryptedKey.getDOM();
      encKey = xmlCipher.loadEncryptedKey(targetElement.getOwnerDocument(), targetElement);
    } catch (final XMLEncryptionException e) {
      log.error("Error when loading library native encrypted key representation", e);
      throw new DecryptionException("Error when loading library native encrypted key representation", e);
    }

    try {
      final Key key = xmlCipher.decryptKey(encKey, algorithm);
      if (key == null) {
        throw new DecryptionException("Key could not be decrypted");
      }
      return key;
    } catch (final XMLEncryptionException e) {
      log.error("Error decrypting encrypted key", e);
      throw new DecryptionException("Error decrypting encrypted key", e);
    }  catch (final Exception e) {
      // Catch anything else, esp. unchecked RuntimeException, and convert to our checked type.
      // BouncyCastle in particular is known to throw unchecked exceptions for what we would
      // consider "routine" failures.
      throw new DecryptionException("Probable runtime exception on decryption:" + e.getMessage(), e);
    }
  }

}
