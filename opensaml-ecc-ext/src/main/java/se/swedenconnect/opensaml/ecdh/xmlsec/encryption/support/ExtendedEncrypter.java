package se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support;

import com.google.common.base.Strings;
import se.swedenconnect.opensaml.ecdh.security.x509.ECDHCredential;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Key;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class ExtendedEncrypter extends org.opensaml.saml.saml2.encryption.Encrypter {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ExtendedDecrypter.class);

  public ExtendedEncrypter(DataEncryptionParameters dataEncParams,
    List<KeyEncryptionParameters> keyEncParams) {
    super(dataEncParams, keyEncParams);
  }

  public ExtendedEncrypter(DataEncryptionParameters dataEncParams, KeyEncryptionParameters keyEncParam) {
    super(dataEncParams, keyEncParam);
  }

  public ExtendedEncrypter(DataEncryptionParameters dataEncParams) {
    super(dataEncParams);
  }

  /**
   * Encrypts a key.
   *
   * @param key the key to encrypt
   * @param kekParams parameters for encrypting the key
   * @param containingDocument the document that will own the DOM element underlying the resulting EncryptedKey object
   *
   * @return the resulting EncryptedKey object
   *
   * @throws EncryptionException exception thrown on encryption errors
   */
  @Override
  @Nonnull public EncryptedKey encryptKey(@Nonnull final Key key, @Nonnull final KeyEncryptionParameters kekParams,
    @Nonnull final Document containingDocument) throws EncryptionException {

    checkParams(kekParams, false);

    final Key encryptionKey = CredentialSupport.extractEncryptionKey(kekParams.getEncryptionCredential());

    /**
     * ECDH Amendment. If the key is ECDH then generate agreed key and use it to generate the encrypted key.
     */
    EncryptedKey encryptedKey;
    if (encryptionKey instanceof ECPublicKey
      && EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES.equals(kekParams.getAlgorithm())) {
      try {
        ECDHParameters ecdhParameters = ((ECDHCredential) kekParams.getEncryptionCredential()).getEcdhParameters();
        String keyWrapMethod = ecdhParameters.getKeyWrapMethod();
        Key keyAgreementKey = ECDHKeyAgreementBase.getECDHKeyAgreementKey(kekParams, encryptionKey, keyWrapMethod);
        encryptedKey = encryptKey(key, keyAgreementKey, keyWrapMethod, null, containingDocument);
      } catch (Exception ex){
        throw new EncryptionException(ex.getMessage());
      }
    } else {
      encryptedKey = encryptKey(key, encryptionKey, kekParams.getAlgorithm(), kekParams.getRSAOAEPParameters(), containingDocument);
    }


    if (kekParams.getKeyInfoGenerator() != null) {
      final KeyInfoGenerator generator = kekParams.getKeyInfoGenerator();
      log.debug("Dynamically generating KeyInfo from Credential for EncryptedKey using generator: {}", generator
        .getClass().getName());
      try {
        encryptedKey.setKeyInfo(generator.generate(kekParams.getEncryptionCredential()));
      } catch (final SecurityException e) {
        log.error("Error during EncryptedKey KeyInfo generation", e);
        throw new EncryptionException("Error during EncryptedKey KeyInfo generation", e);
      }
    }

    if (kekParams.getRecipient() != null) {
      encryptedKey.setRecipient(kekParams.getRecipient());
    }

    return encryptedKey;
  }


  /**
   * Check key encryption parameters for consistency and required values.
   *
   * @param kekParams the key encryption parameters to check
   * @param allowEmpty if false, a null parameter is treated as an error
   *
   * @throws EncryptionException thrown if any parameters are missing or have invalid values
   */
  @Override
  protected void checkParams(@Nullable final KeyEncryptionParameters kekParams, final boolean allowEmpty)
    throws EncryptionException {
    if (kekParams == null) {
      if (allowEmpty) {
        return;
      } else {
        log.error("Key encryption parameters are required");
        throw new EncryptionException("Key encryption parameters are required");
      }
    }
    final Key key = CredentialSupport.extractEncryptionKey(kekParams.getEncryptionCredential());
    if (key == null) {
      log.error("Key encryption credential and contained key are required");
      throw new EncryptionException("Key encryption credential and contained key are required");
    } else if (key instanceof DSAPublicKey) {
      log.error("Attempt made to use DSA key for encrypted key transport");
      throw new EncryptionException("DSA keys may not be used for encrypted key transport");
    } else if (key instanceof ECPublicKey
      && !EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES.equals(kekParams.getAlgorithm())) {
      /**
       * ECDH Amendment. We do allow EC key if the algorithm is ECDH.
       */
      log.error("Attempt made to use EC key for encrypted key transport");
      throw new EncryptionException("EC keys may not be used for encrypted key transport");
    } else if (Strings.isNullOrEmpty(kekParams.getAlgorithm())) {
      log.error("Key encryption algorithm URI is required");
      throw new EncryptionException("Key encryption algorithm URI is required");
    }
  }

}
