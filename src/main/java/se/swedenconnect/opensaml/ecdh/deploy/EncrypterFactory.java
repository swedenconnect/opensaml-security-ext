package se.swedenconnect.opensaml.ecdh.deploy;

import org.bouncycastle.util.encoders.Base64;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.support.*;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;

import se.swedenconnect.opensaml.security.credential.ECDHPeerCredential;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHKeyAgreementBase;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ExtendedDecrypter;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ExtendedEncrypter;

import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Factory class to obtain a suitable {@link Encrypter} or {@link Decrypter} and with ECDH support
 */
public class EncrypterFactory {

  /** The xml encrypt model {@link XmlEncryptModel} */
  private XmlEncryptModel defaultModel;

  /**
   * Constructor for setting up factory with specific default xml encryption parameters.
   * 
   * @param defaultModel
   */
  public EncrypterFactory(XmlEncryptModel defaultModel) {
    this.defaultModel = defaultModel;
  }

  /**
   * Constructor for setting up factory with default xml encryption parameters in {@link XmlEncryptModel}.
   */
  public EncrypterFactory() {
    this.defaultModel = new XmlEncryptModel();
  }

  /**
   * Obtains an encrypter for a specific recipient certificate holding the recipients public key using hte factory's
   * default xml encryption parameters.
   * 
   * @param receiverCertificate
   *          Recipient public key certificate
   * @return {@link ExtendedEncrypter} with ECDH capabilities
   * @throws KeyException
   *           key exception
   * @throws NoSuchAlgorithmException
   *           no such algotithm
   * @throws IllegalArgumentException
   *           illegal argument
   */
  public Encrypter getEncrypter(java.security.cert.X509Certificate receiverCertificate) throws KeyException, NoSuchAlgorithmException,
      IllegalArgumentException {
    return getEncrypter(receiverCertificate, defaultModel);
  }

  /**
   * Obtains an encrypter for a specific recipient certificate holding the recipients public key.
   * 
   * @param receiverCertificate
   *          Recipient public key certificate
   * @param xmlEncryptModel
   *          overrides the default xml encryption model with specific encryption parameters
   * @return {@link ExtendedEncrypter} with ECDH capabilities
   * @throws KeyException
   *           key exception
   * @throws NoSuchAlgorithmException
   *           no such algotithm
   * @throws IllegalArgumentException
   *           illegal argument
   */
  public Encrypter getEncrypter(java.security.cert.X509Certificate receiverCertificate, XmlEncryptModel xmlEncryptModel)
      throws KeyException, NoSuchAlgorithmException, IllegalArgumentException {
    if (xmlEncryptModel == null) {
      xmlEncryptModel = defaultModel;
    }

    // Extract the receiver credential from certificate
    Credential receiverCredential = "EC".equals(receiverCertificate.getPublicKey().getAlgorithm()) ? new ECDHPeerCredential(
      receiverCertificate)
        : CredentialSupport.getSimpleCredential(receiverCertificate, null);
    // Generate symmetric key for data encryption
    Credential symmetricCredential = CredentialSupport.getSimpleCredential(
      AlgorithmSupport.generateSymmetricKey(xmlEncryptModel.getDataEncryptionAlgo()));
    // Define data encryption parameters
    DataEncryptionParameters encParams = new DataEncryptionParameters();
    encParams.setAlgorithm(xmlEncryptModel.getDataEncryptionAlgo());
    encParams.setEncryptionCredential(symmetricCredential);

    // Setup key encryption parameters
    KeyEncryptionParameters kek = new KeyEncryptionParameters();
    if (receiverCredential instanceof ECDHPeerCredential) {
      // Recipient public key is EC. Setup ECDH parameters
      ECDHKeyAgreementBase.prepareBasicKeyAgreementParameters((ECDHPeerCredential) receiverCredential, xmlEncryptModel.getConcatKDFHash());
      kek.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);
    }
    else {
      // Recipient public key is RSA. Setup RSA OAEP parameters
      RSAOAEPParameters rsaoaepParameters = new RSAOAEPParameters();
      if (xmlEncryptModel.getMgf() == null) {
        kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
      }
      else {
        kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11);
        rsaoaepParameters.setMaskGenerationFunction(xmlEncryptModel.getMgf());
      }
      rsaoaepParameters.setDigestMethod(xmlEncryptModel.getOaepDigestMethod());
      String oaepParameter = xmlEncryptModel.getOaepParameter();
      if (oaepParameter != null && oaepParameter.trim().length() > 0) {
        rsaoaepParameters.setOAEPparams(Base64.toBase64String(oaepParameter.getBytes(StandardCharsets.UTF_8)));
      }
      kek.setRSAOAEPParameters(rsaoaepParameters);
    }
    // Set Key info builder based on receiver credential.
    KeyInfoGeneratorFactory kigf = ConfigurationService.get(EncryptionConfiguration.class)
      .getKeyTransportKeyInfoGeneratorManager()
      .getDefaultManager()
      .getFactory(receiverCredential);
    kek.setKeyInfoGenerator(kigf.newInstance());
    kek.setEncryptionCredential(receiverCredential);

    // Encrypt
    Encrypter encrypter = new ExtendedEncrypter(encParams, kek);
    encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
    return encrypter;
  }

  public Decrypter getDecrypter(Credential receiverCredential) {
    return getDecrypter(Arrays.asList(receiverCredential));
  }

  /**
   * Obtains an ECDH capable decrypter for a specific list of decryption credentials
   * 
   * @param receiverCredentials
   *          list of decryption credentials
   * @return {@link ExtendedDecrypter}
   */
  public Decrypter getDecrypter(List<Credential> receiverCredentials) {
    KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(receiverCredentials);
    ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(Arrays.asList(
      new InlineEncryptedKeyResolver(),
      new EncryptedElementTypeEncryptedKeyResolver(),
      new SimpleRetrievalMethodEncryptedKeyResolver()));
    Decrypter decrypter = new ExtendedDecrypter(null, keyResolver, encryptedKeyResolver);
    return decrypter;
  }

}
