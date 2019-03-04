package se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support;

import com.google.common.primitives.Bytes;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import se.swedenconnect.opensaml.ecdh.security.x509.ECDHCredential;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.*;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for ECDH key agreement operations
 *
 * @author stefan@idsec.com
 */
public class ECDHKeyAgreementBase {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ECDHKeyAgreementBase.class);

  /**
   * This function derives the ephemeral-static DH agreed key encryption key for the encryption process
   * <p>ECDH is used to calculate the shared secret</p>
   * <p>The ConcatKDF key derivation function is assumed and required for constructing the derived key encryption key</p>
   *
   * @param kekParams The key encryption parameters provided for encryption
   * @param encryptionKey The key extracted from kekParams which is to be used as the public encryption key
   * @return Agreed key encryption key
   * @throws IllegalArgumentException
   */
  public static Key getECDHKeyAgreementKey(KeyEncryptionParameters kekParams, Key encryptionKey, String keyWrapMethod) throws IllegalArgumentException {
    try {
      ECDHCredential cred = (ECDHCredential) kekParams.getEncryptionCredential();
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
      ECNamedCurveGenParameterSpec parameterSpec = getNamedCurveSpec((ECPublicKey) encryptionKey, 256);
      kpg.initialize(parameterSpec);
      KeyPair tempKeyPair = kpg.generateKeyPair();
      cred.setSenderPubKey(tempKeyPair.getPublic());

      KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
      ka.init(tempKeyPair.getPrivate());
      ka.doPhase(encryptionKey, true);
      byte[] sharedSecret = ka.generateSecret();

      ConcatKDFParams concatKDFParams = cred.getConcatKDF();

      return getAgreedKey(sharedSecret, keyWrapMethod, concatKDFParams);

    } catch (Exception e) {
      log.debug("Unable to generate key agreement key based on provided parameters. Exception: {}", e.getMessage());
      throw new IllegalArgumentException("Unable to generate key agreement key based on provided parameters");
    }
  }
  /**
   * This function derives the ephemeral-static DH agreed key encryption key for the decryption process
   * <p>ECDH is used to calculate the shared secret</p>
   * <p>The ConcatKDF key derivation function is assumed and required for constructing the derived key encryption key</p>
   *
   * @param encryptedKey The EncryptedKey XML object
   * @param kek          The private EC key of the recipient
   * @return Agreed key encryption key
   * @throws IllegalArgumentException
   */
  public static Key getECDHKeyAgreementKey(EncryptedKey encryptedKey, Key kek) throws IllegalArgumentException {

    try {
      EncryptionMethod encryptionMethod = encryptedKey.getEncryptionMethod();
      String keyWrapMethod = encryptionMethod.getAlgorithm(); // Expected http://www.w3.org/2001/04/xmlenc#kw-aes256
      KeyInfo keyInfo = encryptedKey.getKeyInfo();
      AgreementMethod agreementMethod = keyInfo.getAgreementMethods().get(0);
      KeyDerivationMethod keyDerivationMethod = (KeyDerivationMethod) agreementMethod.getUnknownXMLObjects(
        KeyDerivationMethod.DEFAULT_ELEMENT_NAME).get(0);
      String keyDerivationAlgo = keyDerivationMethod.getAlgorithm(); // http://www.w3.org/2009/xmlenc11#ConcatKDF
      if (!keyDerivationAlgo.equalsIgnoreCase(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT)) {
        log.debug("The specified key derivation function is not supported {}. This must be http://www.w3.org/2009/xmlenc11#ConcatKDF", keyDerivationAlgo);
        throw new IllegalArgumentException("Unsupported key derivation function");
      }

      ConcatKDFParams concatKDFParams = (ConcatKDFParams) keyDerivationMethod.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME)
        .get(0);

      OriginatorKeyInfo originatorKeyInfo = agreementMethod.getOriginatorKeyInfo();
      KeyValue keyValue = originatorKeyInfo.getKeyValues().get(0);
      ECKeyValue ecKeyValue = keyValue.getECKeyValue();
      byte[] publicKeyBytes = Base64.getDecoder().decode(ecKeyValue.getPublicKey().getValue());
      byte[] ans1PubKeyBytes = getPublicKeyBytes(publicKeyBytes, ecKeyValue.getNamedCurve().getURI());

      //Extract the public key from bytes
      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ans1PubKeyBytes);
      PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

      //Generate shared secret
      KeyAgreement ka = null;
      ka = KeyAgreement.getInstance("ECDH", "BC");
      ka.init(kek);
      ka.doPhase(publicKey, true);
      byte[] sharedSecret = ka.generateSecret();

      return getAgreedKey(sharedSecret, keyWrapMethod, concatKDFParams);
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Illegal or unsupported parameters for ECDH key agreement");
    }
  }

  private static Key getAgreedKey(byte[] sharedSecret, String keyWrapMethod, ConcatKDFParams concatKDFParams) {

    String digestMethodUri = concatKDFParams.getDigestMethod().getAlgorithm();
    byte[] algorithmID = concatKDFParams.getAlgorithmID();
    byte[] partyUInfo = concatKDFParams.getPartyUInfo();
    byte[] partyVInfo = concatKDFParams.getPartyVInfo();
    byte[] suppPubInfo = concatKDFParams.getSuppPubInfo();
    byte[] suppPrivInfo = concatKDFParams.getSuppPrivInfo();

    int keyLength = AlgorithmSupport.getKeyLength(keyWrapMethod) / 8;
    byte[] rawKey = new byte[keyLength];

    byte[] combinedConcatParams = Bytes.concat(algorithmID, partyUInfo, partyVInfo);
    if (suppPubInfo != null) {
      combinedConcatParams = Bytes.concat(combinedConcatParams, suppPubInfo);
    }
    if (suppPrivInfo != null) {
      combinedConcatParams = Bytes.concat(combinedConcatParams, suppPrivInfo);
    }

    Digest dig = null;
    switch (digestMethodUri) {
    case EncryptionConstants.ALGO_ID_DIGEST_SHA256:
      dig = new SHA256Digest();
      break;
    case EncryptionConstants.ALGO_ID_DIGEST_SHA512:
      dig = new SHA512Digest();
      break;
    }

    ConcatenationKDFGenerator concatKDF = new ConcatenationKDFGenerator(dig);
    KDFParameters kdfParams = new KDFParameters(sharedSecret, combinedConcatParams);
    concatKDF.init(kdfParams);
    concatKDF.generateBytes(rawKey, 0, keyLength);
    Key agreedKey = new SecretKeySpec(rawKey, AlgorithmSupport.getKeyAlgorithm(keyWrapMethod));
    return agreedKey;
  }


  /**
   * The XML representation of a public EC key is the oid of the named curve and the byte representation of the public EC point on the named curve.
   * The function reconstructs the public key ASN.1 representation of the EC public key based on the curve OID and public EC point data.
   *
   * @param publicKeyBytes the byte representation of the public EC point
   * @param curveOidStr    the string representation of the named curve OID
   * @return bytes of the ASN.1 representation of the public key.
   * @throws IOException
   */
  private static byte[] getPublicKeyBytes(byte[] publicKeyBytes, String curveOidStr) throws IOException {
    ASN1EncodableVector publicKeySeq = new ASN1EncodableVector();
    ASN1EncodableVector publicKeyParamSeq = new ASN1EncodableVector();
    ASN1ObjectIdentifier ecPublicKeyOid = new ASN1ObjectIdentifier("1.2.840.10045.2.1");
    ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(curveOidStr);
    publicKeyParamSeq.add(ecPublicKeyOid);
    publicKeyParamSeq.add(curveOid);
    publicKeySeq.add(new DERSequence(publicKeyParamSeq));
    publicKeySeq.add(new DERBitString(publicKeyBytes));

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    DEROutputStream dout = new DEROutputStream(bout);
    dout.writeObject((new DERSequence(publicKeySeq)));
    byte[] publicKeyAsn1Bytes = bout.toByteArray();
    dout.close();
    bout.close();
    return publicKeyAsn1Bytes;
  }

  /**
   * Determines the named curve contained in an EC public key
   * @param ecPubKey EC public key
   * @return the named curve parameter spec
   * @throws IllegalArgumentException if the provided public key is not a suitable EC public key with a defined named curve
   */
  public static ECNamedCurveGenParameterSpec getNamedCurveSpec(PublicKey ecPubKey, int minLen) throws IllegalArgumentException{
    ASN1StreamParser parser = new ASN1StreamParser(ecPubKey.getEncoded());
    try {
      DERSequence seq = (DERSequence) parser.readObject().toASN1Primitive();
      DERSequence innerSeq = (DERSequence) seq.getObjectAt(0).toASN1Primitive();
      ASN1ObjectIdentifier ecPubKeyoid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(0).toASN1Primitive();
      if (!ecPubKeyoid.getId().equalsIgnoreCase("1.2.840.10045.2.1")){
        log.debug("The provided public key with key type oid {} is not an EC public key", ecPubKeyoid.getId());
        throw new IllegalArgumentException("The provided public key is not an EC public key");
      }
      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(1).toASN1Primitive();
      NamedEcCurve namedEcCurve = NamedEcCurve.getCurveByOid(oid.getId(), minLen);
      if (namedEcCurve == null){
        log.debug("The provided public EC key with named curve oid {} does not specify a supported named EC curve", oid.getId());
        throw new IllegalArgumentException("The provided public EC key does not specify a supported named EC curve");
      }
      return new ECNamedCurveGenParameterSpec(namedEcCurve.name());
    } catch (Exception e) {
      throw new IllegalArgumentException("Unable to parse the provided public key as an EC public key based on a named EC curve");
    }

  }

  /**
   * Builds an {@link ECKeyValue} XMLObject from the Java security EC public key type.
   *
   * @param ecPubKey a native Java {@link ECPublicKey}
   * @return an {@link ECKeyValue} XMLObject
   */
  @Nonnull public static ECKeyValue buildECKeyValue(@Nonnull final ECPublicKey ecPubKey) {
    Constraint.isNotNull(ecPubKey, "EC public key cannot be null");

    final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

    final XMLObjectBuilder<ECKeyValue> ecKeyValueBuilder =
      (XMLObjectBuilder<ECKeyValue>) builderFactory.getBuilder(ECKeyValue.DEFAULT_ELEMENT_NAME);
    final ECKeyValue ecKeyValue = Constraint.isNotNull(ecKeyValueBuilder, "ECKeyValue builder not available")
      .buildObject(ECKeyValue.DEFAULT_ELEMENT_NAME);

    final XMLObjectBuilder<NamedCurve> namedCurveBuilder =
      (XMLObjectBuilder<NamedCurve>) builderFactory.getBuilder(NamedCurve.DEFAULT_ELEMENT_NAME);
    final NamedCurve namedCurve = Constraint.isNotNull(namedCurveBuilder, "NamedCurve builder not available")
      .buildObject(NamedCurve.DEFAULT_ELEMENT_NAME);

    final XMLObjectBuilder<org.opensaml.xmlsec.signature.PublicKey> publicKeyBuilder =
      (XMLObjectBuilder<org.opensaml.xmlsec.signature.PublicKey>) builderFactory
        .getBuilder(org.opensaml.xmlsec.signature.PublicKey.DEFAULT_ELEMENT_NAME);
    final org.opensaml.xmlsec.signature.PublicKey publicKey =
      Constraint.isNotNull(publicKeyBuilder, "PublicKey builder not available")
        .buildObject(org.opensaml.xmlsec.signature.PublicKey.DEFAULT_ELEMENT_NAME);

    ASN1StreamParser parser = new ASN1StreamParser(ecPubKey.getEncoded());
    try {
      DERSequence seq = (DERSequence) parser.readObject().toASN1Primitive();
      DERSequence innerSeq = (DERSequence) seq.getObjectAt(0).toASN1Primitive();
      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(1).toASN1Primitive();
      DERBitString key = (DERBitString) seq.getObjectAt(1).toASN1Primitive();

      namedCurve.setURI(oid.getId());
      publicKey.setValue(Base64.getEncoder().encodeToString(key.getBytes()));
    } catch (IOException e) {
      log.error("Illegal Public key paramters");
      throw new IllegalArgumentException("Illegal Public key paramters");
    }

    ecKeyValue.setNamedCurve(namedCurve);
    ecKeyValue.setPublicKey(publicKey);

    return ecKeyValue;
  }

  /**
   * Prepares the ECDH receiver credential with parameters for ECDH encryption
   *
   * <p>This sets up the concatKDF parameters ans the ECDH parameters in the credential</p>
   *
   * <p>The reason the ECDH parameters are added to the </p>
   *
   * @param receiverCredential Public key credentials of the receiver
   * @param hashAlgo The selected digestMethod algorithm.
   */
  public static void prepareBasicKeyAgreementParameters(ECDHCredential receiverCredential, SupportedConcatKDFHash hashAlgo){
    ConcatKDFParams concatKDFParams = createSamlObject(ConcatKDFParams.class, ConcatKDFParams.DEFAULT_ELEMENT_NAME);
    concatKDFParams.setAlgorithmID(new byte[1]);
    concatKDFParams.setPartyUInfo(new byte[0]);
    concatKDFParams.setPartyVInfo(new byte[0]);
    DigestMethod digestMethod = createSamlObject(DigestMethod.class, DigestMethod.DEFAULT_ELEMENT_NAME);
    digestMethod.setAlgorithm(hashAlgo.getId());
    concatKDFParams.setDigestMethod(digestMethod);
    receiverCredential.setConcatKDF(concatKDFParams);
    ECDHParameters ecdhParams = new ECDHParameters();
    ecdhParams.setKeyWrapMethod(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
    receiverCredential.setEcdhParameters(ecdhParams);
  }

  /**
   * Utility method for creating an OpenSAML object given its element name.
   *
   * @param clazz the class to create
   * @param elementName the element name for the XML object to create
   * @return the XML object
   */
  private static <T extends XMLObject> T createSamlObject(Class<T> clazz, QName elementName) {
    if (!XMLObject.class.isAssignableFrom(clazz)) {
      throw new RuntimeException(String.format("%s is not a XMLObject class", clazz.getName()));
    }
    XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    XMLObjectBuilder<? extends XMLObject> builder = builderFactory.getBuilder(elementName);
    if (builder == null) {
      // No builder registered for the given element name. Try creating a builder for the default element name.
      builder = builderFactory.getBuilder(getDefaultElementName(clazz));
    }
    Object object = builder.buildObject(elementName);
    return clazz.cast(object);
  }

  /**
   * Returns the default element name for the supplied class
   *
   * @param clazz class to check
   * @return the default QName
   */
  private static <T extends XMLObject> QName getDefaultElementName(Class<T> clazz) {
    try {
      return (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
    } catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException | SecurityException e) {
      throw new RuntimeException(e);
    }
  }



}
