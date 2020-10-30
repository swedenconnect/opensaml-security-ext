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
package se.swedenconnect.opensaml.xmlsec.encryption.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import org.opensaml.xmlsec.encryption.OriginatorKeyInfo;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.ECKeyValue;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.DecodingException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.security.credential.KeyAgreementCredential;
import se.swedenconnect.opensaml.xmlsec.algorithm.descriptors.NamedCurve;
import se.swedenconnect.opensaml.xmlsec.algorithm.descriptors.NamedCurveRegistry;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * Support methods for performing ECDH key agreement.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECDHSupport {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ECDHSupport.class);

  /** The Object Identifier for an EC public key. */
  public static final String EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1";

  /**
   * Creates a {@link KeyAgreementCredential} by using the supplied peer credential to generate a EC key pair and a
   * secret key that is the key agreement key.
   * 
   * <p>
   * This method works only for the {@value EcEncryptionConstants#ALGO_ID_KEYDERIVATION_CONCAT} key derivation
   * algorithm.
   * </p>
   * 
   * @param peerCredential
   *          the peer credential (containing an EC public key)
   * @param keyWrappingAlgorithm
   *          the key wrapping algorithm
   * @param keyDerivationMethod
   *          the key derivation method parameters for the key derivation algorithm
   * @return a KeyAgreementCredential
   * @throws SecurityException
   *           for errors during the key generation process
   */
  public static KeyAgreementCredential createKeyAgreementCredential(Credential peerCredential,
      String keyWrappingAlgorithm, KeyDerivationMethod keyDerivationMethod) throws SecurityException {

    // Input checking ...
    //
    Constraint.isNotNull(peerCredential, "peerCredential must not be null");
    Constraint.isNotNull(peerCredential.getPublicKey(), "peerCredential must contain a public key");
    Constraint.isTrue(ECPublicKey.class.isInstance(peerCredential.getPublicKey()),
      "Public key of peerCredential must be an ECPublicKey");
    Constraint.isNotNull(keyWrappingAlgorithm, "keyWrappingAlgorithm must not be null");
    Constraint.isNotNull(keyDerivationMethod, "keyDerivationMethod must not be null");
    Constraint.isTrue(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT.equals(keyDerivationMethod.getAlgorithm()),
      String.format("{} key derivation method is not supported - {} is required", keyDerivationMethod.getAlgorithm(),
        EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT));

    final ConcatKDFParams concatKDFParams = keyDerivationMethod.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME)
      .stream()
      .map(ConcatKDFParams.class::cast)
      .findFirst()
      .orElse(null);

    Constraint.isNotNull(concatKDFParams, "ConcatKDF params is missing from KeyDerivationMethod");

    // Given the curve of the peer EC public key generate a EC key pair.
    //
    NamedCurve namedCurve = getNamedCurve((ECPublicKey) peerCredential.getPublicKey());
    if (namedCurve == null) {
      throw new SecurityException("Unsupported named curve in EC public key");
    }
    // TODO: We may want to check the key length so that it isn't too short...

    KeyPair generatedKeyPair = null;
    try {
      log.debug("Generating EC key pair for named curve {} ...", namedCurve.getName());
      ECNamedCurveGenParameterSpec parameterSpec = new ECNamedCurveGenParameterSpec(namedCurve.getName());
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
      kpg.initialize(parameterSpec);
      generatedKeyPair = kpg.generateKeyPair();
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      String msg = String.format("Failed to generate an EC key pair for curve %s - %s", namedCurve.getName(), e.getMessage());
      log.error("{}", msg, e);
      throw new SecurityException(msg, e);
    }

    // Generate the key agreement key ...
    //
    SecretKey keyAgreementKey = null;
    try {
      log.debug("Generating shared secret for ECDH key agreement ...");
      KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
      ka.init(generatedKeyPair.getPrivate());
      ka.doPhase(peerCredential.getPublicKey(), true);
      byte[] sharedSecret = ka.generateSecret();

      // Get JCA algorithm ID and key length given the key wrapping algorithm ...
      //
      String keyWrappingJcaAlgorithmId = AlgorithmSupport.getAlgorithmID(keyWrappingAlgorithm);
      if (keyWrappingAlgorithm == null) {
        String msg = String.format("Algorithm %s is not supported", keyWrappingAlgorithm);
        log.error(msg);
        throw new SecurityException(msg);
      }
      Integer keyWrappingKeySize = AlgorithmSupport.getKeyLength(keyWrappingAlgorithm);
      if (keyWrappingKeySize == null) {
        String msg = String.format("Unknown key size for algorithm %s - cannot proceed", keyWrappingAlgorithm);
        log.error(msg);
        throw new SecurityException(msg);
      }

      log.debug("Generating key agreement key ...");
      keyAgreementKey = generateKeyAgreementKey(sharedSecret, concatKDFParams, keyWrappingJcaAlgorithmId, keyWrappingKeySize);
    }
    catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
      String msg = "Failed to generate shared secret for ECDH key agreement";
      log.error("{}", msg, e);
      throw new SecurityException(msg, e);
    }

    // OK, we have everything for a KeyAgreementCredential ...
    //
    return new KeyAgreementCredential(keyAgreementKey, generatedKeyPair.getPublic(), peerCredential,
      EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES, keyDerivationMethod);
  }

  /**
   * Derives the ephemeral-static DH agreed key encryption key for a decryption process.
   * 
   * <p>
   * ECDH is used to calculate the shared secret.
   * </p>
   * <p>
   * The ConcatKDF key derivation function is assumed and required for constructing the derived key encryption key.
   * </p>
   * 
   * @param decrypterKey
   *          The private EC key of the decrypter
   * @param agreementMethod
   *          the {@code AgreementMethod} element
   * @param keyWrappingJcaAlgorithmId
   *          the JCA algorithm ID for the key wrapping method
   * @param keyWrappingKeySize
   *          the key size for the key wrapping algorithm
   * @return the key agreement key
   * @throws SecurityException
   *           for error during the process
   */
  public static SecretKey getKeyAgreementKey(PrivateKey decrypterKey, AgreementMethod agreementMethod,
      String keyWrappingJcaAlgorithmId, int keyWrappingKeySize) throws SecurityException {

    // Input checking ...
    Constraint.isNotNull(decrypterKey, "decrypterKey must not be null");
    Constraint.isNotNull(decrypterKey, "keyWrappingAlgorithm must not be null");
    Constraint.isNotNull(agreementMethod, "agreementMethod must not be null");

    try {

      if (!EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES.equals(agreementMethod.getAlgorithm())) {
        throw new SecurityException("Unsupported agreement method algorithm - " + agreementMethod.getAlgorithm());
      }
      List<XMLObject> kdms = agreementMethod.getUnknownXMLObjects(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
      if (kdms.isEmpty()) {
        throw new SecurityException("No KeyDerivationMethod element found under supplied AgreementMethod");
      }
      final KeyDerivationMethod keyDerivationMethod = KeyDerivationMethod.class.cast(kdms.get(0));

      if (!EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT.equals(keyDerivationMethod.getAlgorithm())) {
        throw new SecurityException("Unsupported key derivation method - " + keyDerivationMethod.getAlgorithm());
      }
      List<XMLObject> pars = keyDerivationMethod.getUnknownXMLObjects(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
      if (pars.isEmpty()) {
        throw new SecurityException("Missing ConcatKDFParams under KeyDerivation element");
      }
      ConcatKDFParams concatKDFParams = ConcatKDFParams.class.cast(pars.get(0));

      // We'll find the generated public key under OriginatorInfo.
      // Let's process it and get an EC public key object ...
      //
      if (agreementMethod.getOriginatorKeyInfo() == null) {
        throw new SecurityException("Missing OriginatorKeyInfo - need generated public key");
      }
      final OriginatorKeyInfo originatorKeyInfo = agreementMethod.getOriginatorKeyInfo();

      byte[] encodedPublicKey = null;

      if (!originatorKeyInfo.getKeyValues().isEmpty()) {
        ECKeyValue ecKeyValue = originatorKeyInfo.getKeyValues()
          .stream()
          .filter(v -> v.getECKeyValue() != null)
          .map(v -> v.getECKeyValue())
          .findFirst()
          .orElse(null);
        if (ecKeyValue != null) {
          encodedPublicKey = getPublicKeyBytes(
            Base64Support.decode(ecKeyValue.getPublicKey().getValue()), ecKeyValue.getNamedCurve().getURI());
        }
      }
      else if (!originatorKeyInfo.getDEREncodedKeyValues().isEmpty()) {
        // Assume only one key
        encodedPublicKey = Base64Support.decode(originatorKeyInfo.getDEREncodedKeyValues().get(0).getValue());
      }

      if (encodedPublicKey == null) {
        throw new SecurityException("Could not find generated public key in OriginatorKeyInfo");
      }

      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedPublicKey);
      PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

      // Next, generate the shared secret ...
      //
      KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
      ka.init(decrypterKey);
      ka.doPhase(publicKey, true);
      byte[] sharedSecret = ka.generateSecret();

      // And finally, generate the key agreement key.
      //
      return generateKeyAgreementKey(sharedSecret, concatKDFParams, keyWrappingJcaAlgorithmId, keyWrappingKeySize);
    }
    catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new SecurityException("Failed to generate key - " + e.getMessage(), e);
    }
    catch (InvalidKeyException e) {
      throw new SecurityException("Failed to generate shared secret", e);
    }
    catch (DecodingException e) {
      throw new SecurityException("Decoding error", e);
    }
  }

  /**
   * Generates an agreement key using the ConcatKDF key derivation algorithm.
   * 
   * @param sharedSecret
   *          the shared secret
   * @param concatKDFParams
   *          the parameters for the ConcatKDF operation
   * @param keyWrappingJcaAlgorithmId
   *          the JCA algorithm ID for the key wrapping method
   * @param keyWrappingKeySize
   *          the key size for the key wrapping algorithm
   * @return the secret key
   * @throws SecurityException
   *           for parameter and algorithm errors
   */
  private static SecretKey generateKeyAgreementKey(byte[] sharedSecret, ConcatKDFParams concatKDFParams,
      String keyWrappingJcaAlgorithmId, int keyWrappingKeySize) throws SecurityException {

    // Assert that ConcatKDFParams are correct ...
    //
    if (concatKDFParams.getDigestMethod() == null || concatKDFParams.getDigestMethod().getAlgorithm() == null) {
      throw new SecurityException("Missing digest method in ConcatKDFParams");
    }

    if (concatKDFParams.getAlgorithmID() == null) {
      throw new SecurityException("Missing AlgorithmID attribute from ConcatKDFParams");
    }
    if (concatKDFParams.getPartyUInfo() == null) {
      throw new SecurityException("Missing PartyUInfo attribute from ConcatKDFParams");
    }
    if (concatKDFParams.getPartyVInfo() == null) {
      throw new SecurityException("Missing PartyVInfo attribute from ConcatKDFParams");
    }

    // ConcatKDF key derivation
    //
    byte[] combinedConcatParams = Bytes.concat(
      extractConcatKDFParamVal(concatKDFParams.getAlgorithmID()), 
      extractConcatKDFParamVal(concatKDFParams.getPartyUInfo()), 
      extractConcatKDFParamVal(concatKDFParams.getPartyVInfo()));

    if (concatKDFParams.getSuppPubInfo() != null) {
      combinedConcatParams = Bytes.concat(combinedConcatParams, extractConcatKDFParamVal(concatKDFParams.getSuppPubInfo()));
    }
    if (concatKDFParams.getSuppPrivInfo() != null) {
      combinedConcatParams = Bytes.concat(combinedConcatParams, extractConcatKDFParamVal(concatKDFParams.getSuppPrivInfo()));
    }

    Digest digest = null;
    if (concatKDFParams.getDigestMethod().getAlgorithm().equals(EncryptionConstants.ALGO_ID_DIGEST_SHA256)) {
      digest = new SHA256Digest();
    }
    else if (concatKDFParams.getDigestMethod().getAlgorithm().equals(EncryptionConstants.ALGO_ID_DIGEST_SHA512)) {
      digest = new SHA512Digest();
    }
    else if (concatKDFParams.getDigestMethod().getAlgorithm().equals(SignatureConstants.ALGO_ID_DIGEST_SHA1)) {
      // Black-list checking should already have been done ...
      digest = new SHA1Digest();
    }
    else if (concatKDFParams.getDigestMethod().getAlgorithm().equals(SignatureConstants.ALGO_ID_DIGEST_SHA384)) {
      digest = new SHA384Digest();
    }
    else if (concatKDFParams.getDigestMethod().getAlgorithm().equals(EncryptionConstants.ALGO_ID_DIGEST_RIPEMD160)) {
      digest = new RIPEMD160Digest();
    }
    else {
      throw new SecurityException("ConcatKDFParams contains unsupported digest algorithm - "
          + concatKDFParams.getDigestMethod().getAlgorithm());
    }

    ConcatenationKDFGenerator concatKDF = new ConcatenationKDFGenerator(digest);
    KDFParameters kdfParams = new KDFParameters(sharedSecret, combinedConcatParams);
    concatKDF.init(kdfParams);

    int keyLength = keyWrappingKeySize / 8;
    byte[] rawKey = new byte[keyLength];
    concatKDF.generateBytes(rawKey, 0, keyLength);

    return new SecretKeySpec(rawKey, keyWrappingJcaAlgorithmId);
  }

  /**
   * Extract the unpadded ConcatKDF parameter value from a padded parameter (imported from XML representation).
   *
   * @param paddedParam
   *          the bytes of the padded parameter
   * @return extracted ConcatKDF parameter
   * @throws SecurityException
   *           if the parameter has illegal padding and the length of the un-padded value is not a multiple of 8 bits
   */
  private static byte[] extractConcatKDFParamVal(byte[] paddedParam) throws SecurityException {
    if (paddedParam == null) {
      // The value is absent. Return empty byte array
      return new byte[] {};
    }
    if (paddedParam.length == 0) {
      // The value is present with empty value. Return empty byte array
      return new byte[] {};
    }
    // Reaching this point meant that a padded value is present. This must be a multiple of 8 bits = has 0 or 8 padding
    // bits.
    if (paddedParam[0] == 0x08 && paddedParam.length > 1) {
      // The value has 8 padding bits. Remove the padding byte and the byte with 8 padding bits.
      // This should never happen, but is implemented so it can be handled if received. The appropriate representation
      // is to use 0 padding bits, not 8.
      return Arrays.copyOfRange(paddedParam, 2, paddedParam.length);
    }
    if (paddedParam[0] != 0x00) {
      // A padding value other than 8 or 0 is encountered. This is an error since we can only handle byte values.
      throw new IllegalArgumentException("Unsupported use of padding bits in ConcatKDF parameters");
    }
    // Return the up-padded value. In this case we know the padding byte has the value 0x00 (0 padding bits), so we
    // remove the padding byte and keep rest.
    return Arrays.copyOfRange(paddedParam, 1, paddedParam.length);
  }

  /**
   * The XML representation of a public EC key is the Object Identifier of the named curve and the byte representation
   * of the public EC point on the named curve. The function reconstructs the public key ASN.1 representation of the EC
   * public key based on the curve OID and public EC point data.
   * <p>
   * Note: the {@code curveOidUri} parameter should be the URI representation of the named curve Object Identifier, i.e.
   * {@code urn:oid:1.2.840.10045.3.1.7}. However, to cover for bugs in other implementations, the method also handles
   * the cases where the plain OID is passed, i.e. {@code 1.2.840.10045.3.1.7}.
   * </p>
   *
   * @param publicKeyBytes
   *          the byte representation of the public EC point
   * @param curveOidUri
   *          the URI for the named curve OID
   * @return bytes of the ASN.1 representation of the public key
   * @throws SecurityException
   *           ASN.1 errors
   */
  private static byte[] getPublicKeyBytes(byte[] publicKeyBytes, String curveOidUri) throws SecurityException {

    ASN1EncodableVector publicKeyParamSeq = new ASN1EncodableVector();
    publicKeyParamSeq.add(new ASN1ObjectIdentifier(EC_PUBLIC_KEY_OID));

    String oid = curveOidUri.startsWith("urn:oid:") ? curveOidUri.substring(8) : curveOidUri;

    publicKeyParamSeq.add(new ASN1ObjectIdentifier(oid));

    ASN1EncodableVector publicKeySeq = new ASN1EncodableVector();
    publicKeySeq.add(new DERSequence(publicKeyParamSeq));
    publicKeySeq.add(new DERBitString(publicKeyBytes));

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    // DEROutputStream is deprecated in Bouncy Castle 1.63, but if we change to 
    // ASN1OutputStream.create(OutputStream, String) as suggested in 1.63, it won't 
    // work for older versions of BC since this method does not exist.    
    @SuppressWarnings("deprecation")
    ASN1OutputStream dout = new org.bouncycastle.asn1.DEROutputStream(bout);
    try {
      dout.writeObject(new DERSequence(publicKeySeq));
      return bout.toByteArray();
    }
    catch (IOException e) {
      throw new SecurityException("Failed to get EC public key bytes", e);
    }
    finally {
      try {
        dout.close();
        bout.close();
      }
      catch (IOException e) {
      }
    }
  }
  
  /**
   * Given a EC public key its named curve is returned.
   * 
   * @param publicKey
   *          the public key
   * @return the named curve, or {@code null} if the curve is not supported
   */
  public static NamedCurve getNamedCurve(ECPublicKey publicKey) {
    try {
      ASN1StreamParser parser = new ASN1StreamParser(publicKey.getEncoded());
      ASN1Sequence seq = (ASN1Sequence) parser.readObject().toASN1Primitive();
      ASN1Sequence innerSeq = (ASN1Sequence) seq.getObjectAt(0).toASN1Primitive();
      ASN1ObjectIdentifier ecPubKeyoid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(0).toASN1Primitive();
      if (!ecPubKeyoid.getId().equals(EC_PUBLIC_KEY_OID)) {
        log.error("The provided public key with key type OID {} is not a valid EC public key", ecPubKeyoid.getId());
        return null;
      }
      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(1).toASN1Primitive();
      log.debug("Asking NamedCurveRegistry for curve having OID {} ...", oid);
      NamedCurveRegistry registry = ConfigurationService.get(NamedCurveRegistry.class);
      if (registry == null) {
        throw new RuntimeException("NamedCurveRegistry is not available");
      }
      NamedCurve curve = registry.get(oid.getId());
      if (curve != null) {
        log.debug("Looked up NamedCurve {} ({}) (keyLength:{})", curve.getObjectIdentifier(), curve.getName(), curve.getKeyLength());
        return curve;
      }
      else {
        log.debug("NamedCurve with OID {} was not found in the NamedCurveRegistry", oid.getId());
        return null;
      }
    }
    catch (NullPointerException | IOException e) {
      log.error("Unable to parse the provided public key as an EC public key based on a named EC curve", e);
      return null;
    }
  }

}
