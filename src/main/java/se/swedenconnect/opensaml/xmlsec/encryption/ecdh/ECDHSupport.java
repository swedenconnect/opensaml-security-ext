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
package se.swedenconnect.opensaml.xmlsec.encryption.ecdh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import org.opensaml.xmlsec.encryption.OriginatorKeyInfo;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.ECKeyValue;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import com.google.common.primitives.Bytes;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * Support methods for performing ECDH key agreement.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECDHSupport {

  /** The Object Identifier for an EC public key. */
  public static final String EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1";

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
   * @param keyWrappingAlgorithm
   *          the key wrapping method to use
   * @param agreementMethod
   *          the {@code AgreementMethod} element
   * @return the key agreement key
   * @throws SecurityException
   *           for error during the process
   */
  public static SecretKey getKeyAgreementKey(
      PrivateKey decrypterKey, String keyWrappingAlgorithm, AgreementMethod agreementMethod) throws SecurityException {

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

      if (originatorKeyInfo.getKeyValues().isEmpty() || originatorKeyInfo.getKeyValues().get(0).getECKeyValue() == null) {
        throw new SecurityException("Missing KeyValue under OriginatorKeyInfo - need generated EC public key");
      }
      final ECKeyValue ecKeyValue = originatorKeyInfo.getKeyValues().get(0).getECKeyValue();

      byte[] publicKeyBytes = Base64.getDecoder().decode(ecKeyValue.getPublicKey().getValue());
      byte[] ans1PubKeyBytes = getPublicKeyBytes(publicKeyBytes, ecKeyValue.getNamedCurve().getURI());

      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ans1PubKeyBytes);
      PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

      // Next, generate the shared secret ...
      //
      KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
      ka.init(decrypterKey);
      ka.doPhase(publicKey, true);
      byte[] sharedSecret = ka.generateSecret();

      // And finally, generate the key agreement key.
      //
      return generateKeyAgreementKey(sharedSecret, keyWrappingAlgorithm, concatKDFParams);
    }
    catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new SecurityException("Failed to generate key - " + e.getMessage(), e);
    }
    catch (InvalidKeyException e) {
      throw new SecurityException("Failed to generate shared secret", e);
    }
  }

  /**
   * Generates an agreement key using the ConcatKDF key derivation algorithm.
   * 
   * @param sharedSecret
   *          the shared secret
   * @param keyWrappingAlgorithm
   *          the key wrapping method
   * @param concatKDFParams
   *          the parameters for the ConcatKDF operation
   * @return the secret key
   * @throws SecurityException
   *           for parameter and algorithm errors
   */
  private static SecretKey generateKeyAgreementKey(byte[] sharedSecret, String keyWrappingAlgorithm, ConcatKDFParams concatKDFParams)
      throws SecurityException {

    // Assert that ConcatKDFParams are correct ...
    //
    if (concatKDFParams.getDigestMethod() == null || concatKDFParams.getDigestMethod().getAlgorithm() == null) {
      throw new SecurityException("Missing digest method in ConcatKDFParams");
    }

    if (concatKDFParams.getAlgorithmID() == null) {
      throw new SecurityException("Missing AlgorithmID attribute from ConcatKDFParams");
    }
    else if (concatKDFParams.getAlgorithmID().length < 2) {
      throw new SecurityException("Illegal value for AlgorithmID attribute in ConcatKDFParams");
    }

    if (concatKDFParams.getPartyUInfo() == null) {
      throw new SecurityException("Missing PartyUInfo attribute from ConcatKDFParams");
    }
    else if (concatKDFParams.getPartyUInfo().length < 2) {
      throw new SecurityException("Illegal value for PartyUInfo attribute in ConcatKDFParams");
    }

    if (concatKDFParams.getPartyVInfo() == null) {
      throw new SecurityException("Missing PartyVInfo attribute from ConcatKDFParams");
    }
    else if (concatKDFParams.getPartyVInfo().length < 2) {
      throw new SecurityException("Illegal value for PartyVInfo attribute in ConcatKDFParams");
    }

    // Algorithm checks ...
    //
    String jcaAlgorithm = AlgorithmSupport.getKeyAlgorithm(keyWrappingAlgorithm);
    if (jcaAlgorithm == null) {
      throw new SecurityException("Algorithm " + keyWrappingAlgorithm + " is not supported - could not find JCA algorithm");
    }
    Integer keyWrappingAlgorithmLength = AlgorithmSupport.getKeyLength(keyWrappingAlgorithm);
    if (keyWrappingAlgorithm == null) {
      throw new SecurityException("Algorithm " + keyWrappingAlgorithm + " is not supported - no key length info available");
    }

    // ConcatKDF key derivation
    //
    byte[] combinedConcatParams = Bytes.concat(
      concatKDFParams.getAlgorithmID(), concatKDFParams.getPartyUInfo(), concatKDFParams.getPartyVInfo());

    if (concatKDFParams.getSuppPubInfo() != null) {
      combinedConcatParams = Bytes.concat(combinedConcatParams, concatKDFParams.getSuppPubInfo());
    }
    if (concatKDFParams.getSuppPrivInfo() != null) {
      combinedConcatParams = Bytes.concat(combinedConcatParams, concatKDFParams.getSuppPrivInfo());
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
    else if (concatKDFParams.getDigestMethod().getAlgorithm().equals(EncryptionConstants.XMLENC_NS + "sha384")) {
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

    int keyLength = keyWrappingAlgorithmLength / 8;
    byte[] rawKey = new byte[keyLength];
    concatKDF.generateBytes(rawKey, 0, keyLength);

    return new SecretKeySpec(rawKey, jcaAlgorithm);
  }

  /**
   * The XML representation of a public EC key is the Object Identifier of the named curve and the byte representation
   * of the public EC point on the named curve. The function reconstructs the public key ASN.1 representation of the EC
   * public key based on the curve OID and public EC point data.
   *
   * @param publicKeyBytes
   *          the byte representation of the public EC point
   * @param curveOidStr
   *          the string representation of the named curve OID
   * @return bytes of the ASN.1 representation of the public key
   * @throws SecurityException
   *           ASN.1 errors
   */
  private static byte[] getPublicKeyBytes(byte[] publicKeyBytes, String curveOidStr) throws SecurityException {

    ASN1EncodableVector publicKeyParamSeq = new ASN1EncodableVector();
    publicKeyParamSeq.add(new ASN1ObjectIdentifier(EC_PUBLIC_KEY_OID));
    publicKeyParamSeq.add(new ASN1ObjectIdentifier(curveOidStr));

    ASN1EncodableVector publicKeySeq = new ASN1EncodableVector();
    publicKeySeq.add(new DERSequence(publicKeyParamSeq));
    publicKeySeq.add(new DERBitString(publicKeyBytes));

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    DEROutputStream dout = new DEROutputStream(bout);

    try {
      dout.writeObject((new DERSequence(publicKeySeq)));
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

}
