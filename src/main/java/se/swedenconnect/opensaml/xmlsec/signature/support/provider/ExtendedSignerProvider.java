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
package se.swedenconnect.opensaml.xmlsec.signature.support.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.util.encoders.Base64;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmRegistry;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.impl.provider.ApacheSantuarioSignerProviderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.NodeList;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.xmlsec.algorithm.ExtendedAlgorithmSupport;
import se.swedenconnect.opensaml.xmlsec.signature.support.provider.padding.SCPSSPadding;

/**
 * The Sun PKCS#11 crypto provider does not have support for PSS padding which makes HSM RSA-PSS signing impossible
 * using the standard OpenSAML signer provider ({@link ApacheSantuarioSignerProviderImpl}). Therefore, the
 * {@code ExtendedSignerProvider} overrides {@link ApacheSantuarioSignerProviderImpl} with functionality that performs
 * the PSS padding in software and only the raw RSA encryption operation is done in the HSM. This enables RSA-PSS
 * signing with RSA keys in HSM even when RSA-PSS is not supported by the PKCS#11 API.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 * @see ApacheSantuarioSignerProviderImpl
 */
public class ExtendedSignerProvider extends ApacheSantuarioSignerProviderImpl {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(ExtendedSignerProvider.class);

  /**
   * The PKCS#11 fixes of this provider may be disabled by setting the system property
   * {@code se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.disabled} to
   * {@code true}.
   */
  private boolean disabled = false;

  /**
   * Default constructor.
   */
  public ExtendedSignerProvider() {
    this.disabled = Boolean.parseBoolean(
      System.getProperty("se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.disabled", "false"));
    if (this.disabled) {
      ExtendedSignerProvider.log.info("The ExtendedSignerProvider has been disabled - {} will be active",
        ApacheSantuarioSignerProviderImpl.class.getName());
    }
  }

  /**
   * Tests if the signing key is a SUN PKCS#11 key and the signing algorithm is RSA-PSS. If this is the case, then PSS
   * padding is performed in software and only the raw RSA encryption operation is done in the HSM. This enables RSA-PSS
   * signing with RSA keys in HSM even when RSA-PSS is not supported by the PKCS#11 API.
   */
  @Override
  public void signObject(final Signature signature) throws SignatureException {
    if (this.disabled) {
      super.signObject(signature);
      return;
    }
    Constraint.isNotNull(signature, "Signature cannot be null");
    Constraint.isTrue(Init.isInitialized(), "Apache XML security library is not initialized");

    final XMLSignature xmlSignature = ((SignatureImpl) signature).getXMLSignature();
    final Credential signingCredential = signature.getSigningCredential();
    final Key signingKey = CredentialSupport.extractSigningKey(signingCredential);

    // Should we intercept this call and provider our own implementation?
    //
    if (!this.shouldOverride(signingKey, xmlSignature)) {
      // Nope, let the default implementation handle this operation.
      super.signObject(signature);
      return;
    }

    final SignedInfo signedInfo = xmlSignature.getSignedInfo();
    if (signedInfo == null) {
      final String msg = "Bad XMLSignature - missing SignedInfo";
      ExtendedSignerProvider.log.error(msg);
      throw new SignatureException(msg);
    }
    
    log.debug("{} executing during signature with {}", ExtendedSignerProvider.class.getSimpleName(), signedInfo.getSignatureMethodURI());

    try {
      // Calculate digest values ...
      signedInfo.generateDigestValues();

      // Get canonicalized bytes ...
      final byte[] signedInfoBytes = signedInfo.getCanonicalizedOctetStream();

      // Perform RSA-PSS padding ...
      //
      final RSAPublicKey publicKey = (RSAPublicKey) signingCredential.getPublicKey();
      if (publicKey == null) {
        final String msg = "No RSA public key found in signing credential";
        ExtendedSignerProvider.log.error(msg);
        throw new SignatureException(msg);
      }
      final SCPSSPadding pssPadding = new SCPSSPadding(
        this.getDigest(signedInfo.getSignatureMethodURI()),
        publicKey.getModulus().bitLength());

      final byte[] emBytes = pssPadding.getPaddingFromMessage(signedInfoBytes);

      // Next, perform a raw RSA transform (the signing) ...
      //
      final Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, signingKey);
      final byte[] signatureBytes = cipher.doFinal(emBytes);

      // Finally, place the signature in its correct place in the XML signature object ...
      //
      final NodeList signatureValue = xmlSignature.getElement()
        .getElementsByTagNameNS(SignatureConstants.XMLSIG_NS, "SignatureValue");
      if (signatureValue.getLength() == 0) {
        throw new SignatureException("Invalid XMLSignature - missing SignatureValue element");
      }
      signatureValue.item(0).setTextContent(Base64.toBase64String(signatureBytes));
    }
    catch (final XMLSecurityException e) {
      ExtendedSignerProvider.log.error("Failure during digest calculation - {}", e.getMessage(), e);
      throw new SignatureException("Failure during digest calculation", e);
    }
    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
      ExtendedSignerProvider.log.error("RSA transform failed - {}", e.getMessage(), e);
      throw new SignatureException("RSA signature failure", e);
    }
  }

  /**
   * Predicate that tells us whether our implementation should kick-in, or whether we should let
   * {@link ApacheSantuarioSignerProviderImpl} process the call.
   * <p>
   * If the signing key is an RSA SunPKCS11 private key and the algorithm is an RSA-PSS algorithm we let our override
   * take control. We can also force our implementation by setting the system property
   * {@code se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.testmode} to
   * {@code true}.
   * </p>
   *
   * @param signingKey
   *          the signing key
   * @param xmlSignature
   *          the XML signature object
   * @return whether we should override or not
   */
  private boolean shouldOverride(final Key signingKey, final XMLSignature xmlSignature) {
    if (signingKey != null && !"RSA".equals(signingKey.getAlgorithm())) {
      return false;
    }
    if (this.isTestMode()) {
      return true;
    }
    final String signingAlgorithm = xmlSignature != null && xmlSignature.getSignedInfo() != null
        ? xmlSignature.getSignedInfo().getSignatureMethodURI()
        : null;

    return signingKey != null && "RSA".equals(signingKey.getAlgorithm())
        && "sun.security.pkcs11.P11Key$P11PrivateKey".equals(signingKey.getClass().getName())
        && ExtendedAlgorithmSupport.isRSAPSS(signingAlgorithm);
  }

  /**
   * Return the digest function specified by a signature algorithm.
   *
   * @param signatureAlgorithm
   *          signature algorithm
   * @return the digest algorithm
   * @throws NoSuchAlgorithmException if no support for the algorithm is available 
   */
  private MessageDigest getDigest(final String signatureAlgorithm) throws NoSuchAlgorithmException {
    
    final AlgorithmRegistry algorithmRegistry = AlgorithmSupport.getGlobalAlgorithmRegistry();    
    final AlgorithmDescriptor algorithmDescriptor = algorithmRegistry.get(signatureAlgorithm);
    if (algorithmDescriptor == null || !AlgorithmDescriptor.AlgorithmType.Signature.equals(algorithmDescriptor.getType())) {
      log.error("Unsupported signature algorithm - {}", signatureAlgorithm);
      throw new NoSuchAlgorithmException("Unsupported signature algorithm - " + signatureAlgorithm);
    }
    final String jcaDigest = SignatureAlgorithm.class.cast(algorithmDescriptor).getDigest();
    log.debug("Getting digest algorithm for '{}'", jcaDigest);
    return MessageDigest.getInstance(jcaDigest);
  }

  /**
   * Predicate that tells if this instance is running in test mode. Using test mode we can test the PKCS#11 workaround
   * even without an installed HSM.
   *
   * @return test mode flag
   */
  private boolean isTestMode() {
    return Boolean.parseBoolean(
      System.getProperty("se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.testmode", "false"));
  }

}
