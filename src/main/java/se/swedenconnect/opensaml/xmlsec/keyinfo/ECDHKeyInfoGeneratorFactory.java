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
package se.swedenconnect.opensaml.xmlsec.keyinfo;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import org.opensaml.xmlsec.encryption.OriginatorKeyInfo;
import org.opensaml.xmlsec.encryption.RecipientKeyInfo;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.opensaml.xmlsec.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.ecdh.security.x509.ECDHPeerCredential;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.ECDHKeyAgreementBase;
import se.swedenconnect.opensaml.xmlsec.encryption.ecdh.EcEncryptionConstants;

/**
 * Key info generator to be used when encrypting using ECDH.
 * 
 * This key info generator factory must be added to the encryption configuration of OpenSAML, or added explicitly to the
 * {@code KeyEncryptionParameters}.
 * 
 * <p>
 * Example:
 * </p>
 * 
 * <pre>
 * <code>
 *      ECDHKeyInfoGeneratorFactory ecdhFactory = new ECDHKeyInfoGeneratorFactory();
 *        ecdhFactory.setEmitX509IssuerSerial(true);
 *        ecdhFactory.setEmitPublicKeyValue(true);
 *
 *      ConfigurationService.get(EncryptionConfiguration.class)
 *        .getKeyTransportKeyInfoGeneratorManager()
 *        .getDefaultManager().registerFactory(ecdhFactory);
 * </code>
 * </pre>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ECDHKeyInfoGeneratorFactory extends X509KeyInfoGeneratorFactory {

  /** {@inheritDoc} */
  public boolean handles(@Nonnull final Credential credential) {
    return credential instanceof ECDHPeerCredential;
  }

  /** {@inheritDoc} */
  public Class<? extends Credential> getCredentialType() {
    return ECDHPeerCredential.class;
  }

  /** {@inheritDoc} */
  @Nonnull
  public KeyInfoGenerator newInstance() {
    final X509OptionsWorkAround _options = (X509OptionsWorkAround) this.getOptions();
    return new ECDHKeyInfoGenerator(_options.clone());
  }

  /** {@inheritDoc} */
  @Override
  protected X509Options newOptions() {
    return new X509OptionsWorkAround();
  }

  /**
   * Since the visibility of the {@link X509Options} class prevents us from cloning it, we have to come up with a
   * workaround.
   */
  protected class X509OptionsWorkAround extends X509Options {

    /** {@inheritDoc} */
    @Override
    protected X509Options clone() {
      return super.clone();
    }
  }

  /**
   * An implementation of {@link KeyInfoGenerator} capable of handling the information contained within a
   * {@link ECDHPeerCredential}.
   * 
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public class ECDHKeyInfoGenerator extends X509KeyInfoGenerator {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ECDHKeyInfoGenerator.class);

    /**
     * Constructor.
     * 
     * @param options
     *          the options to be used by the generator
     */
    protected ECDHKeyInfoGenerator(X509Options options) {
      super(options);
    }

    /** {@inheritDoc} */
    @Nullable
    public KeyInfo generate(@Nullable final Credential credential) throws SecurityException {

      if (credential == null) {
        log.warn("ECDHKeyInfoGenerator was passed a null credential");
        return null;
      }
      else if (!ECDHPeerCredential.class.isInstance(credential)) {
        log.warn("ECDHKeyInfoGenerator was passed a credential that was not an instance of ECDHPeerCredential: {}",
          credential.getClass().getName());
        return null;
      }
      ECDHPeerCredential ecdhCredential = ECDHPeerCredential.class.cast(credential);

      XMLObjectBuilder<AgreementMethod> agreementMethodBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(AgreementMethod.DEFAULT_ELEMENT_NAME);
      AgreementMethod am = agreementMethodBuilder.buildObject(AgreementMethod.DEFAULT_ELEMENT_NAME);
      am.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);

      XMLObjectBuilder<KeyDerivationMethod> keyDerivationMethodBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
      KeyDerivationMethod kdm = keyDerivationMethodBuilder.buildObject(KeyDerivationMethod.DEFAULT_ELEMENT_NAME);
      kdm.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT);

      if (ecdhCredential.getConcatKDFParams() == null) {
        throw new SecurityException("Supplied ECDHPeerCredential does not contain ConcatKDF params");
      }
      XMLObjectBuilder<ConcatKDFParams> concatKDFParamsBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
      ConcatKDFParams kdfParams = concatKDFParamsBuilder.buildObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
      kdfParams.setAlgorithmID(ecdhCredential.getConcatKDFParams().getAlgorithmID());
      kdfParams.setPartyUInfo(ecdhCredential.getConcatKDFParams().getPartyUInfo());
      kdfParams.setPartyVInfo(ecdhCredential.getConcatKDFParams().getPartyVInfo());
      kdfParams.setSuppPrivInfo(ecdhCredential.getConcatKDFParams().getSuppPrivInfo());
      kdfParams.setSuppPubInfo(ecdhCredential.getConcatKDFParams().getSuppPubInfo());

      XMLObjectBuilder<DigestMethod> digestMethodBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(DigestMethod.DEFAULT_ELEMENT_NAME);
      DigestMethod dm = digestMethodBuilder.buildObject(DigestMethod.DEFAULT_ELEMENT_NAME);
      dm.setAlgorithm(ecdhCredential.getConcatKDFParams().getDigestMethod().getAlgorithm());
      kdfParams.setDigestMethod(dm);
      kdm.getUnknownXMLObjects().add(kdfParams);
      am.getUnknownXMLObjects().add(kdm);

      XMLObjectBuilder<OriginatorKeyInfo> originatorKeyInfoBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(OriginatorKeyInfo.DEFAULT_ELEMENT_NAME);
      OriginatorKeyInfo oki = originatorKeyInfoBuilder.buildObject(OriginatorKeyInfo.DEFAULT_ELEMENT_NAME);
      this.processEcPublicKey(oki, ecdhCredential.getSenderGeneratedPublicKey());
      am.setOriginatorKeyInfo(oki);

      XMLObjectBuilder<RecipientKeyInfo> recipientKeyInfoBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(RecipientKeyInfo.DEFAULT_ELEMENT_NAME);
      RecipientKeyInfo rki = recipientKeyInfoBuilder.buildObject(RecipientKeyInfo.DEFAULT_ELEMENT_NAME);

      XMLObjectBuilder<X509Data> x509DataBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(X509Data.DEFAULT_ELEMENT_NAME);
      X509Data x509Data = x509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
      this.processEntityCertificate(rki, x509Data, ecdhCredential);

      List<XMLObject> x509DataChildren = x509Data.getOrderedChildren();
      if (!x509DataChildren.isEmpty()) {
        rki.getX509Datas().add(x509Data);
      }
      am.setRecipientKeyInfo(rki);

      XMLObjectBuilder<KeyInfo> keyInfoBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(KeyInfo.DEFAULT_ELEMENT_NAME);
      KeyInfo keyInfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
      keyInfo.getAgreementMethods().add(am);
      return keyInfo;
    }

    /**
     * Builds the XML representation of the sender public key.
     *
     * @param keyInfo
     *          keyInfo object where the public key data is to be added
     * @param senderPublicKey
     *          credential holding the sender public key
     * @throws SecurityException
     *           if the supplied public key is not an EC key
     */
    protected void processEcPublicKey(@Nonnull KeyInfo keyInfo, @Nonnull PublicKey senderPublicKey) throws SecurityException {
      if (ECPublicKey.class.isInstance(senderPublicKey)) {
        XMLObjectBuilder<KeyValue> keyValueBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
          .getBuilderOrThrow(KeyValue.DEFAULT_ELEMENT_NAME);
        KeyValue keyValue = keyValueBuilder.buildObject(KeyValue.DEFAULT_ELEMENT_NAME);
        keyValue.setECKeyValue(ECDHKeyAgreementBase.buildECKeyValue((ECPublicKey) senderPublicKey));
        keyInfo.getKeyValues().add(keyValue);
      }
      else {
        throw new SecurityException("Not an EC public key");
      }
    }
  }
}
