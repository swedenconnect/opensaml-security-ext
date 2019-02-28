/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.xmlsec.keyinfo.impl;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.impl.ConcatKDFParamsBuilder;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.impl.KeyDerivationMethodBuilder;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support.ECDHKeyAgreementBase;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support.EcEncryptionConstants;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import se.swedenconnect.opensaml.ecdh.security.x509.ECDHCredential;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.ConcatKDFParams;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.KeyDerivationMethod;
import org.opensaml.xmlsec.encryption.OriginatorKeyInfo;
import org.opensaml.xmlsec.encryption.RecipientKeyInfo;
import org.opensaml.xmlsec.encryption.impl.*;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.DigestMethodBuilder;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;

import javax.annotation.Nonnull;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

/**
 * This key info generator factory must be added to the encryption configuration of OpenSAML, or added explicitly to the KeyEncryptionParameters.
 * <p></p>
 * <p>Example:</p>
 * <pre><code>
 *      ECDHKeyInfoGeneratorFactory ecdhFactory = new ECDHKeyInfoGeneratorFactory();
 *        ecdhFactory.setEmitX509IssuerSerial(true);
 *        ecdhFactory.setEmitPublicKeyValue(true);
 *
 *      ConfigurationService.get(EncryptionConfiguration.class)
 *        .getKeyTransportKeyInfoGeneratorManager()
 *        .getDefaultManager().registerFactory(ecdhFactory);
 * </code></pre>
 */
public class ECDHKeyInfoGeneratorFactory extends X509KeyInfoGeneratorFactory {

  /** {@inheritDoc} */
  public boolean handles(@Nonnull final Credential credential) {
    return credential instanceof ECDHCredential;
  }

  /** {@inheritDoc} */
  public Class<? extends Credential> getCredentialType() {
    return ECDHCredential.class;
  }

  /** {@inheritDoc} */
  @Nonnull public KeyInfoGenerator newInstance() {
    // TODO lock options during cloning ?
    final X509Options newOptions = super.getOptions().clone();
    return new ECDHKeyInfoGenerator(newOptions);
  }

  public class ECDHKeyInfoGenerator extends X509KeyInfoGenerator {

    /**
     * Constructor.
     *
     */
    protected ECDHKeyInfoGenerator(X509Options newOptions) {
      super(newOptions);
    }

    /** {@inheritDoc} */
    public KeyInfo generate(Credential credential) throws SecurityException {

      ECDHCredential ecdhCredential = (ECDHCredential) credential;

      AgreementMethod am = new AgreementMethodBuilder().buildObject();
      am.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES);

      KeyDerivationMethod kdm = new KeyDerivationMethodBuilder().buildObject();
      kdm.setAlgorithm(EcEncryptionConstants.ALGO_ID_KEYDERIVATION_CONCAT);
      ConcatKDFParams kdfParams = new ConcatKDFParamsBuilder().buildObject();
      kdfParams.setAlgorithmID(ecdhCredential.getConcatKDF().getAlgorithmID());
      kdfParams.setPartyUInfo(ecdhCredential.getConcatKDF().getPartyUInfo());
      kdfParams.setPartyVInfo(ecdhCredential.getConcatKDF().getPartyVInfo());
      kdfParams.setSuppPrivInfo(ecdhCredential.getConcatKDF().getSuppPrivInfo());
      kdfParams.setSuppPubInfo(ecdhCredential.getConcatKDF().getSuppPubInfo());
      DigestMethod dm = new DigestMethodBuilder().buildObject();
      dm.setAlgorithm(ecdhCredential.getConcatKDF().getDigestMethod().getAlgorithm());
      kdfParams.setDigestMethod(dm);
      kdm.getUnknownXMLObjects().add(kdfParams);
      am.getUnknownXMLObjects().add(kdm);

      OriginatorKeyInfo oki = new OriginatorKeyInfoBuilder().buildObject();
      processEcPublicKey(oki, ecdhCredential.getSenderPubKey());
      am.setOriginatorKeyInfo(oki);

      RecipientKeyInfo rki = new RecipientKeyInfoBuilder().buildObject();
      XMLObjectBuilder<X509Data> x509DataBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilderOrThrow(X509Data.DEFAULT_ELEMENT_NAME);
      final X509Data x509Data = x509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
      processEntityCertificate(rki, x509Data, ecdhCredential);
      final List<XMLObject> x509DataChildren = x509Data.getOrderedChildren();
      if (x509DataChildren != null && x509DataChildren.size() > 0) {
        rki.getX509Datas().add(x509Data);
      }
      am.setRecipientKeyInfo(rki);

      KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
      keyInfo.getAgreementMethods().add(am);
      return keyInfo;

    }

    /**
     * Build the XML representation of the sender public key
     *
     * @param keyInfo         keyInfo object where the public key data is to be added
     * @param senderPublicKey credential holding the sender public key.
     * @throws SecurityException
     */
    protected void processEcPublicKey(@Nonnull KeyInfo keyInfo, @Nonnull PublicKey senderPublicKey) throws SecurityException {
      if (senderPublicKey != null && senderPublicKey instanceof ECPublicKey) {

        final XMLObjectBuilder<KeyValue> keyValueBuilder = (XMLObjectBuilder<KeyValue>)
          XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(KeyValue.DEFAULT_ELEMENT_NAME);
        final KeyValue keyValue = Constraint.isNotNull(keyValueBuilder, "KeyValue builder not available").buildObject(
          KeyValue.DEFAULT_ELEMENT_NAME);

        keyValue.setECKeyValue(ECDHKeyAgreementBase.buildECKeyValue((ECPublicKey) senderPublicKey));
        keyInfo.getKeyValues().add(keyValue);
      }
      else {
        throw new SecurityException("No an EC public key");
      }
    }
  }
}
