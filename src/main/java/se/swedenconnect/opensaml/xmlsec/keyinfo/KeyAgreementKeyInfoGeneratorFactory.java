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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.AgreementMethod;
import org.opensaml.xmlsec.encryption.OriginatorKeyInfo;
import org.opensaml.xmlsec.encryption.RecipientKeyInfo;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.security.credential.KeyAgreementCredential;

/**
 * Key info generator to be used when encrypting using key agreement methods.
 * 
 * <p>
 * Note that either {@code emitOriginatorKeyInfoPublicKeyValue} or {@code emitOriginatorKeyInfoPublicDEREncodedKeyValue}
 * must be set. Otherwise, and empty {@code OriginatorKeyInfo} element will be created.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyAgreementKeyInfoGeneratorFactory extends X509KeyInfoGeneratorFactory {
  
  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(KeyAgreementKeyInfoGeneratorFactory.class);

  /** {@inheritDoc} */
  public boolean handles(@Nonnull final Credential credential) {
    return credential instanceof KeyAgreementCredential;
  }

  /** {@inheritDoc} */
  public Class<? extends Credential> getCredentialType() {
    return KeyAgreementCredential.class;
  }

  /** {@inheritDoc} */
  @Nonnull
  public KeyInfoGenerator newInstance() {
    final ExtendedX509Options _options = (ExtendedX509Options) this.getOptions();
    if (!_options.emitOriginatorKeyInfoPublicDEREncodedKeyValue && !_options.emitOriginatorKeyInfoPublicKeyValue) {
      log.error("Bad configuration - emitOriginatorKeyInfoPublicDEREncodedKeyValue or "
        + "emitOriginatorKeyInfoPublicKeyValue must be set");
    }
    return new KeyAgreementKeyInfoGenerator(_options.clone());
  }

  /**
   * Get the option to emit the value of {@link KeyAgreementCredential#getSenderGeneratedPublicKey()} as a KeyValue
   * element in the {@code OriginatorKeyInfo} element.
   *
   * @return the option value
   */
  public boolean emitOriginatorKeyInfoPublicKeyValue() {
    if (ExtendedX509Options.class.isInstance(this.getOptions())) {
      return ((ExtendedX509Options) this.getOptions()).emitOriginatorKeyInfoPublicKeyValue;
    }
    return false;
  }

  /**
   * Set the option to emit the value of {@link KeyAgreementCredential#getSenderGeneratedPublicKey()} as a KeyValue
   * element in the {@code OriginatorKeyInfo} element.
   *
   * @param value
   *          the new option value to set
   */
  public void setEmitOriginatorKeyInfoPublicKeyValue(final boolean value) {
    if (ExtendedX509Options.class.isInstance(this.getOptions())) {
      ((ExtendedX509Options) this.getOptions()).emitOriginatorKeyInfoPublicKeyValue = value;
    }
  }

  /**
   * Get the option to emit the value of {@link KeyAgreementCredential#getSenderGeneratedPublicKey()} as a
   * DEREncodedKeyValue element in the {@code OriginatorKeyInfo} element.
   *
   * @return the option value
   */
  public boolean emitOriginatorKeyInfoPublicDEREncodedKeyValue() {
    if (ExtendedX509Options.class.isInstance(this.getOptions())) {
      return ((ExtendedX509Options) this.getOptions()).emitOriginatorKeyInfoPublicDEREncodedKeyValue;
    }
    return false;
  }

  /**
   * Set the option to emit the value of {@link KeyAgreementCredential#getSenderGeneratedPublicKey()} as a
   * DEREncodedKeyValue element in the {@code OriginatorKeyInfo} element.
   *
   * @param value
   *          the new option value to set
   */
  public void setEmitOriginatorKeyInfoPublicDEREncodedKeyValue(final boolean value) {
    if (ExtendedX509Options.class.isInstance(this.getOptions())) {
      ((ExtendedX509Options) this.getOptions()).emitOriginatorKeyInfoPublicDEREncodedKeyValue = value;
    }
  }

  /** {@inheritDoc} */
  @Override
  protected X509Options newOptions() {
    return new ExtendedX509Options();
  }

  /**
   * Since the visibility of the {@link X509Options} class prevents us from cloning it, we have to come up with a
   * workaround.
   */
  protected class ExtendedX509Options extends X509Options {

    /** Emit the value of {@link KeyAgreementCredential#getSenderGeneratedPublicKey()} as a KeyValue element. */
    private boolean emitOriginatorKeyInfoPublicKeyValue;

    /**
     * Emit the value of {@link KeyAgreementCredential#getSenderGeneratedPublicKey()} as a DEREncodedKeyValue element.
     */
    private boolean emitOriginatorKeyInfoPublicDEREncodedKeyValue;

    /** {@inheritDoc} */
    @Override
    protected X509Options clone() {
      ExtendedX509Options clonedOptions = (ExtendedX509Options) super.clone();
      clonedOptions.emitOriginatorKeyInfoPublicKeyValue = this.emitOriginatorKeyInfoPublicKeyValue;
      clonedOptions.emitOriginatorKeyInfoPublicDEREncodedKeyValue = this.emitOriginatorKeyInfoPublicDEREncodedKeyValue;
      return clonedOptions;
    }
  }

  /**
   * An implementation of {@link KeyInfoGenerator} capable of handling the information contained within a
   * {@link KeyAgreementCredential}.
   * 
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public class KeyAgreementKeyInfoGenerator extends X509KeyInfoGenerator {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(KeyAgreementKeyInfoGenerator.class);

    /**
     * Constructor.
     * 
     * @param options
     *          the options to be used by the generator
     */
    protected KeyAgreementKeyInfoGenerator(X509Options options) {
      super(options);
    }

    /** {@inheritDoc} */
    @Nullable
    public KeyInfo generate(@Nullable final Credential credential) throws SecurityException {

      if (credential == null) {
        log.warn("KeyAgreementKeyInfoGenerator was passed a null credential");
        return null;
      }
      else if (!KeyAgreementCredential.class.isInstance(credential)) {
        log.warn("KeyAgreementKeyInfoGenerator was passed a credential that was not an instance of KeyAgreementCredential: {}",
          credential.getClass().getName());
        return null;
      }
      KeyAgreementCredential kaCredential = KeyAgreementCredential.class.cast(credential);

      AgreementMethod am = (AgreementMethod) XMLObjectSupport.buildXMLObject(AgreementMethod.DEFAULT_ELEMENT_NAME);
      am.setAlgorithm(kaCredential.getAgreementMethodAlgorithm());

      am.getUnknownXMLObjects().add(kaCredential.getKeyDerivationMethod());

      OriginatorKeyInfo oki = (OriginatorKeyInfo) XMLObjectSupport.buildXMLObject(OriginatorKeyInfo.DEFAULT_ELEMENT_NAME);
      this.processSenderPublicKey(oki, kaCredential);
      am.setOriginatorKeyInfo(oki);

      // The contents of RecipientKeyInfo will be the same as ds:KeyInfo for a non key-agreement case,
      // so we let the super implementation generate a KeyInfo and then clone it into a RecipientKeyInfo
      // element.
      //
      KeyInfo toBeRki = super.generate(kaCredential.getPeerCredential());
      RecipientKeyInfo rki = this.cloneToRecipientKeyInfo(toBeRki);
      am.setRecipientKeyInfo(rki);

      KeyInfo keyInfo = (KeyInfo) XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
      keyInfo.getAgreementMethods().add(am);
      return keyInfo;
    }

    /**
     * Clones a {@code ds:KeyInfo} element into an {@code xenc:RecipientKeyInfo} element.
     * 
     * @param keyInfo
     *          the object to clone
     * @return a {@code RecipientKeyInfo} object
     */
    protected RecipientKeyInfo cloneToRecipientKeyInfo(KeyInfo keyInfo) {
      try {
        Element keyInfoElement = XMLObjectSupport.marshall(keyInfo);

        Document doc = XMLObjectProviderRegistrySupport.getParserPool().newDocument();
        Element clonedElement = (Element) doc.importNode(keyInfoElement, true);
        doc.appendChild(clonedElement);

        doc.renameNode(doc.getDocumentElement(), RecipientKeyInfo.DEFAULT_ELEMENT_NAME.getNamespaceURI(),
          RecipientKeyInfo.DEFAULT_ELEMENT_NAME.getPrefix() + ":" + RecipientKeyInfo.DEFAULT_ELEMENT_NAME.getLocalPart());

        RecipientKeyInfo rki = (RecipientKeyInfo) XMLObjectSupport.getUnmarshaller(RecipientKeyInfo.DEFAULT_ELEMENT_NAME)
          .unmarshall(doc.getDocumentElement());
        rki.releaseDOM();

        return rki;
      }
      catch (MarshallingException | XMLParserException | UnmarshallingException e) {
        throw new XMLRuntimeException("Failed to clone KeyInfo into RecipientKeyInfo", e);
      }
    }

    /**
     * Extends {@link BasicKeyInfoGenerator#processPublicKey(KeyInfo, Credential)} with support for EC keys.
     */
    @Override
    protected void processPublicKey(KeyInfo keyInfo, Credential credential) throws SecurityException {
      if (credential.getPublicKey() != null) {
        if (emitPublicKeyValue()) {
          ExtendedKeyInfoSupport.addPublicKey(keyInfo, credential.getPublicKey());
        }
        if (emitPublicDEREncodedKeyValue()) {
          try {
            KeyInfoSupport.addDEREncodedPublicKey(keyInfo, credential.getPublicKey());
          }
          catch (final NoSuchAlgorithmException e) {
            throw new SecurityException("Cannot DER-encode key, unsupported key algorithm", e);
          }
          catch (final InvalidKeySpecException e) {
            throw new SecurityException("Cannot DER-encode key, invalid key specification", e);
          }
        }
      }
    }

    /**
     * Adds the sender generated public key to the OriginatorKeyInfo element.
     * 
     * @param keyInfo
     *          the key info to update
     * @param credential
     *          the credential holding the sender generated public key
     * @throws SecurityException
     *           for algorithm errors
     */
    protected void processSenderPublicKey(OriginatorKeyInfo keyInfo, KeyAgreementCredential credential) throws SecurityException {
      if (credential.getSenderGeneratedPublicKey() != null) {
        if (emitOriginatorKeyInfoPublicKeyValue()) {
          ExtendedKeyInfoSupport.addPublicKey(keyInfo, credential.getSenderGeneratedPublicKey());
        }
        if (emitOriginatorKeyInfoPublicDEREncodedKeyValue()) {
          try {
            KeyInfoSupport.addDEREncodedPublicKey(keyInfo, credential.getSenderGeneratedPublicKey());
          }
          catch (final NoSuchAlgorithmException e) {
            throw new SecurityException("Cannot DER-encode key, unsupported key algorithm", e);
          }
          catch (final InvalidKeySpecException e) {
            throw new SecurityException("Cannot DER-encode key, invalid key specification", e);
          }
        }
      }
    }
    
  }

}
