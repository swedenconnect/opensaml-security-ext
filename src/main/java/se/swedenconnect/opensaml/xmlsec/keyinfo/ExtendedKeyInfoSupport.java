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

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERBitString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.ECKeyValue;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.opensaml.xmlsec.signature.NamedCurve;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Extends {@link KeyInfoSupport} with support for EC keys.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedKeyInfoSupport {

  /**
   * Extends {@link KeyInfoSupport#addPublicKey(KeyInfo, PublicKey)} with support for EC keys.
   * 
   * @param keyInfo
   *          the {@link KeyInfo} element to which to add the key
   * @param pk
   *          the native Java {@link PublicKey} to add
   * @throws SecurityException
   *           for incorrect public key encodings
   */
  public static void addPublicKey(@Nonnull final KeyInfo keyInfo, @Nullable final PublicKey pk) throws SecurityException {
    Constraint.isNotNull(keyInfo, "KeyInfo cannot be null");

    if (!ECPublicKey.class.isInstance(pk)) {
      KeyInfoSupport.addPublicKey(keyInfo, pk);
      return;
    }

    final KeyValue keyValue = (KeyValue) XMLObjectSupport.buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
    keyValue.setECKeyValue(buildECKeyValue((ECPublicKey) pk));
    keyInfo.getKeyValues().add(keyValue);
  }

  /**
   * Builds an {@link ECKeyValue} XMLObject from the Java security EC public key type.
   *
   * @param ecPubKey
   *          a native Java {@link ECPublicKey}
   * @return an {@link ECKeyValue} XMLObject
   * @throws SecurityException
   *           if the supplied public key is not encoded correctly
   */
  @Nonnull
  public static ECKeyValue buildECKeyValue(@Nonnull final ECPublicKey ecPubKey) throws SecurityException {
    Constraint.isNotNull(ecPubKey, "EC public key cannot be null");

    try {
      final ECKeyValue ecKeyValue = (ECKeyValue) XMLObjectSupport.buildXMLObject(ECKeyValue.DEFAULT_ELEMENT_NAME);

      ASN1StreamParser parser = new ASN1StreamParser(ecPubKey.getEncoded());

//      DERSequence seq = (DERSequence) parser.readObject().toASN1Primitive();
      ASN1Sequence seq = (ASN1Sequence) parser.readObject().toASN1Primitive();
//      DERSequence innerSeq = (DERSequence) seq.getObjectAt(0).toASN1Primitive();
      ASN1Sequence innerSeq = (ASN1Sequence) seq.getObjectAt(0).toASN1Primitive();
      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(1).toASN1Primitive();
      
      final NamedCurve namedCurve = (NamedCurve) XMLObjectSupport.buildXMLObject(NamedCurve.DEFAULT_ELEMENT_NAME);      
      namedCurve.setURI("urn:oid:" + oid.getId());
      ecKeyValue.setNamedCurve(namedCurve);

      final org.opensaml.xmlsec.signature.PublicKey publicKey = (org.opensaml.xmlsec.signature.PublicKey) XMLObjectSupport.buildXMLObject(
        org.opensaml.xmlsec.signature.PublicKey.DEFAULT_ELEMENT_NAME);
      DERBitString key = (DERBitString) seq.getObjectAt(1).toASN1Primitive();
      publicKey.setValue(Base64Support.encode(key.getBytes(), Base64Support.UNCHUNKED)); 
      ecKeyValue.setPublicKey(publicKey);

      return ecKeyValue;
    }
    catch (IOException e) {
      throw new SecurityException("Invalid EC public key parameters", e);
    }
  }

  // Hidden
  private ExtendedKeyInfoSupport() {
  }

}
