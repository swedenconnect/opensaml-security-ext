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

import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.signature.DigestMethod;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Class for representing parameter inputs to the ConcatKDF key derivation algorithm.
 * 
 * <p>
 * Note: The attribute values that are assigned using the setter methods or the
 * {@link #ConcatKDFParameters(String, byte[], byte[], byte[])} constructor should <b>not</b> be padded according to the
 * XML encryption standard (see {@link ConcatKDFParams}). Only the actual value should be assigned.
 * </p>
 * <p>
 * If you, for some reason, need to assign an attribute value whose bit length is not divisible by 8, you need to create
 * a {@link ConcatKDFParams} object and assign it using {@link #ConcatKDFParameters(ConcatKDFParams)}.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ConcatKDFParameters {

  /** Default value for the mandatory attribute AlgorithmID. */
  public static final byte[] DEFAULT_ALGORITHM_ID = new byte[] {};

  /** Default value for mandatory attribute PartyUInfo. */
  public static final byte[] DEFAULT_PARTY_UINFO = new byte[] {};

  /** Default value for mandatory attribute PartyVInfo. */
  public static final byte[] DEFAULT_PARTY_VINFO = new byte[] {};

  /** The XML representation of this object. */
  private ConcatKDFParams xmlObject;

  /**
   * A constructor that assigns the digest method and also assigns default values for AlgorithmID, PartyUInfo and
   * PartyVInfo.
   * 
   * @param digestMethod
   *          the digest method
   */
  public ConcatKDFParameters(String digestMethod) {
    this(digestMethod, DEFAULT_ALGORITHM_ID, DEFAULT_PARTY_UINFO, DEFAULT_PARTY_VINFO);
  }

  /**
   * Constructor assigning the digest method and the mandatory ConcatKDFParams attributes.
   * 
   * @param digestMethod
   *          the digest method
   * @param algorithmID
   *          the AlgorithmID attribute
   * @param partyUInfo
   *          the PartyUInfo attribute
   * @param partyVInfo
   *          the PartyVInfo attribute
   */
  public ConcatKDFParameters(String digestMethod, byte[] algorithmID, byte[] partyUInfo, byte[] partyVInfo) {
    Constraint.isNotEmpty(digestMethod, "digestMethod must be set");
    Constraint.isNotNull(algorithmID, "algorithmID must not be null");
    Constraint.isNotNull(partyUInfo, "partyUInfo must not be null");
    Constraint.isNotNull(partyVInfo, "partyVInfo must not be null");

    this.xmlObject = (ConcatKDFParams) XMLObjectSupport.buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
    DigestMethod dm = (DigestMethod) XMLObjectSupport.buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
    dm.setAlgorithm(digestMethod);
    this.xmlObject.setDigestMethod(dm);
    this.xmlObject.setAlgorithmID(pad(algorithmID));
    this.xmlObject.setPartyUInfo(pad(partyUInfo));
    this.xmlObject.setPartyVInfo(pad(partyVInfo));
  }

  /**
   * Constructor that creates the object from the supplied {@code XMLObject} representation of ConcatKDFParams.
   * 
   * @param params
   *          XML object
   */
  public ConcatKDFParameters(ConcatKDFParams params) {
    Constraint.isNotNull(params, "params must not be null");
    Constraint.isNotNull(params.getDigestMethod(), "params.DigestMethod must not be null");
    Constraint.isNotEmpty(params.getDigestMethod().getAlgorithm(), "digestMethod must be set");
    Constraint.isNotEmpty(params.getAlgorithmID(), "params.algorithmID must be set");
    Constraint.isNotEmpty(params.getPartyUInfo(), "params.partyUInfo must be set");
    Constraint.isNotEmpty(params.getPartyVInfo(), "params.partyVInfo must be set");
    try {
      this.xmlObject = XMLObjectSupport.cloneXMLObject(params);
    }
    catch (MarshallingException | UnmarshallingException e) {
      throw new XMLRuntimeException("Failed to clone ConcatKDFParams", e);
    }
  }

  /**
   * Transforms this object into the OpenSAML {@code XMLObject} representation of the ConcatKDF parameters.
   * 
   * @return a {@link ConcatKDFParams} object
   */
  public ConcatKDFParams toXMLObject() {
    try {
      return XMLObjectSupport.cloneXMLObject(this.xmlObject);
    }
    catch (MarshallingException | UnmarshallingException e) {
      throw new XMLRuntimeException("Failed to clone ConcatKDFParams", e);
    }
  }

  /**
   * Returns the DigestMethod of the ConcatKDF parameters.
   * 
   * @return the digest method
   */
  public String getDigestMethod() {
    return this.xmlObject.getDigestMethod().getAlgorithm();
  }

  /**
   * Sets the AlgorithmID attribute.
   * 
   * @param algorithmID
   *          the AlgorithmID attribute
   */
  public void setAlgorithmID(byte[] algorithmID) {
    this.xmlObject.setAlgorithmID(pad(algorithmID));
  }

  /**
   * Sets the PartyUIInfo attribute.
   * 
   * @param partyUInfo
   *          the PartyUIInfo attribute
   */
  public void setPartyUInfo(byte[] partyUInfo) {
    this.xmlObject.setPartyUInfo(pad(partyUInfo));
  }

  /**
   * Sets the PartyVInfo attribute.
   * 
   * @param partyVInfo
   *          the PartyVInfo attribute
   */
  public void setPartyVInfo(byte[] partyVInfo) {
    this.xmlObject.setPartyVInfo(pad(partyVInfo));
  }

  /**
   * Sets the SuppPubInfo attribute.
   * 
   * @param suppPubInfo
   *          the SuppPubInfo attribute
   */
  public void setSuppPubInfo(byte[] suppPubInfo) {
    this.xmlObject.setSuppPubInfo(pad(suppPubInfo));
  }

  /**
   * Sets the SuppPrivInfo attribute.
   * 
   * @param suppPrivInfo
   *          the SuppPrivInfo attribute
   */
  public void setSuppPrivInfo(byte[] suppPrivInfo) {
    this.xmlObject.setSuppPrivInfo(pad(suppPrivInfo));
  }

  /**
   * Pads an attribute value to be asssigned to a {@link ConcatKDFParams} object according to the XML encryption
   * standard.
   * 
   * @param value
   *          the value (may be {@code null})
   * @return the padded value
   */
  private static byte[] pad(final byte[] value) {
    if (value == null) {
      return null;
    }
    byte[] newValue = new byte[value.length + 1];
    newValue[0] = 0x00;
    System.arraycopy(value, 0, newValue, 1, value.length);
    return newValue;
  }

}
