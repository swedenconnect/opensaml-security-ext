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

import org.bouncycastle.util.Arrays;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.xmlsec.signature.DigestMethod;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Class for representing parameter inputs to the ConcatKDF key derivation algorithm.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ConcatKDFParameters {

  /** Default value for the mandatory attribute AlgorithmID. */
  public static final byte[] DEFAULT_ALGORITHM_ID = new byte[] { 0x00 };

  /** Default value for mandatory attribute PartyUInfo. */
  public static final byte[] DEFAULT_PARTY_UINFO = new byte[] { 0x00 };

  /** Default value for mandatory attribute PartyVInfo. */
  public static final byte[] DEFAULT_PARTY_VINFO = new byte[] { 0x00 };

  /** Digest method algorithm URI. */
  private String digestMethod;

  /** The ConcatKDFParams AlgorithmID attribute. */
  private byte[] algorithmID;

  /** The ConcatKDFParams PartyUInfo attribute. */
  private byte[] partyUInfo;

  /** The ConcatKDFParams PartyVInfo attribute. */
  private byte[] partyVInfo;

  /** The ConcatKDFParams SuppPubInfo attribute. */
  private byte[] suppPubInfo;

  /** The ConcatKDFParams SuppPrivInfo attribute. */
  private byte[] suppPrivInfo;

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
    this.digestMethod = Constraint.isNotEmpty(digestMethod, "digestMethod must be set");
    this.algorithmID = Arrays.copyOf(
      Constraint.isNotEmpty(algorithmID, "algorithmID must be set"), algorithmID.length);
    this.partyUInfo = Arrays.copyOf(
      Constraint.isNotEmpty(partyUInfo, "partyUInfo must be set"), partyUInfo.length);
    this.partyVInfo = Arrays.copyOf(
      Constraint.isNotEmpty(partyVInfo, "partyVInfo must be set"), partyVInfo.length);
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
    this.digestMethod = Constraint.isNotEmpty(params.getDigestMethod().getAlgorithm(), "digestMethod must be set");
    this.algorithmID = Arrays.copyOf(
      Constraint.isNotEmpty(params.getAlgorithmID(), "params.algorithmID must be set"), params.getAlgorithmID().length);
    this.partyUInfo = Arrays.copyOf(
      Constraint.isNotEmpty(params.getPartyUInfo(), "params.partyUInfo must be set"), params.getPartyUInfo().length);
    this.partyVInfo = Arrays.copyOf(
      Constraint.isNotEmpty(params.getPartyVInfo(), "params.partyVInfo must be set"), params.getPartyVInfo().length);
    this.setSuppPubInfo(params.getSuppPubInfo());
    this.setSuppPrivInfo(params.getSuppPrivInfo());
  }

  /**
   * Transforms this object into the OpenSAML {@code XMLObject} representation of the ConcatKDF parameters.
   * 
   * @return a {@link ConcatKDFParams} object
   */
  public ConcatKDFParams toXMLObject() {
    ConcatKDFParams params = (ConcatKDFParams) XMLObjectSupport.buildXMLObject(ConcatKDFParams.DEFAULT_ELEMENT_NAME);
    DigestMethod dm = (DigestMethod) XMLObjectSupport.buildXMLObject(DigestMethod.DEFAULT_ELEMENT_NAME);
    dm.setAlgorithm(this.getDigestMethod());
    params.setDigestMethod(dm);
    params.setAlgorithmID(this.getAlgorithmID());
    params.setPartyUInfo(this.getPartyUInfo());
    params.setPartyVInfo(this.getPartyVInfo());
    if (this.suppPubInfo != null) {
      params.setSuppPubInfo(this.getSuppPubInfo());
    }
    if (this.suppPrivInfo != null) {
      params.setSuppPrivInfo(this.getSuppPrivInfo());
    }
    return params;
  }

  /**
   * Returns the digest method for the KDFConcat operation.
   * 
   * @return the digest method.
   */
  public String getDigestMethod() {
    return this.digestMethod;
  }

  /**
   * Returns a copy of the AlgorithmID attribute byte array.
   * 
   * @return the AlgorithmID attribute
   */
  public byte[] getAlgorithmID() {
    return Arrays.copyOf(this.algorithmID, this.algorithmID.length);
  }

  /**
   * Returns a copy of the PartyUInfo attribute byte array.
   * 
   * @return the PartyUIInfo attribute
   */
  public byte[] getPartyUInfo() {
    return Arrays.copyOf(this.partyUInfo, this.partyUInfo.length);
  }

  /**
   * Returns a copy of the PartyVInfo attribute byte array.
   * 
   * @return the PartyVInfo attribute
   */
  public byte[] getPartyVInfo() {
    return Arrays.copyOf(this.partyVInfo, this.partyVInfo.length);
  }

  /**
   * Returns a copy of the SuppPubInfo attribute byte array.
   * 
   * @return the SuppPubInfo attribute, or {@code null}
   */
  public byte[] getSuppPubInfo() {
    return this.suppPubInfo != null ? Arrays.copyOf(this.suppPubInfo, this.suppPubInfo.length) : null;
  }

  /**
   * Sets the SuppPubInfo attribute.
   * 
   * @param suppPubInfo
   *          the SuppPubInfo attribute
   */
  public void setSuppPubInfo(byte[] suppPubInfo) {
    this.suppPubInfo = suppPubInfo != null ? Arrays.copyOf(suppPubInfo, suppPubInfo.length) : null;
  }

  /**
   * Returns a copy of the SuppPrivInfo attribute byte array.
   * 
   * @return the SuppPrivInfo attribute, or {@code null}
   */
  public byte[] getSuppPrivInfo() {
    return this.suppPrivInfo != null ? Arrays.copyOf(this.suppPrivInfo, this.suppPrivInfo.length) : null;
  }

  /**
   * Sets the SuppPrivInfo attribute.
   * 
   * @param suppPrivInfo
   *          the SuppPrivInfo attribute
   */
  public void setSuppPrivInfo(byte[] suppPrivInfo) {
    this.suppPrivInfo = suppPrivInfo != null ? Arrays.copyOf(suppPrivInfo, suppPrivInfo.length) : null;
  }

}
