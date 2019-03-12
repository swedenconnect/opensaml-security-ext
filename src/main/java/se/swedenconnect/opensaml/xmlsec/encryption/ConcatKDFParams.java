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
package se.swedenconnect.opensaml.xmlsec.encryption;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.DigestMethod;

/**
 * Representation of the ConcatKDF key derivation method.
 * 
 * <pre>
 * {@code
 * <element name="ConcatKDFParams" type="xenc11:ConcatKDFParamsType"/>
 * 
 * <complexType name="ConcatKDFParamsType">
 *   <sequence>
 *     <element ref="ds:DigestMethod"/>
 *   </sequence>
 *   <attribute name="AlgorithmID" type="hexBinary"/>
 *   <attribute name="PartyUInfo" type="hexBinary"/>
 *   <attribute name="PartyVInfo" type="hexBinary"/>
 *   <attribute name="SuppPubInfo" type="hexBinary"/>
 *   <attribute name="SuppPrivInfo" type="hexBinary"/
 * </complexType>}
 * </pre>
 * 
 * <p>
 * The AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo and SuppPrivInfo attributes are all defined as arbitrary-length
 * bitstrings, thus they may need to be padded in order to be encoded into hexBinary for XML Encryption. The following
 * padding and encoding method must be used when encoding bitstring values for the AlgorithmID, PartyUInfo, PartyVInfo,
 * SuppPubInfo and SuppPrivInfo:
 * </p>
 * <ol>
 * <li>The bitstring is divided into octets using big-endian encoding. If the length of the bitstring is not a multiple
 * of 8 then add padding bits (value 0) as necessary to the last octet to make it a multiple of 8.</li>
 * <li>Prepend one octet to the octets string from step 1. This octet shall identify (in a big-endian representation)
 * the number of padding bits added to the last octet in step 1.</li>
 * <li>Encode the octet string resulting from step 2 as a hexBinary string.</li>
 * </ol>
 * <p>
 * Example: the bitstring 11011, which is 5 bits long, gets 3 additional padding bits to become the bitstring 11011000
 * (or D8 in hex). This bitstring is then prepended with one octet identifying the number of padding bits to become the
 * octet string (in hex) 03D8, which then finally is encoded as a hexBinary string value of "03D8".
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ConcatKDFParams extends XMLObject {

  /** Element local name. */
  static final String DEFAULT_ELEMENT_LOCAL_NAME = "ConcatKDFParams";

  /** Default element name. */
  static final QName DEFAULT_ELEMENT_NAME = new QName(EncryptionConstants.XMLENC11_NS, DEFAULT_ELEMENT_LOCAL_NAME,
    EncryptionConstants.XMLENC11_PREFIX);

  /** Local name of the XSI type. */
  static final String TYPE_LOCAL_NAME = "ConcatKDFParamsType";

  /** QName of the XSI type. */
  static final QName TYPE_NAME = new QName(EncryptionConstants.XMLENC11_NS, TYPE_LOCAL_NAME, EncryptionConstants.XMLENC11_PREFIX);

  /** AlgorithmID attribute name. */
  static final String ALGORITHMID_ATTRIBUTE_NAME = "AlgorithmID";

  /** PartyUInfo attribute name. */
  static final String PARTY_UI_NFO_ATTRIBUTE_NAME = "PartyUInfo";

  /** PartyVInfo attribute name. */
  static final String PARTY_V_INFO_ATTRIBUTE_NAME = "PartyVInfo";

  /** SuppPubInfo attribute name. */
  static final String SUPP_PUB_INFO_ATTRIBUTE_NAME = "SuppPubInfo";

  /** SuppPrivInfo attribute name. */
  static final String SUPP_PRIV_INFO_ATTRIBUTE_NAME = "SuppPrivInfo";

  /**
   * Gets the digest method.
   * 
   * @return the digest method
   */
  DigestMethod getDigestMethod();

  /**
   * Sets the digest method.
   * 
   * @param digestMethod
   *          the digest method
   */
  void setDigestMethod(DigestMethod digestMethod);

  /**
   * Gets the {@code AlgorithmID} attribute in its padded and encoded form.
   * 
   * @return the {@code AlgorithmID} attribute
   */
  byte[] getAlgorithmID();

  /**
   * Sets the {@code AlgorithmID} attribute.
   * 
   * @param algorithmID
   *          the {@code AlgorithmID} attribute in its padded and encoded form
   */
  void setAlgorithmID(byte[] algorithmID);

  /**
   * Gets the {@code PartyUInfo} attribute in its padded and encoded form.
   * 
   * @return the {@code PartyUInfo} attribute
   */
  byte[] getPartyUInfo();

  /**
   * Sets the {@code PartyUInfo} attribute.
   * 
   * @param partyUInfo
   *          the {@code PartyUInfo} attribute in its padded and encoded form
   */
  void setPartyUInfo(byte[] partyUInfo);

  /**
   * Gets the {@code PartyVInfo} attribute in its padded and encoded form.
   * 
   * @return the {@code PartyVInfo} attribute
   */
  byte[] getPartyVInfo();

  /**
   * Sets the {@code PartyVInfo} attribute.
   * 
   * @param partyVInfo
   *          the {@code PartyVInfo} attribute in its padded and encoded form
   */
  void setPartyVInfo(byte[] partyVInfo);

  /**
   * Gets the {@code SuppPubInfo} attribute in its padded and encoded form.
   * 
   * @return the {@code SuppPubInfo} attribute
   */
  byte[] getSuppPubInfo();

  /**
   * Sets the {@code SuppPubInfo} attribute.
   * 
   * @param suppPubInfo
   *          the {@code SuppPubInfo} attribute in its padded and encoded form
   */
  void setSuppPubInfo(byte[] suppPubInfo);

  /**
   * Gets the {@code SuppPrivInfo} attribute in its padded and encoded form.
   * 
   * @return the {@code SuppPrivInfo} attribute
   */
  byte[] getSuppPrivInfo();

  /**
   * Sets the {@code SuppPrivInfo} attribute.
   * 
   * @param suppPrivInfo
   *          the {@code SuppPrivInfo} attribute in its padded and encoded form
   */
  void setSuppPrivInfo(byte[] suppPrivInfo);

}
