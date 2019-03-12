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
package se.swedenconnect.opensaml.xmlsec.encryption.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.signature.DigestMethod;

import se.swedenconnect.opensaml.xmlsec.encryption.ConcatKDFParams;

/**
 * Implementation class for {@link ConcatKDFParams}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ConcatKDFParamsImpl extends AbstractXMLObject implements ConcatKDFParams {

  /** The digest method. */
  private DigestMethod digestMethod;

  /** The {@code AlgorithmID} attribute. */
  private byte[] algorithmID;

  /** The {@code PartyUInfo} attribute. */
  private byte[] partyUInfo;

  /** The {@code PartyVInfo} attribute. */
  private byte[] partyVInfo;

  /** The {@code SuppPubInfo} attribute. */
  private byte[] suppPubInfo;

  /** The {@code SuppPrivInfo} attribute. */
  private byte[] suppPrivInfo;

  /**
   * Constructor.
   *
   * @param namespaceURI
   *          the namespace the element is in
   * @param elementLocalName
   *          the local name of the XML element this Object represents
   * @param namespacePrefix
   *          the prefix for the given namespace
   */
  protected ConcatKDFParamsImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
    super(namespaceURI, elementLocalName, namespacePrefix);
  }

  /** {@inheritDoc} */
  @Override
  public DigestMethod getDigestMethod() {
    return this.digestMethod;
  }

  /** {@inheritDoc} */
  @Override
  public void setDigestMethod(DigestMethod digestMethod) {
    this.digestMethod = this.prepareForAssignment(this.digestMethod, digestMethod);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getAlgorithmID() {
    return this.algorithmID != null ? Arrays.copyOf(this.algorithmID, this.algorithmID.length) : null;
  }

  /** {@inheritDoc} */
  @Override
  public void setAlgorithmID(byte[] algorithmID) {
    this.algorithmID = this.prepareForAssignment(this.algorithmID,
      algorithmID != null ? Arrays.copyOf(algorithmID, algorithmID.length) : null);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getPartyUInfo() {
    return this.partyUInfo != null ? Arrays.copyOf(this.partyUInfo, this.partyUInfo.length) : null;
  }

  /** {@inheritDoc} */
  @Override
  public void setPartyUInfo(byte[] partyUInfo) {
    this.partyUInfo = this.prepareForAssignment(this.partyUInfo,
      partyUInfo != null ? Arrays.copyOf(partyUInfo, partyUInfo.length) : null);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getPartyVInfo() {
    return this.partyVInfo != null ? Arrays.copyOf(this.partyVInfo, this.partyVInfo.length) : null;
  }

  /** {@inheritDoc} */
  @Override
  public void setPartyVInfo(byte[] partyVInfo) {
    this.partyVInfo = this.prepareForAssignment(this.partyVInfo,
      partyVInfo != null ? Arrays.copyOf(partyVInfo, partyVInfo.length) : null);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getSuppPubInfo() {
    return this.suppPubInfo != null ? Arrays.copyOf(this.suppPubInfo, this.suppPubInfo.length) : null;
  }

  /** {@inheritDoc} */
  @Override
  public void setSuppPubInfo(byte[] suppPubInfo) {
    this.suppPubInfo = this.prepareForAssignment(this.suppPubInfo,
      suppPubInfo != null ? Arrays.copyOf(suppPubInfo, suppPubInfo.length) : null);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getSuppPrivInfo() {
    return this.suppPrivInfo != null ? Arrays.copyOf(this.suppPrivInfo, this.suppPrivInfo.length) : null;
  }

  /** {@inheritDoc} */
  @Override
  public void setSuppPrivInfo(byte[] suppPrivInfo) {
    this.suppPrivInfo = this.prepareForAssignment(this.suppPrivInfo,
      suppPrivInfo != null ? Arrays.copyOf(suppPrivInfo, suppPrivInfo.length) : null);
  }

  /** {@inheritDoc} */
  @Override
  public List<XMLObject> getOrderedChildren() {
    if (this.digestMethod == null) {
      return null;
    }
    List<XMLObject> result = new ArrayList<>();
    result.add(this.digestMethod);
    return Collections.unmodifiableList(result);
  }

}
