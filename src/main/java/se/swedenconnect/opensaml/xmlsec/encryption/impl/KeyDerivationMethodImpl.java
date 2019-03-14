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

import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.IndexedXMLObjectChildrenList;

import se.swedenconnect.opensaml.xmlsec.encryption.KeyDerivationMethod;

/**
 * Implementation class for {@link KeyDerivationMethod}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyDerivationMethodImpl extends AbstractXMLObject implements KeyDerivationMethod {

  /** Algorithm attribute. */
  private String algorithm;

  /** Any objects. */
  private IndexedXMLObjectChildrenList<XMLObject> unknownXMLObjects;

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
  protected KeyDerivationMethodImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
    super(namespaceURI, elementLocalName, namespacePrefix);
    this.unknownXMLObjects = new IndexedXMLObjectChildrenList<>(this);
  }
  
  /** {@inheritDoc} */
  public String getAlgorithm() {
    return this.algorithm;
  }

  /** {@inheritDoc} */
  public void setAlgorithm(String algorithm) {
    this.algorithm = prepareForAssignment(this.algorithm, algorithm);
  }  

  /** {@inheritDoc} */
  public List<XMLObject> getUnknownXMLObjects() {
    return this.unknownXMLObjects;
  }

  /** {@inheritDoc} */
  @SuppressWarnings("unchecked")
  public List<XMLObject> getUnknownXMLObjects(final QName typeOrName) {
    return (List<XMLObject>) this.unknownXMLObjects.subList(typeOrName);
  }
  
  /** {@inheritDoc} */
  public List<XMLObject> getOrderedChildren() {
    return Collections.unmodifiableList(this.unknownXMLObjects);
  }

}
