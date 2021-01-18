/*
 * Copyright 2019-2021 Sweden Connect
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

import org.opensaml.core.xml.ElementExtensibleXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

/**
 * Represents the {@code xenc:KeyDerivationMethod} element.
 * 
 * <pre>
 * {@code
 * <element name="KeyDerivationMethod" type="xenc:KeyDerivationMethodType"/>
 *
 * <complexType name="KeyDerivationMethodType">
 *   <sequence>
 *     <any namespace="##any" minOccurs="0" maxOccurs="unbounded"/>
 *   </sequence>
 *   <attribute name="Algorithm" type="anyURI" use="required"/>
 * </complexType>}
 * </pre>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface KeyDerivationMethod extends XMLObject, ElementExtensibleXMLObject {

  /** Element local name. */
  public static final String DEFAULT_ELEMENT_LOCAL_NAME = "KeyDerivationMethod";

  /** Default element name. */
  public static final QName DEFAULT_ELEMENT_NAME = new QName(EncryptionConstants.XMLENC11_NS, DEFAULT_ELEMENT_LOCAL_NAME,
    EncryptionConstants.XMLENC11_PREFIX);

  /** Local name of the XSI type. */
  public static final String TYPE_LOCAL_NAME = "KeyDerivationMethodType";

  /** QName of the XSI type. */
  public static final QName TYPE_NAME = new QName(EncryptionConstants.XMLENC11_NS, TYPE_LOCAL_NAME, EncryptionConstants.XMLENC11_PREFIX);

  /** Algorithm attribute name. */
  public static final String ALGORITHM_ATTRIBUTE_NAME = "Algorithm";

  /**
   * Gets the algorithm URI attribute.
   * 
   * @return the algorithm
   */
  String getAlgorithm();

  /**
   * Sets the algorithm URI attribute.
   * 
   * @param algorithm
   *          the algorithm
   */
  void setAlgorithm(String algorithm);
}
