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

package se.swedenconnect.opensaml.ecdh.xmlsec.encryption.impl;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.IndexedXMLObjectChildrenList;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.KeyDerivationMethod;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 */
public class KeyDerivationMethodImpl extends AbstractXMLObject implements KeyDerivationMethod {

    /** Algorithm attribute value. */
    private String algorithm;

    /** List of wildcard &lt;any&gt; XMLObject children. */
    private IndexedXMLObjectChildrenList xmlChildren;

    /**
     * Constructor.
     *
     * @param namespaceURI
     * @param elementLocalName
     * @param namespacePrefix
     */
    protected KeyDerivationMethodImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        xmlChildren = new IndexedXMLObjectChildrenList(this);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getOrderedChildren() {
        final ArrayList<XMLObject> children = new ArrayList<>();
        children.addAll(xmlChildren);
        if (children.size() == 0) {
            return null;
        }
        return Collections.unmodifiableList(children);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getUnknownXMLObjects() {
        return (List<XMLObject>) this.xmlChildren;
    }

    /** {@inheritDoc} */
    public List<XMLObject> getUnknownXMLObjects(final QName typeOrName) {
        return (List<XMLObject>) this.xmlChildren.subList(typeOrName);
    }

    /** {@inheritDoc} */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /** {@inheritDoc} */
    public void setAlgorithm(final String newAlgorithm) {
        this.algorithm = prepareForAssignment(this.algorithm, newAlgorithm);
    }
}
