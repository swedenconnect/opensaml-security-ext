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

package se.swedenconnect.opensaml.ecdh.xmlsec.encryption;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.DigestMethod;

import javax.annotation.Nullable;
import javax.xml.namespace.QName;

/**
 *
 */
public interface ConcatKDFParams extends XMLObject {

    /** Element local name. */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "ConcatKDFParams";

    /** Default element name. */
    public static final QName DEFAULT_ELEMENT_NAME =
            new QName(EncryptionConstants.XMLENC11_NS, DEFAULT_ELEMENT_LOCAL_NAME, EncryptionConstants.XMLENC11_PREFIX);

    /** Local name of the XSI type. */
    public static final String TYPE_LOCAL_NAME = "ConcatKDFParamsType";

    /** QName of the XSI type. */
    public static final QName TYPE_NAME =
            new QName(EncryptionConstants.XMLENC11_NS, TYPE_LOCAL_NAME, EncryptionConstants.XMLENC11_PREFIX);

    /** AlgorithmID attribute name. */
    public static final String ALGORITHMID_ATTRIBUTE_NAME = "AlgorithmID";

    /** PartyUInfo attribute name. */
    public static final String PARTYUINFO_ATTRIBUTE_NAME = "PartyUInfo";

    /** PartyVInfo attribute name. */
    public static final String PARTYVINFO_ATTRIBUTE_NAME = "PartyVInfo";

    /** SuppPubInfo attribute name. */
    public static final String SUPPPUBINFO_ATTRIBUTE_NAME = "SuppPubInfo";

    /** SuppPrivInfo attribute name. */
    public static final String SUPPPRIVINFO_ATTRIBUTE_NAME = "SuppPrivInfo";

    @Nullable public byte[] getAlgorithmID();

    public void setAlgorithmID(@Nullable byte[] algorithmID);

    @Nullable public byte[] getPartyUInfo();

    public void setPartyUInfo(@Nullable byte[] partyUInfo);

    @Nullable public byte[] getPartyVInfo();

    public void setPartyVInfo(@Nullable byte[] partyVInfo);

    @Nullable public byte[] getSuppPubInfo();

    public void setSuppPubInfo(@Nullable byte[] suppPubInfo);

    @Nullable public byte[] getSuppPrivInfo();

    public void setSuppPrivInfo(@Nullable byte[] suppPrivInfo);

    @Nullable public DigestMethod getDigestMethod();

    public void setDigestMethod(DigestMethod digestMethod);
}
