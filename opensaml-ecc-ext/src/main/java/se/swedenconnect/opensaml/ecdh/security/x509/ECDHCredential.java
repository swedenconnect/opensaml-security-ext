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

package se.swedenconnect.opensaml.ecdh.security.x509;

import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support.ECDHParameters;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.ConcatKDFParams;

import javax.annotation.Nonnull;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 *
 */
public class ECDHCredential extends BasicX509Credential {

    private ConcatKDFParams concatKDF;

    private PublicKey senderPubKey;

    /** ECDH parameters. */
    private ECDHParameters ecdhParameters;


    /** {@inheritDoc} */
    @Nonnull public Class<? extends Credential> getCredentialType() {
        return ECDHCredential.class;
    }

    /**
     * Constructor.
     *
     * @param entityCertificate
     */
    public ECDHCredential(X509Certificate entityCertificate) {
        super(entityCertificate);
    }

    public ConcatKDFParams getConcatKDF() {
        return concatKDF;
    }

    public void setConcatKDF(ConcatKDFParams concatKDF) {
        this.concatKDF = concatKDF;
    }

    public PublicKey getSenderPubKey() {
        return senderPubKey;
    }

    public void setSenderPubKey(PublicKey senderPubKey) {
        this.senderPubKey = senderPubKey;
    }

    public ECDHParameters getEcdhParameters() {
        return ecdhParameters;
    }

    public void setEcdhParameters(ECDHParameters ecdhParameters) {
        this.ecdhParameters = ecdhParameters;
    }
}
