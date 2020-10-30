/*
 * Copyright 2019-2020 Sweden Connect
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
package se.swedenconnect.opensaml.xmlsec.keyinfo.provider;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.criteria.impl.EvaluableCredentialCriterion;
import org.opensaml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Instance of evaluable credential criteria for evaluating whether a credential's certificate meets the criteria
 * specified by the set of certificates found in a KeyInfo's list of certificates.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EvaluableX509CertificatesCredentialCriterion implements EvaluableCredentialCriterion {

  /** Class logger. */
  private static final Logger log = LoggerFactory.getLogger(EvaluableX509CertificatesCredentialCriterion.class);

  /** The selectors we use to match certificates. */
  private List<X509CertSelector> selectors;

  /**
   * Constructor.
   *
   * @param certificates
   *          a list of certificate encodings (from a KeyInfo)
   */
  public EvaluableX509CertificatesCredentialCriterion(@Nonnull final List<org.opensaml.xmlsec.signature.X509Certificate> certificates) {
    Constraint.isNotNull(certificates, "certificates must not be null");

    this.selectors = new ArrayList<>();

    // Transform the supplied certificate encodings into selector instances.
    //
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X.509");
    }
    catch (CertificateException e) {
      throw new RuntimeException(e);
    }

    for (org.opensaml.xmlsec.signature.X509Certificate c : certificates) {
      try {
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(
          (X509Certificate) factory.generateCertificate(
            new ByteArrayInputStream(Base64Support.decode(c.getValue()))));
        this.selectors.add(selector);
      }
      catch (Exception e) {
        log.error("Failed to decode certificate", e);
        continue;
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean test(final Credential input) {
    if (input == null) {
      log.error("Credential input was null");
      return false;
    }
    else if (!X509Credential.class.isInstance(input)) {
      log.info("Credential is not an X509Credential, cannot evaluate certificate criteria");
      return false;
    }
    X509Certificate entityCertificate = ((X509Credential) input).getEntityCertificate();
    if (entityCertificate == null) {
      log.info("X509Credential did not contain an entity certificate, cannot evaluate certificate criteria");
      return false;
    }
    for (X509CertSelector selector : this.selectors) {
      if (selector.match(entityCertificate)) {
        return true;
      }
    }

    return false;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "EvaluableX509CertificatesCredentialCriterion [selectors=<contents not displayable>]";
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (this.selectors == null ? 0 : this.selectors.hashCode());
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (this.getClass() != obj.getClass()) {
      return false;
    }
    EvaluableX509CertificatesCredentialCriterion other = (EvaluableX509CertificatesCredentialCriterion) obj;
    if (this.selectors == null) {
      if (other.selectors != null) {
        return false;
      }
    }
    else if (!this.selectors.equals(other.selectors)) {
      return false;
    }
    return true;
  }

}
