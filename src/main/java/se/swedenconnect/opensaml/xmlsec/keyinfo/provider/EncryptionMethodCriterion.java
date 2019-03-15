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
package se.swedenconnect.opensaml.xmlsec.keyinfo.provider;

import org.opensaml.xmlsec.encryption.EncryptionMethod;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.Criterion;

/**
 * A criterion containing an {@link EncryptionMethod} object.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EncryptionMethodCriterion implements Criterion {

  /** The encryption method. */
  private EncryptionMethod encryptionMethod;

  /**
   * Constructor.
   *
   * @param encryptionMethod
   *          the encryption method
   */
  public EncryptionMethodCriterion(EncryptionMethod encryptionMethod) {
    this.encryptionMethod = Constraint.isNotNull(encryptionMethod, "encryptionMethod must not be null");
  }

  /**
   * Returns the encryption method.
   * 
   * @return the encryption method
   */
  public EncryptionMethod getEncryptionMethod() {
    return this.encryptionMethod;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer("EncryptionMethodCriterion [encryptionMethod=[");
    sb.append("algorithm=").append(this.encryptionMethod.getAlgorithm());
    if (this.encryptionMethod.getKeySize() != null) {
      sb.append(",keySize=").append(this.encryptionMethod.getKeySize().getValue());
    }
    sb.append("]]");
    return sb.toString();
  }

}
