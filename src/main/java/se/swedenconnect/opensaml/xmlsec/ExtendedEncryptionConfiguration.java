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
package se.swedenconnect.opensaml.xmlsec;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;

/**
 * Extends OpenSAML's {@link EncryptionConfiguration} with support for key agreement and key derivation algorithms.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ExtendedEncryptionConfiguration extends EncryptionConfiguration {

  /**
   * Get the list of key agreement credentials to use, in preference order.
   * 
   * <p>
   * A key agreement credential is typically the peer public key that may be used in a key agreement protocol to
   * generate a key encryption/wrapping key.
   * </p>
   * 
   * @return the list of key agreement credentials, may be empty
   */
  @Nonnull
  @NonnullElements
  @Unmodifiable
  @NotLive
  List<Credential> getKeyAgreementCredentials();

  /**
   * Get the list of preferred agreement method algorithm URIs, in preference order.
   * 
   * @return the list of algorithm URIs, may be empty
   */
  @Nonnull
  @NonnullElements
  @Unmodifiable
  @NotLive
  List<String> getAgreementMethodAlgorithms();

  /**
   * Get the list of preferred key derivation algorithm URIs, in preference order.
   * 
   * @return the list of algorithm URIs, may be empty
   */
  @Nonnull
  @NonnullElements
  @Unmodifiable
  @NotLive
  List<String> getKeyDerivationAlgorithms();

  /**
   * Get the instance of {@link ConcatKDFParameters}.
   * 
   * @return the parameters instance
   */
  @Nullable
  ConcatKDFParameters getConcatKDFParameters();

}
