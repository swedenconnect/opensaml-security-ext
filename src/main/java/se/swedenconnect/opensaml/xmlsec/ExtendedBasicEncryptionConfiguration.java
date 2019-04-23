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
package se.swedenconnect.opensaml.xmlsec;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import se.swedenconnect.opensaml.xmlsec.algorithm.ExtendedAlgorithmSupport;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;

/**
 * Extends OpenSAML's {@link BasicEncryptionConfiguration} so that we implement the
 * {@link ExtendedEncryptionConfiguration} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedBasicEncryptionConfiguration extends BasicEncryptionConfiguration implements ExtendedEncryptionConfiguration {

  /** Key agreement credentials. */
  @Nonnull
  @NonnullElements
  private List<Credential> keyAgreementCredentials;

  /** Key agreement credentials found among assigned key transport credentials. */
  @Nonnull
  @NonnullElements
  private List<Credential> additionalkeyAgreementCredentials;

  /** Agreement method algorithm URIs. */
  @Nonnull
  @NonnullElements
  private List<String> agreementMethodAlgorithms;

  /** Key derivation agorithm URIs. */
  @Nonnull
  @NonnullElements
  private List<String> keyDerivationAlgorithms;

  /** ConcatKDF parameters. */
  @Nullable
  private ConcatKDFParameters concatKDFParameters;

  /**
   * Constructor.
   */
  public ExtendedBasicEncryptionConfiguration() {
    super();
    this.keyAgreementCredentials = Collections.emptyList();
    this.additionalkeyAgreementCredentials = new ArrayList<>();
    this.agreementMethodAlgorithms = Collections.emptyList();
    this.keyDerivationAlgorithms = Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  @NonnullElements
  @Unmodifiable
  @NotLive
  public List<Credential> getKeyAgreementCredentials() {
    return ImmutableList.copyOf(Stream.concat(
      this.keyAgreementCredentials.stream(), this.additionalkeyAgreementCredentials.stream())
      .collect(Collectors.toList()));
  }

  /**
   * Sets the key agreement credentials to use.
   * <p>
   * A key agreement credential is typically the peer public key that may be used in a key agreement protocol to
   * generate a key encryption/wrapping key.
   * </p>
   * 
   * @param keyAgreementCredentials
   *          the list of key transport agreement credentials
   */
  public void setKeyAgreementCredentials(@Nullable final List<Credential> keyAgreementCredentials) {
    if (keyAgreementCredentials == null) {
      this.keyAgreementCredentials = Collections.emptyList();
      return;
    }
    this.keyAgreementCredentials = new ArrayList<>(Collections2.filter(keyAgreementCredentials, Predicates.notNull()));
  }

  /**
   * Since the core OpenSAML classes does not support key agreement, we override this method and look at each
   * credential. If the credential may be used in a key agreement protocol, we also save it among the key agreement
   * credentials (see {@link #setKeyAgreementCredentials(List)}).
   */
  @Override
  public void setKeyTransportEncryptionCredentials(List<Credential> credentials) {
    super.setKeyTransportEncryptionCredentials(credentials);

    if (credentials != null) {
      credentials.stream()
        .filter(ExtendedAlgorithmSupport::peerCredentialSupportsKeyAgreement)
        .forEach(this.additionalkeyAgreementCredentials::add);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  @NonnullElements
  @Unmodifiable
  @NotLive
  public List<String> getAgreementMethodAlgorithms() {
    return ImmutableList.copyOf(this.agreementMethodAlgorithms);
  }

  /**
   * Set the agreement method algorithms to use.
   * 
   * @param algorithms
   *          the list of algorithms
   */
  public void setAgreementMethodAlgorithms(@Nullable final List<String> algorithms) {
    if (algorithms == null) {
      this.agreementMethodAlgorithms = Collections.emptyList();
      return;
    }
    this.agreementMethodAlgorithms = new ArrayList<>(StringSupport.normalizeStringCollection(algorithms));
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  @NonnullElements
  @Unmodifiable
  @NotLive
  public List<String> getKeyDerivationAlgorithms() {
    return ImmutableList.copyOf(this.keyDerivationAlgorithms);
  }

  /**
   * Set the key derivation algorithms to use.
   * 
   * @param algorithms
   *          the list of algorithms
   */
  public void setKeyDerivationAlgorithms(@Nullable final List<String> algorithms) {
    if (algorithms == null) {
      this.keyDerivationAlgorithms = Collections.emptyList();
      return;
    }
    this.keyDerivationAlgorithms = new ArrayList<>(StringSupport.normalizeStringCollection(algorithms));
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public ConcatKDFParameters getConcatKDFParameters() {
    return this.concatKDFParameters;
  }

  /**
   * Assigns the default ConcatKDF parameters to be used during ConcatKDF key derivation.
   * 
   * @param concatKDFParameters
   *          the ConcatKDF parameters
   */
  public void setConcatKDFParameters(@Nullable final ConcatKDFParameters concatKDFParameters) {
    this.concatKDFParameters = concatKDFParameters;
  }

}
