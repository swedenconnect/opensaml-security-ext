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
package se.swedenconnect.opensaml.xmlsec.config;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.xmlsec.DecryptionConfiguration;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.SignatureValidationConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;

/**
 * Abstract base class for {@link SecurityConfiguration}. Sub-classes should implement the create-methods for the
 * different operations they wish to override.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractSecurityConfiguration implements SecurityConfiguration {

  /** Cache of the default encryption configuration. */
  private EncryptionConfiguration defaultEncryptionConfiguration;

  /** Cache of the default decryption configuration. */
  private DecryptionConfiguration defaultDecryptionConfiguration;

  /** Cache of the default signature configuration. */
  private SignatureSigningConfiguration defaultSignatureSigningConfiguration;

  /** Cache of the default signature validation configuration. */
  private SignatureValidationConfiguration defaultSignatureValidationConfiguration;

  /** Logger instance. */
  private Logger log = LoggerFactory.getLogger(AbstractSecurityConfiguration.class);

  /**
   * Constructor.
   * <p>
   * <b>Note:</b> Subclasses MUST NOT create any XML objects that require that OpenSAML has been initialized in the
   * constructor. The reason for this is that a {@link SecurityConfiguration} object most likely is setup as an argument
   * to the {@link OpenSAMLSecurityDefaultsConfig} which is passed to the {@link OpenSAMLInitializer}.
   * </p>
   */
  public AbstractSecurityConfiguration() {
  }

  /** {@inheritDoc} */
  @Override
  public final EncryptionConfiguration getEncryptionConfiguration() {
    EncryptionConfiguration config = this.getDefaultEncryptionConfiguration();
    if (config != null) {
      log.debug("Returning encryption configuration for profile '{}'", this.getProfileName());
      return config;
    }
    log.debug("No default encryption configuration configured for security configuration '{}', using OpenSAML defaults",
      this.getProfileName());

    config = ConfigurationService.get(EncryptionConfiguration.class);

    if (config == null) {
      log.warn("No EncryptionConfiguration object exists in OpenSAML configuration. Has OpenSAML been initialized?");
      log.debug("Using ExtendedDefaultSecurityConfigurationBootstrap to create encryption configuration");

      config = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    }
    return config;
  }

  /**
   * Returns the default encryption configuration for this instance.
   * 
   * @return default encryption configuration, or {@code null} if this security configuration object has not overridden
   *         the system defaults
   */
  protected final EncryptionConfiguration getDefaultEncryptionConfiguration() {
    if (this.defaultEncryptionConfiguration == null) {
      this.defaultEncryptionConfiguration = this.createDefaultEncryptionConfiguration();
    }
    return this.defaultEncryptionConfiguration;
  }

  /**
   * Creates the default encryption configuration for this instance.
   * <p>
   * The default implementation returns {@code null} which means that the {@link EncryptionConfiguration} held by
   * {@link ConfigurationService} will be returned when {@link SecurityConfiguration#getEncryptionConfiguration()} is
   * called.
   * </p>
   * 
   * @return default encryption configuration, or {@code null} if the security configuration object does not need to
   *         modify the system defaults
   */
  protected EncryptionConfiguration createDefaultEncryptionConfiguration() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public final DecryptionConfiguration getDecryptionConfiguration() {
    DecryptionConfiguration config = this.getDefaultDecryptionConfiguration();
    if (config != null) {
      log.debug("Returning decryption configuration for profile '{}'", this.getProfileName());
      return config;
    }
    log.debug("No default decryption configuration configured for security configuration '{}', using OpenSAML defaults",
      this.getProfileName());

    config = ConfigurationService.get(DecryptionConfiguration.class);

    if (config == null) {
      log.warn("No DecryptionConfiguration object exists in OpenSAML configuration. Has OpenSAML been initialized?");
      log.debug("Using DefaultSecurityConfigurationBootstrap to create encryption configuration");

      config = DefaultSecurityConfigurationBootstrap.buildDefaultDecryptionConfiguration();
    }
    return config;
  }

  /**
   * Returns the default decryption configuration for this instance.
   * 
   * @return default decryption configuration, or {@code null} if this security configuration object has not overridden
   *         the system defaults
   */
  protected final DecryptionConfiguration getDefaultDecryptionConfiguration() {
    if (this.defaultDecryptionConfiguration == null) {
      this.defaultDecryptionConfiguration = this.createDefaultDecryptionConfiguration();
    }
    return this.defaultDecryptionConfiguration;
  }

  /**
   * Creates the default decryption configuration for this instance.
   * <p>
   * The default implementation returns {@code null} which means that the {@link DecryptionConfiguration} held by
   * {@link ConfigurationService} will be returned when {@link SecurityConfiguration#getDecryptionConfiguration()} is
   * called.
   * </p>
   * 
   * @return default decryption configuration, or {@code null} if the security configuration object does not need to
   *         modify the system defaults
   */
  protected DecryptionConfiguration createDefaultDecryptionConfiguration() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public final SignatureSigningConfiguration getSignatureSigningConfiguration() {
    SignatureSigningConfiguration config = this.getDefaultSignatureSigningConfiguration();
    if (config != null) {
      log.debug("Returning signature configuration for profile '{}'", this.getProfileName());
      return config;
    }
    log.debug("No default signature configuration configured for security configuration '{}', using OpenSAML defaults",
      this.getProfileName());

    config = ConfigurationService.get(SignatureSigningConfiguration.class);

    if (config == null) {
      log.warn("No SignatureSigningConfiguration object exists in OpenSAML configuration. Has OpenSAML been initialized?");
      log.debug("Using DefaultSecurityConfigurationBootstrap to create signature configuration");

      config = DefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration();
    }
    return config;
  }

  /**
   * Returns the default signature configuration for this instance.
   * 
   * @return default signature configuration, or {@code null} if this security configuration object has not overridden
   *         the system defaults
   */
  protected final SignatureSigningConfiguration getDefaultSignatureSigningConfiguration() {
    if (this.defaultSignatureSigningConfiguration == null) {
      this.defaultSignatureSigningConfiguration = this.createDefaultSignatureSigningConfiguration();
    }
    return this.defaultSignatureSigningConfiguration;
  }

  /**
   * Creates the default signature configuration for this instance.
   * <p>
   * The default implementation returns {@code null} which means that the {@link SignatureSigningConfiguration} held by
   * {@link ConfigurationService} will be returned when {@link SecurityConfiguration#getSignatureSigningConfiguration()}
   * is called.
   * </p>
   * 
   * @return default signature configuration, or {@code null} if the security configuration object does not need to
   *         modify the system defaults
   */
  protected SignatureSigningConfiguration createDefaultSignatureSigningConfiguration() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public final SignatureValidationConfiguration getSignatureValidationConfiguration() {
    SignatureValidationConfiguration config = this.getDefaultSignatureValidationConfiguration();
    if (config != null) {
      log.debug("Returning signature validation configuration for profile '{}'", this.getProfileName());
      return config;
    }
    log.debug("No default signature validation configuration configured for security configuration '{}', using OpenSAML defaults",
      this.getProfileName());

    config = ConfigurationService.get(SignatureValidationConfiguration.class);

    if (config == null) {
      log.warn("No SignatureValidationConfiguration object exists in OpenSAML configuration. Has OpenSAML been initialized?");
      log.debug("Using DefaultSecurityConfigurationBootstrap to create signature configuration");

      config = DefaultSecurityConfigurationBootstrap.buildDefaultSignatureValidationConfiguration();
    }
    return config;
  }

  /**
   * Returns the default signature validation configuration for this instance.
   * 
   * @return default signature validation configuration, or {@code null} if this security configuration object has not
   *         overridden the system defaults
   */
  protected final SignatureValidationConfiguration getDefaultSignatureValidationConfiguration() {
    if (this.defaultSignatureValidationConfiguration == null) {
      this.defaultSignatureValidationConfiguration = this.createDefaultSignatureValidationConfiguration();
    }
    return this.defaultSignatureValidationConfiguration;
  }

  /**
   * Creates the default signature validation configuration for this instance.
   * <p>
   * The default implementation returns {@code null} which means that the {@link SignatureValidationConfiguration} held
   * by {@link ConfigurationService} will be returned when
   * {@link SecurityConfiguration#getSignatureValidationConfiguration()} is called.
   * </p>
   * 
   * @return default signature validation configuration, or {@code null} if the security configuration object does not
   *         need to modify the system defaults
   */
  protected SignatureValidationConfiguration createDefaultSignatureValidationConfiguration() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public void initOpenSAML() throws InitializationException {
    synchronized (ConfigurationService.class) {
      if (this.getDefaultEncryptionConfiguration() != null) {
        log.info("Security configuration for '{}' profile registers EncryptionConfiguration", this.getProfileName());
        ConfigurationService.register(EncryptionConfiguration.class, this.getDefaultEncryptionConfiguration());
      }
      if (this.getDefaultDecryptionConfiguration() != null) {
        log.info("Security configuration for '{}' profile registers DecryptionConfiguration", this.getProfileName());
        ConfigurationService.register(DecryptionConfiguration.class, this.getDefaultDecryptionConfiguration());
      }
      if (this.getDefaultSignatureSigningConfiguration() != null) {
        log.info("Security configuration for '{}' profile registers SignatureSigningConfiguration", this.getProfileName());
        ConfigurationService.register(SignatureSigningConfiguration.class, this.getDefaultSignatureSigningConfiguration());
      }
      if (this.getDefaultSignatureValidationConfiguration() != null) {
        log.info("Security configuration for '{}' profile registers SignatureValidationConfiguration", this.getProfileName());
        ConfigurationService.register(SignatureValidationConfiguration.class, this.getDefaultSignatureValidationConfiguration());
      }
    }
  }

}
