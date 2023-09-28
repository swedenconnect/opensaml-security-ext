/*
 * Copyright 2019-2023 Sweden Connect
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
package se.swedenconnect.opensaml;

import net.shibboleth.shared.logic.Constraint;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.xmlsec.config.SecurityConfiguration;

/**
 * Initializer that modifies OpenSAML's default algorithms as returned by {@link DefaultSecurityConfigurationBootstrap}
 * with the caller's own wishes for security defaults.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLSecurityDefaultsConfig implements OpenSAMLInitializerConfig {

  /** Logger instance. */
  private Logger log = LoggerFactory.getLogger(OpenSAMLSecurityDefaultsConfig.class);

  /** The security configuration to install. */
  private SecurityConfiguration securityConfiguration;

  /**
   * Constructor.
   *
   * @param securityConfiguration
   *          the security configuration to install
   */
  public OpenSAMLSecurityDefaultsConfig(final SecurityConfiguration securityConfiguration) {
    this.securityConfiguration = Constraint.isNotNull(securityConfiguration, "securityConfiguration must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "opensaml-security-config";
  }

  /**
   * Does nothing.
   */
  @Override
  public void preInitialize() throws Exception {
  }

  /**
   * Updates OpenSAML with the security configuration for this object.
   */
  @Override
  public void postInitialize() throws Exception {
    log.info("Updating OpenSAML security configuration defaults using profile '{}' ...",
      this.securityConfiguration.getProfileName());

    this.securityConfiguration.initOpenSAML();

    log.info("OpenSAML security configuration defaults updated by profile {}",
      this.securityConfiguration.getProfileName());
  }

}
