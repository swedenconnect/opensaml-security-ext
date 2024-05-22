/*
 * Copyright 2019-2024 Sweden Connect
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

import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;

/**
 * A security configuration for OpenSAML default settings.
 * <p>
 * For a listing of the security defaults see {@link ExtendedDefaultSecurityConfigurationBootstrap} and
 * {@link DefaultSecurityConfigurationBootstrap}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultSecurityConfiguration extends AbstractSecurityConfiguration {

  /** {@inheritDoc} */
  @Override
  public String getProfileName() {
    return "opensaml-extensions-default";
  }

  /**
   * Returns the default signing configuration with RSA-PSS extensions.
   */
  @Override
  protected SignatureSigningConfiguration createDefaultSignatureSigningConfiguration() {
    return ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration();
  }

  @Override
  protected EncryptionConfiguration createDefaultEncryptionConfiguration() {
    return ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
  }

}
