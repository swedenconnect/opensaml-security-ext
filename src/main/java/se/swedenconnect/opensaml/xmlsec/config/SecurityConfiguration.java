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
package se.swedenconnect.opensaml.xmlsec.config;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.DecryptionConfiguration;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.SignatureValidationConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;

import se.swedenconnect.opensaml.OpenSAMLInitializer;

/**
 * An interface that enables us to work with security configurations and defaults in a simple fashion.
 * <p>
 * The OpenSAML {@link ConfigurationService} singleton may be queried for the configuration to use for a certain
 * security operation. For example, to get the {@link EncryptionConfiguration} to use, the following code gives us the
 * config for an encryption operation:
 * </p>
 * 
 * <pre><code>
 * EncryptionConfiguration encryptionConfiguration = ConfigurationService.get(EncryptionConfiguration.class);
 * </code></pre>
 * 
 * <p>
 * This is simple and straightforward, and you should probably stick with that way of getting the system defaults for
 * security configuration. However, in some cases, for example when a SAML SP or IdP should support several different
 * profiles regarding security configuration the above doesn't work that well. In these cases you may instantiate
 * different {@code SecurityConfiguration} objects with different defaults, and use those objects to query for the
 * security configuration.
 * </p>
 * 
 * <pre><code>SecurityConfiguration saml2intConfig = setupSaml2intConfig();
 * ...
 * EncryptionConfig config = saml2intConfig.getEncryptionConfiguration();</code></pre>
 * 
 * <p>
 * When OpenSAML is initialized (using {@link InitializationService#initialize()}) the {@link ConfigurationService} will
 * be assigned the default values from the {@link DefaultSecurityConfigurationBootstrap} class. After OpenSAML has been
 * initialized it is possible to modify these defaults by replacing the stored default objects.
 * </p>
 * 
 * <pre><code>EncryptionConfiguration myEncryptionConfiguration = ...;
 * ... a lot of code setting algorithms ...
 * ConfigurationService.register(EncryptionConfiguration.class, myEncryptionConfiguration);</code></pre>
 * 
 * <p>
 * By using a {@code SecurityConfiguration} object this step may be simplified. For example, to configure the system to
 * use the SAML2Int algorithm requirements you simply do:
 * </p>
 * 
 * <pre><code>SecurityConfiguration saml2intConfig = new SAML2IntSecurityConfiguration();
 * saml2intConfig.initOpenSAML();</code></pre>
 * <p>
 * If you use the {@link OpenSAMLInitializer} you can do the following instead:
 * </p>
 * 
 * <pre><code>OpenSAMLInitializer.getInstance().initialize(
 *   new OpenSAMLSecurityExtensionConfig(),
 *   new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()));</code></pre>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SecurityConfiguration {

  /**
   * Gets the profile name of this configuration setup.
   * 
   * @return the profile name
   */
  String getProfileName();

  /**
   * Returns the encryption configuration that has been configured.
   * 
   * @return encryption configuration
   */
  EncryptionConfiguration getEncryptionConfiguration();

  /**
   * Returns the decryption configuration that has been configured.
   * 
   * @return decryption configuration
   */
  DecryptionConfiguration getDecryptionConfiguration();

  /**
   * Returns the signing configuration that has been configued.
   * 
   * @return signing configuration
   */
  SignatureSigningConfiguration getSignatureSigningConfiguration();

  /**
   * Returns the signature validation configuration that has been configured.
   * 
   * @return signature validation configuration
   */
  SignatureValidationConfiguration getSignatureValidationConfiguration();

  /**
   * Initializes OpenSAML with the defaults that has been installed for this instance.
   * 
   * <p>
   * {@code ConfigurationService.register(XXXConfiguration.class, xxxConfiguration);}
   * </p>
   * 
   * @throws InitializationException
   *           for initialization errors
   */
  void initOpenSAML() throws InitializationException;

}
