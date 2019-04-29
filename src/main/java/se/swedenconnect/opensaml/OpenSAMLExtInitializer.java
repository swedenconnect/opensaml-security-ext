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
package se.swedenconnect.opensaml;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;

/**
 * Singleton class for configuration of the OpenSAML Security extensions library.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLExtInitializer {

  /** Logger instance. */
  private Logger log = LoggerFactory.getLogger(OpenSAMLExtInitializer.class);

  /** The singleton instance. */
  private static OpenSAMLExtInitializer INSTANCE = new OpenSAMLExtInitializer();

  /**
   * Returns the initializer instance.
   * 
   * @return the initializer instance
   */
  public static OpenSAMLExtInitializer getInstance() {
    return INSTANCE;
  }

  /**
   * Initializes the OpenSAML library.
   * 
   * @throws Exception
   *           thrown if there is a problem initializing the library
   */
  public final synchronized void initialize() throws Exception {

    // Extend our configuration with support for key agreement.
    //
    EncryptionConfiguration encryptionConfiguration = null;
    synchronized (ConfigurationService.class) {
      encryptionConfiguration = ConfigurationService.get(EncryptionConfiguration.class);
      if (encryptionConfiguration == null) {
        log.info("OpenSAML has not been initialized");
        OpenSAMLInitializer.getInstance().initialize();
      }
    }

    if (ExtendedEncryptionConfiguration.class.isInstance(encryptionConfiguration)) {
      // It seems like the configuration already contains the extensions needed.
      return;
    }
    ExtendedEncryptionConfiguration extendedEncryptionConfiguration = ExtendedDefaultSecurityConfigurationBootstrap
      .buildDefaultEncryptionConfiguration(encryptionConfiguration);

    // Register the extended encryption configuration.
    //
    synchronized (ConfigurationService.class) {
      ConfigurationService.register(EncryptionConfiguration.class, extendedEncryptionConfiguration);
    }
    
    log.info("OpenSAML Security extensions has been successfully initialized");
  }

  // Hidden constructor
  private OpenSAMLExtInitializer() {
  }

}
