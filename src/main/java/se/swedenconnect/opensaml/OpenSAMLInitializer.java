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
package se.swedenconnect.opensaml;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;

/**
 * Singleton class for initialization and configuration of the OpenSAML library.
 * 
 * @author Martin Lindström (martin@idsec.se)
 */
public class OpenSAMLInitializer {

  /** Logger instance. */
  private Logger log = LoggerFactory.getLogger(OpenSAMLInitializer.class);

  /** Whether OpenSAML already has been initialized. */
  private boolean initialized;

  /** The initializer may be assigned a configured parser pool. */
  private ParserPool parserPool;

  /** Builder features for the default parser pool. */
  private static final Map<String, Boolean> builderFeatures;

  static {
    builderFeatures = new HashMap<>();
    builderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
    builderFeatures.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
    builderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);
  }

  /** The singleton instance. */
  private static OpenSAMLInitializer INSTANCE = new OpenSAMLInitializer();

  /**
   * Returns the initializer instance.
   * 
   * @return the initializer instance
   */
  public static OpenSAMLInitializer getInstance() {
    return INSTANCE;
  }

  /**
   * Predicate that tells if the OpenSAML library already has been initialized.
   * 
   * @return if the library has been initialized true is returned, otherwise false
   */
  public boolean isInitialized() {
    return this.initialized;
  }

  /**
   * Initializes the OpenSAML library.
   * 
   * <p>
   * The {@link OpenSAMLInitializerConfig#preInitialize()} for all supplied {@code customConfigs} are called in order
   * before OpenSAML is initialized ({@link InitializationService#initialize()}. After OpenSAML has been initialized,
   * all {@link OpenSAMLInitializerConfig#postInitialize()} methods are invoked.
   * </p>
   * 
   * @param customConfigs
   *          custom configuration of OpenSAML
   * @throws Exception
   *           thrown if there is a problem initializing the library
   */
  public final synchronized void initialize(final OpenSAMLInitializerConfig... customConfigs) throws Exception {

    if (this.initialized) {
      log.info("OpenSAML library has already been initialized");
      return;
    }
    
    if (customConfigs != null) {
      for (OpenSAMLInitializerConfig config : customConfigs) {
        log.debug("Invoking preInitialize for configurer '{}' ...", config.getName());
        config.preInitialize();
        log.debug("preInitialize for configurer '{}' was successfully executed", config.getName());
      }
    }

    log.debug("Initializing OpenSAML library...");

    InitializationService.initialize();

    XMLObjectProviderRegistry registry;
    synchronized (ConfigurationService.class) {
      registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
      if (registry == null) {
        log.debug("XMLObjectProviderRegistry did not exist in ConfigurationService, will be created");
        registry = new XMLObjectProviderRegistry();
        ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
      }
    }
    if (this.parserPool != null) {
      log.debug("Installing configured parser pool to XMLObjectProviderRegistry...");
      registry.setParserPool(this.parserPool);
    }
    else if (registry.getParserPool() == null) {
      log.debug("Installing default parser pool to XMLObjectProviderRegistry...");
      registry.setParserPool(createDefaultParserPool());
    }

    log.info("OpenSAML library successfully initialized");
    
    if (customConfigs != null) {
      for (OpenSAMLInitializerConfig config : customConfigs) {
        log.debug("Invoking postInitialize for configurer '{}' ...", config.getName());
        config.postInitialize();
        log.debug("postInitialize for configurer '{}' was successfully executed", config.getName());
      }
    }

    this.initialized = true;
  }

  /**
   * Set the global ParserPool to configure.
   * 
   * @param parserPool
   *          the parserPool to assign
   */
  public void setParserPool(final ParserPool parserPool) {
    this.parserPool = parserPool;
    if (this.isInitialized()) {
      log.info("OpenSAML library has already been initialized - setting supplied parser pool to registry");
      XMLObjectProviderRegistrySupport.setParserPool(parserPool);
    }
  }

  /**
   * Creates a basic parser pool with default settings.
   * 
   * @return the default parser pool
   * @throws ComponentInitializationException
   *           for init errors
   */
  public static ParserPool createDefaultParserPool() throws ComponentInitializationException {
    BasicParserPool basicParserPool = new BasicParserPool();
    basicParserPool.setMaxPoolSize(100);
    basicParserPool.setCoalescing(true);
    basicParserPool.setIgnoreComments(true);
    basicParserPool.setIgnoreElementContentWhitespace(true);
    basicParserPool.setNamespaceAware(true);
    basicParserPool.setBuilderFeatures(builderFeatures);
    basicParserPool.initialize();
    return basicParserPool;
  }

  // Hidden constructor
  protected OpenSAMLInitializer() {
  }

}
