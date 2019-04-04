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

import java.util.Iterator;
import java.util.ServiceLoader;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.Initializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.xmlsec.algorithm.descriptors.NamedCurve;
import se.swedenconnect.opensaml.xmlsec.algorithm.descriptors.NamedCurveRegistry;

/**
 * OpenSAML {@link Initializer} implementation for named curves.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurveRegistryInitializer implements Initializer {

  /** Logger. */
  private Logger log = LoggerFactory.getLogger(NamedCurveRegistryInitializer.class);

  /** {@inheritDoc} */
  @Override
  public void init() throws InitializationException {
    final NamedCurveRegistry registry = new NamedCurveRegistry();
    final ServiceLoader<NamedCurve> loader = ServiceLoader.load(NamedCurve.class);
    final Iterator<NamedCurve> iter = loader.iterator();
    while (iter.hasNext()) {
      final NamedCurve curve = iter.next();
      log.debug("Registering NamedCurve of name '{}' with OID '{}' (keyLength: {}): {}",
        curve.getName(), curve.getObjectIdentifier(), curve.getKeyLength(), curve.getClass().getName());
      registry.register(curve);
    }

    ConfigurationService.register(NamedCurveRegistry.class, registry);
  }

}
