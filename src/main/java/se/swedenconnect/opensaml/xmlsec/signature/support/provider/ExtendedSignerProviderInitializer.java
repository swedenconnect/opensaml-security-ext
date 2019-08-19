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
package se.swedenconnect.opensaml.xmlsec.signature.support.provider;

import java.net.URL;
import java.net.URLClassLoader;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.Initializer;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.SignerProvider;
import org.opensaml.xmlsec.signature.support.impl.provider.ApacheSantuarioSignerProviderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * OpenSAML uses the Java service loader to load the {@link SignerProvider} that should be used. Any number of providers
 * may be on the classpath and if we want to have a particular one loaded (and cached) by the {@link Signer} class we
 * have to make sure that this one is before any other provider on the classpath. So, not an ideal case, but not a
 * problem since the only provider used in a default setup is {@link ApacheSantuarioSignerProviderImpl}. But since we
 * extend this class with workraounds for RSAPSS, we want to make sure that our {@link ExtendedSignerProvider} is loaded
 * before the default provider, no matter how the classpath looks.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedSignerProviderInitializer implements Initializer {

  /** Logger. */
  private Logger log = LoggerFactory.getLogger(ExtendedSignerProviderInitializer.class);

  /**
   * The {@link Signer} class has a static signer provider cached. This provider is set the first time the
   * {@link Signer#signObject(org.opensaml.xmlsec.signature.Signature)} method is called. So what we want to do is to
   * modify the classpath so that the resource that holds our extended signer provider is always found first. Once, that
   * is done, we invoke the {@code signObject} method which will set the cached provider to our implementation.
   */
  @Override
  public synchronized void init() throws InitializationException {

    log.debug("Setting up {} as system signer provider ...", ExtendedSignerProvider.class.getSimpleName());

    // First get the URL to the resource that holds our extended signer provider.
    //
    URL jarPath;
    try {
      jarPath = ExtendedSignerProvider.class.getProtectionDomain().getCodeSource().getLocation();
      log.debug("Will load extended signer provider from {}", jarPath.toExternalForm());
    }
    catch (SecurityException | NullPointerException e) {
      log.error("Failed to get path to extended signer provider", e);
      log.warn("Can not guarantee that {} will be used", ExtendedSignerProvider.class.getSimpleName());
      return;
    }

    // Install our own custom class loader and invoke signObject to get the caching done.
    //
    ClassLoader defaultLoader = null;
    try {
      defaultLoader = Thread.currentThread().getContextClassLoader();

      URLClassLoader customLoader = new URLClassLoader(new URL[] { jarPath },
        defaultLoader != null ? defaultLoader : ClassLoader.getSystemClassLoader());

      Thread.currentThread().setContextClassLoader(customLoader);

      try {
        Signer.signObject(null);
      }
      catch (ConstraintViolationException | NullPointerException | SignatureException expected) {
        // We expect ConstraintViolationException ...
      }
      log.info("{} has now been cached as the signer provider used by the {} class", 
        ExtendedSignerProvider.class.getName(), Signer.class.getName());
    }
    catch (SecurityException e) {
      log.error("Failed to modify classpath for installation of extended signer provider", e);
      log.warn("Can not guarantee that {} will be used", ExtendedSignerProvider.class.getSimpleName());
    }
    finally {
      if (defaultLoader != null) {
        try {
          Thread.currentThread().setContextClassLoader(defaultLoader);
        }
        catch (SecurityException e) {          
        }
      }
    }
  }

}
