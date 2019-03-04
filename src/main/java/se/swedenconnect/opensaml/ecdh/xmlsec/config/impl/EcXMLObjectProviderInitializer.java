package se.swedenconnect.opensaml.ecdh.xmlsec.config.impl;

import org.opensaml.core.xml.config.AbstractXMLObjectProviderInitializer;

/**
 * Add EC Encryption config resources
 */
public class EcXMLObjectProviderInitializer extends AbstractXMLObjectProviderInitializer {

  /** Config resources. */
  private static String[] configs = {
    "/ec-encryption-config.xml"
  };

  /** {@inheritDoc} */
  protected String[] getConfigResources() {
    return configs;
  }

}
