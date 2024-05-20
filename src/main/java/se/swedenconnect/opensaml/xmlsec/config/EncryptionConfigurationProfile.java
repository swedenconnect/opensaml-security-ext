package se.swedenconnect.opensaml.xmlsec.config;

import org.opensaml.saml.security.SAMLMetadataKeyAgreementEncryptionConfiguration;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.KeyAgreementEncryptionConfiguration;
import org.opensaml.xmlsec.impl.BasicEncryptionConfiguration;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Provides profiled encryption configurations and tools to do some useful customizations
 *
 * <p>
 *   This class is motivated primarily because key wrapping with ECDH will not be executed unless peer metadata indicates that
 *   the recipient supports this feature.
 *   This is fixed by setting a common key wrap policy to "Allways".
 *   This class provides two default encryption configurations that support key wrap with ECDH.
 * </p>
 */
public class EncryptionConfigurationProfile {

  /**
   * Default SAML encryption configuration with default Key Wrap settings
   */
  public static final EncryptionConfiguration DEFAULT_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP;

  /**
   * Default eIDAS SAML encryption configuration with default Key Wrap settings
   */
  public static final EncryptionConfiguration EIDAS_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP;

  static {
    DEFAULT_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP = getCustomEncryptConfiguration(
      null, null, SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always
    );
    EIDAS_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP = getCustomEncryptConfiguration(
      List.of(
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#aes192-gcm"
      ),
      List.of(
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        "http://www.w3.org/2001/04/xmlenc#kw-aes256",
        "http://www.w3.org/2001/04/xmlenc#kw-aes128",
        "http://www.w3.org/2001/04/xmlenc#kw-aes192"
      ),
      SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always
    );
  }

  /**
   * Create a custom encryption configuration using specified algorithms and default key wrap policy
   * @param supportedEncAlgs supported encryption algorithms
   * @param supportedKeyWrapAlgs supported key wrap algorithms
   * @param keyWrapPolicy default key wrap policy
   * @return custom encryption configuration
   */
  public static EncryptionConfiguration getCustomEncryptConfiguration(List<String> supportedEncAlgs, List<String> supportedKeyWrapAlgs,
   SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap keyWrapPolicy) {
    // Create configuration
    BasicEncryptionConfiguration encryptionConfiguration = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    // Set supported data encryption algorithms
    if (supportedEncAlgs != null) {
      encryptionConfiguration.setDataEncryptionAlgorithms(supportedEncAlgs);
    }
    // Set key transport encryption algorithms
    if (supportedKeyWrapAlgs != null) {
      encryptionConfiguration.setKeyTransportEncryptionAlgorithms(supportedKeyWrapAlgs);
    }
    // Set default key wrap functionality
    if (keyWrapPolicy != null) {
      encryptionConfiguration.setKeyAgreementConfigurations(updateDefaultKeyWrapPolicy(
        encryptionConfiguration.getKeyAgreementConfigurations(), keyWrapPolicy));
    }
    return encryptionConfiguration;
  }

  /**
   * Update the key agreement configuration with a default key wrap policy
   *
   * @param originConfig original key agreement configuration to update
   * @param keyWrapPolicy key wrap policy for all key types
   * @return updated agreement configuration
   */
  public static Map<String, KeyAgreementEncryptionConfiguration> updateDefaultKeyWrapPolicy(Map<String, KeyAgreementEncryptionConfiguration> originConfig,
    SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap keyWrapPolicy) {
    return updateDefaultKeyWrapPolicy(originConfig,
      originConfig.keySet().stream()
        .collect(Collectors.toMap(Function.identity(),
          kw -> keyWrapPolicy))
    );
  }

  /**
   * Update the key agreement configuration with a default key wrap policy
   *
   * @param originConfig original key agreement configuration to update
   * @param keyWrapPolicyMap a map of key wrap policy per key type
   * @return updated agreement configuration
   */
  public static Map<String, KeyAgreementEncryptionConfiguration> updateDefaultKeyWrapPolicy(Map<String, KeyAgreementEncryptionConfiguration> originConfig,
    Map<String, SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap> keyWrapPolicyMap) {

    Map<String, KeyAgreementEncryptionConfiguration> keyAgreementConfigurations = new HashMap<>(originConfig);
    keyWrapPolicyMap.keySet()
      .forEach(type -> {
        KeyAgreementEncryptionConfiguration ecKeyAgreementParams = keyAgreementConfigurations.get(type);
        SAMLMetadataKeyAgreementEncryptionConfiguration samlEcKeyAgreementParams = new SAMLMetadataKeyAgreementEncryptionConfiguration();
        samlEcKeyAgreementParams.setMetadataUseKeyWrap(keyWrapPolicyMap.get(type));
        samlEcKeyAgreementParams.setAlgorithm(ecKeyAgreementParams.getAlgorithm());
        samlEcKeyAgreementParams.setParameters(ecKeyAgreementParams.getParameters());
        keyAgreementConfigurations.put(type, samlEcKeyAgreementParams);
      });
    return keyAgreementConfigurations;
  }

}
