package se.swedenconnect.opensaml.xmlsec.config;

import org.opensaml.saml.security.SAMLMetadataKeyAgreementEncryptionConfiguration;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
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
  public static final BasicEncryptionConfiguration DEFAULT_ENCRYPTION_CONFIG;
  /**
   * Default SAML encryption configuration with default Key Wrap settings
   */
  public static final BasicEncryptionConfiguration DEFAULT_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP;

  /**
   * Default eIDAS SAML encryption configuration with default Key Wrap settings
   */
  public static final BasicEncryptionConfiguration EIDAS_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP;

  /**
   * Strict eIDAS version 1.3 SAML encryption configuration with default Key Wrap settings
   */
  public static final BasicEncryptionConfiguration STRICT_EIDAS_1_3_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP;

  /**
   * Strict eIDAS version 1.4 SAML encryption configuration with default Key Wrap settings
   */
  public static final BasicEncryptionConfiguration STRICT_EIDAS_1_4_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP;

  static {
    DEFAULT_ENCRYPTION_CONFIG = EncryptionConfigurationProfile.builder().build();

    DEFAULT_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP = EncryptionConfigurationProfile.builder()
      .keyWrapPolicy(SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always)
      .build();

    EIDAS_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP = EncryptionConfigurationProfile.builder()
      .encryptionAlgorithms(List.of(
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#aes192-gcm"
      ))
      .keyWrapEncryptionAlgorithms(List.of(
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        "http://www.w3.org/2001/04/xmlenc#kw-aes256",
        "http://www.w3.org/2001/04/xmlenc#kw-aes128",
        "http://www.w3.org/2001/04/xmlenc#kw-aes192"
      ))
      .keyWrapPolicy(SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always)
      .build();

    STRICT_EIDAS_1_3_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP = EncryptionConfigurationProfile.builder()
      .encryptionAlgorithms(List.of(
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#aes192-gcm"
      ))
      .keyWrapEncryptionAlgorithms(List.of(
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        "http://www.w3.org/2001/04/xmlenc#kw-aes256",
        "http://www.w3.org/2001/04/xmlenc#kw-aes128",
        "http://www.w3.org/2001/04/xmlenc#kw-aes192"
      ))
      .keyWrapPolicy(SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always)
      .excludedAlgorithms(List.of(
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES,
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256
      ))
      .build();

    STRICT_EIDAS_1_4_ENCRYPTION_CONFIG_WITH_DEFAULT_KEY_WRAP = EncryptionConfigurationProfile.builder()
      .encryptionAlgorithms(List.of(
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#aes192-gcm"
      ))
      .keyWrapEncryptionAlgorithms(List.of(
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        "http://www.w3.org/2001/04/xmlenc#kw-aes256",
        "http://www.w3.org/2001/04/xmlenc#kw-aes128",
        "http://www.w3.org/2001/04/xmlenc#kw-aes192"
      ))
      .keyWrapPolicy(SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap.Always)
      .excludedAlgorithms(List.of(
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES,
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192,
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP
      ))
      .build();
  }

  /**
   * Returns a builder for building an encryption configuration profile;
   * @return builder
   */
  public static Builder builder() {
    return new Builder();
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

  /**
   * Builder for encryption configuration profiles
   */
  public static class Builder {

    /** Base encrypt configuration to be modified */
    private BasicEncryptionConfiguration baseEncryptConfiguration;
    /** List of supported encryption algorithms */
    private List<String> supportedEncAlgs;
    /** List of supported key wrapping algorithms */
    private List<String> supportedKeyWrapAlgs;
    /** List of excluded algorithms */
    private List<String> excludedAlgs;
    /** Key wrap policies mapped under key exchange type */
    private Map<String, SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap> keyWrapPolicyMap;

    /**
     * Constructor starting from the default Open SAML configuration
     */
    public Builder() {
      this.baseEncryptConfiguration = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    }
    /**
     * Constructor setting a custom base encrypt configuration to modify using this builder
     */
    public Builder(BasicEncryptionConfiguration baseEncryptConfiguration) {
      this.baseEncryptConfiguration = baseEncryptConfiguration;
    }

    /**
     * Sets the encryption algorithms.
     *
     * @param encryptionAlgorithms a list of strings representing the encryption algorithms
     * @return the builder instance
     */
    Builder encryptionAlgorithms(List<String> encryptionAlgorithms) {
      this.supportedEncAlgs = encryptionAlgorithms;
      return this;
    }

    /**
     * Sets the list of supported key wrap encryption algorithms.
     *
     * @param keyWrapEncryptionAlgorithms a list of key wrap encryption algorithms
     * @return the builder instance
     */
    Builder keyWrapEncryptionAlgorithms(List<String> keyWrapEncryptionAlgorithms) {
      this.supportedKeyWrapAlgs = keyWrapEncryptionAlgorithms;
      return this;
    }

    /**
     * Sets the list of excluded algorithms.
     *
     * @param excludedAlgorithms a list of excluded algorithms
     * @return the builder instance
     */
    Builder excludedAlgorithms(List<String> excludedAlgorithms) {
      this.excludedAlgs = excludedAlgorithms;
      return this;
    }

    /**
     * Sets the key wrap policy for key agreement encryption.
     *
     * @param keyWrapPolicyMap a map specifying the key wrap policy per key type
     * @return the builder instance
     */
    Builder keyWrapPolicy (Map<String, SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap> keyWrapPolicyMap) {
      this.keyWrapPolicyMap = keyWrapPolicyMap;
      return this;
    }

    /**
     * Sets the key wrap policy for all key wrap types.
     *
     * @param keyWrapPolicy the key wrap policy to be set
     * @return the builder instance
     */
    Builder keyWrapPolicy (SAMLMetadataKeyAgreementEncryptionConfiguration.KeyWrap keyWrapPolicy) {
      this.keyWrapPolicyMap = baseEncryptConfiguration.getKeyAgreementConfigurations().keySet().stream()
        .collect(Collectors.toMap(Function.identity(),
          kw -> keyWrapPolicy));
      return this;
    }

    /**
     * Builds a {@link BasicEncryptionConfiguration} object based on the provided parameters.
     *
     * @return the {@link BasicEncryptionConfiguration} object
     */
    public BasicEncryptionConfiguration build() {

      // Set supported data encryption algorithms
      if (supportedEncAlgs != null) {
        baseEncryptConfiguration.setDataEncryptionAlgorithms(supportedEncAlgs);
      }
      // Set key transport encryption algorithms
      if (supportedKeyWrapAlgs != null) {
        baseEncryptConfiguration.setKeyTransportEncryptionAlgorithms(supportedKeyWrapAlgs);
      }
      if (excludedAlgs != null) {
        baseEncryptConfiguration.setExcludedAlgorithms(excludedAlgs);
      }
      // Set default key wrap functionality
      if (keyWrapPolicyMap != null) {
        baseEncryptConfiguration.setKeyAgreementConfigurations(updateDefaultKeyWrapPolicy(
          baseEncryptConfiguration.getKeyAgreementConfigurations(), keyWrapPolicyMap));
      }
      return baseEncryptConfiguration;
    }
  }

}
