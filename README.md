![Logo](img/sc-logo.png)

# opensaml-security-ext

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Maven Central](https://img.shields.io/maven-central/v/se.swedenconnect.opensaml/opensaml-security-ext.svg)

Security extensions for OpenSAML

---

The opensaml-security-ext was originally created to introduce algorithm support that was missing
from OpenSAML. Now, when OpenSAML 5.x has implemented all these algorithm, the library has been
reduced to implement a workaround for using RSA-OAEP and RSA-PSS with HSM protected keys since the Sun PKCS#11 provider does not support RSA-OAEP and RSA-PSS padding.

> Well, not only. The library also offers some utility methods for encryption/decryption and signing
as well as initializing and security configuration helpers.

Java API documentation of the opensaml-security-ext library is found [here](https://docs.swedenconnect.se/opensaml-security-ext/javadoc/).

### Maven and opensaml-security-ext

The opensaml-security-ext project artifacts are published to Maven central.

Include the following snippet in your Maven POM to add opensaml-security-ext as a dependency for your project.

```
<dependency>
  <groupId>se.swedenconnect.opensaml</groupId>
  <artifactId>opensaml-security-ext</artifactId>
  <version>${opensaml-security-ext.version}</version>
</dependency>
```

## Initializing support

OpenSAML needs to be initialized in order to function. The opensaml-security-ext provides the
singleton class [OpenSAMLInitializer](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/OpenSAMLInitializer.java) for this purpose.

One or more [OpenSAMLInitializerConfig](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/OpenSAMLInitializerConfig.java) instances may be supplied as arguments to the `OpenSAMLInitializer.initialize` method in order to add customized configuration.

In order to utilize the extensions from this library, the [OpenSAMLSecurityExtensionConfig](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/OpenSAMLSecurityExtensionConfig.java) should be supplied in the `initialize`-call.

It is also possible to configure other algorithm defaults than what is the OpenSAML defaults. This is done by using the [OpenSAMLSecurityDefaultsConfig](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/OpenSAMLSecurityDefaultsConfig.java) class that takes a [SecurityConfiguration](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/config/SecurityConfiguration.java) instance. In the example below the security configuration is set up according to [SAML2Int](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

```
// Initialize OpenSAML and the security extensions.
// We also configure algorithm defaults according to SAML2Int ...
//
OpenSAMLInitializer.getInstance().initialize(
  new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
  new OpenSAMLSecurityExtensionConfig());
```

> For our test cases we had to add the Bouncy Castle crypto provider manually in order to implement ECDH. It should be sufficient to have it in the class path, but to be safe, the `preInitialize` method of the `OpenSAMLSecurityExtensionConfig` checks whether this provider is installed and does so if it isn't already installed.

**Note**: The [eidas-opensaml](https://github.com/litsec/eidas-opensaml) library uses opensaml-security-ext. It defines `SecurityConfiguration` classes for eIDAS security configuration, one "strict" will small chances of interoperability and one "relaxed" that will actually work against a node using the CEF-software.

## Workarounds for the Sun PKCS#11 provider

The standard Sun Java PKCS#11 provider does not support RSA-OAEP decryption which is a problem if the decryption key is stored in a HSM accessed through a PKCS#11 API. See this [Stack Overflow](https://stackoverflow.com/questions/23844694/bad-padding-exception-rsa-ecb-oaepwithsha-256andmgf1padding-in-pkcs11) article.

The [Pkcs11Decrypter](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/encryption/support/Pkcs11Decrypter.java) extends OpenSAML's `Decrypter` implementation with a work-around for this problem.
This work-around comprises of:

- Performing a raw RSA decryption on the encrypted data.
- Performing OAEP padding processing on the decrypted data outside of the HSM to extract the decrypted plaintext.

Furthermore, the Sun PKCS#11 provider does not implement PSS-padding, making it impossible to sign using RSA-PSS if the signing key is stored on a HSM and the Sun PKCS#11 provider is used. The opensaml-security-ext library solves this by overriding OpenSAML's standard `SignerProvider` (`ApacheSantuarioSignerProviderImpl`) with an extension, [ExtendedSignerProvider](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/signature/support/provider/ExtendedSignerProvider.java). This extension handles padding in software and only the raw RSA transform is performed on the HSM.

By adding the opensaml-security-ext library to your classpath, the `ExtendedSignerProvider` will be made the default OpenSAML signer provider, and when RSA-PSS signing is ordered and the current crypto provider is the Sun PKCS#11 provider, the above described workaround will kick in. Otherwise, the default provider handles the operation.

If you, for some reason, want to disable the `ExtendedSignerProvider` functionality, set the system property `se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.disabled` to `true`. You can also force the provider to execute all RSA-based signatures by setting the property `se.swedenconnect.opensaml.xmlsec.signature.support.provider.ExtendedSignerProvider.testmode` to `true`. This is for testing purposes.

---


Copyright &copy; 2016-2025, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
