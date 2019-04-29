![Logo](img/sc-logo.png)

# opensaml-security-ext

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Crypto and security extensions to OpenSAML

---

The opensaml-security-ext extends the core OpenSAML libraries with the capability to encrypt and decrypt XML data using ephemeral-static ECDH key agreement. This library also offers a workaround for using RSA-OAEP with HSM protected keys where the PKCS#11 API does not support RSA-OAEP.

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

> Note: Publication to Maven central will be done for the first non-snapshot version.

## Initializing support

OpenSAML needs to be initialized in order to function. The opensaml-security-ext provides the
singleton class [OpenSAMLInitializer](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/OpenSAMLInitializer.java) for this purpose.

Also, in order to utilize the extensions from this library, the [OpenSAMLExtInitializer](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/OpenSAMLExtInitializer.java) should be used.

```
// Initialize OpenSAML and the security extensions ...
OpenSAMLInitializer.getInstance().initialize();
OpenSAMLExtInitializer.getInstance().initialize();
```

> Note: We may add different "modes" to the initializing. For example, one that registers default algorithms according to SAML2Int and one that registers algorithms according to the eIDAS defaults.

> Note: For our test cases we had to add the Bouncy Castle crypto provider manually in order to implement ECDH. It should be sufficient to have it in the class path, but if you run into problems you may have to add this:

```
Security.addProvider(new BouncyCastleProvider());
```

## Extended encryption and decryption support

In order to add support for key agreement to OpenSAML in a way that an application that wishes to have this support only needs to make configuration changes we had to add quite a number of different extensions. We tested this on a Shibboleth deployment and managed to add ECDH support to an IdP.

When encrypting a SAML object, for example an `Assertion`, for a peer, the following steps are generally taken:

1. Locate the peer metadata/credentials.
2. Resolve the encryption parameters to use during the encryption process using a `EncryptionParametersResolver`.
3. Encrypt the data.


#### Resolving encryption parameters from metadata

Below we illustrate how this is done using the [ExtendedSAMLMetadataEncryptionParametersResolver](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/ExtendedSAMLMetadataEncryptionParametersResolver.java). For details, see `resolvedEncryptionParametersFromMetadata` method in the [EncryptionDecryptionTest.java](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/test/java/se/swedenconnect/opensaml/examples/EncryptionDecryptionTest.java) file.

```
// The peer metadata.
final EntityDescriptor metadata = ...;

// Set up a MetadataCredentialResolver (a resolver that reads from SAML metadata)
MetadataCredentialResolver credentialResolver = new MetadataCredentialResolver();    credentialResolver.setKeyInfoCredentialResolver(
  DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
credentialResolver.initialize();

// Set up the criteria ...
//
// We need default algorithms (in case no are given in EncryptionMethod in metadata).
EncryptionConfigurationCriterion encConfCriterion = new EncryptionConfigurationCriterion(
  ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration());

// RoleDescriptorCriterion gives us the metadata. In a real case a RoleDescriptorResolver
// would be used.
RoleDescriptorCriterion rdCriterion = 
  new RoleDescriptorCriterion(metadata.getRoleDescriptors().get(0));

CriteriaSet criteriaSet = new CriteriaSet(encConfCriterion, rdCriterion);

// Resolve encryption parameters and encrypt.
//
ExtendedSAMLMetadataEncryptionParametersResolver resolver = 
  new ExtendedSAMLMetadataEncryptionParametersResolver(credentialResolver);

EncryptionParameters params = resolver.resolveSingle(criteriaSet);

Encrypter encrypter = new Encrypter();

EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
  new DataEncryptionParameters(params), new KeyEncryptionParameters(params, metadata.getEntityID()));

```

The encrypted data is represented in XML as:

```
<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" 
                    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" 
                         xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptedKey Recipient="http://id.example.com/sp1" 
                       xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256" 
                             xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>
      <ds:KeyInfo>
        <xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
          <xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF"
                                      xmlns:xenc11="http://www.w3.org/2009/xmlenc11#">
            <xenc11:ConcatKDFParams AlgorithmID="0000" PartyUInfo="0000" PartyVInfo="0000">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" 
                               xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
            </xenc11:ConcatKDFParams>
          </xenc11:KeyDerivationMethod>
          <xenc:OriginatorKeyInfo>
            <ds:KeyValue>
              <ds11:ECKeyValue xmlns:ds11="http://www.w3.org/2009/xmldsig11#">
                <ds11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>                                 
                <ds11:PublicKey>BPqJLXfFWIjsa9hPug...umuc=</ds11:PublicKey>
              </ds11:ECKeyValue>
            </ds:KeyValue>
          </xenc:OriginatorKeyInfo>
           <xenc:RecipientKeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#">                              
              <ds:X509Certificate>MIIB...AEoizR</ds:X509Certificate>
            </ds:X509Data>
          </xenc:RecipientKeyInfo>
        </xenc:AgreementMethod>
      </ds:KeyInfo>
      <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
        <xenc:CipherValue>3i2e4G/2LK2oSo...dE1cluerju0sQ==</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedKey>
  </ds:KeyInfo>
  <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">        
    <xenc:CipherValue>WreMTql...rXWg4=</xenc:CipherValue>
  </xenc:CipherData>
</xenc:EncryptedData>
```

The decryption phase looks like:

```

Credential[] localCredentials = ...;
Decrypter decrypter = new Decrypter(DecryptionUtils.createDecryptionParameters(localCredentials));
decrypter.setRootInNewDocument(true);

Type decryptedObject = (Type) decrypter.decryptData(encryptedData);
```

The trick here that allows us to decrypt the above data is the [KeyAgreementMethodKeyInfoProvider](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/keyinfo/provider/KeyAgreementMethodKeyInfoProvider.java). This is a special purpose provider that handles key agreement and sets up a `KeyAgreementCredential` that makes it possible to use the standard OpenSAML decrypter. See [DecryptionUtils](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/encryption/support/DecryptionUtils.java) for how to set up decryption parameters.

#### Resolving encryption parameters from local configuration

The opensaml-security-ext library also offers another encryption parameter provider, the [ExtendedEncryptionParametersResolver](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/ExtendedEncryptionParametersResolver.java). This provider does not locate peer credentials in metadata. Instead we hand them over directly. For details, see `resolvedEncryptionParameters` method in the [EncryptionDecryptionTest.java](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/test/java/se/swedenconnect/opensaml/examples/EncryptionDecryptionTest.java) file.

```
// We use the default encryption configuration. The extended part introduces support
// for key agreement and key derivation configuration.
//
BasicExtendedEncryptionConfiguration config =
  ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();

// Install our key transport encryption credentials.
// The setKeyTransportEncryptionCredentials will analyze whether the added credential can be
// used for ordinary key transport or key agreement.
// Note: You may also use the setKeyAgreementCredentials to explicitly assign credentials that
// may be used for key agreement.
//
config.setKeyTransportEncryptionCredentials(Arrays.asList(peerCredential1, peerCredential2));

// Make our encryption configuration into a criteria for the resolver.
//
EncryptionConfigurationCriterion criterion = new EncryptionConfigurationCriterion(config);
CriteriaSet criteriaSet = new CriteriaSet(criterion);

// Instantiate our extension of the EncryptionParametersResolver to get the parameters needed
// for encryption.
//
ExtendedEncryptionParametersResolver resolver = new ExtendedEncryptionParametersResolver();
EncryptionParameters params = resolver.resolveSingle(criteriaSet);

// Encrypt
Encrypter encrypter = new Encrypter();

EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
  new DataEncryptionParameters(params), new KeyEncryptionParameters(params, "recipient"));
```

The decryption phase is the same as the previous example.

#### Manual setup of encryption

Finally, the opensaml-security-ext library offers a way to manually setup the parameters needed
for ECDH encryption.

For details, see `manualEncryptionSetup` method in the [EncryptionDecryptionTest.java](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/test/java/se/swedenconnect/opensaml/examples/EncryptionDecryptionTest.java) file.

In this case we need to use the "hack", [ECDHKeyAgreementParameters](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/encryption/support/ECDHKeyAgreementParameters.java) which is an extension of OpenSAML's `KeyEncryptionParameters` class. The `ECDHKeyAgreementParameters` has defaults for ECDH using ConcatKDF for key derivation.

```
// Set up parameters for encryption manually ...
DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
dataEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);

// In order for ECDH to be possible with OpenSAML's Encrypter class we need to instantiate
// our special purpose key encryption parameters object.
ECDHKeyAgreementParameters kekParams = new ECDHKeyAgreementParameters();
kekParams.setPeerCredential(this.ecPeerCredential);
// The kekParams will use default algorithms for key wrapping and key agreement.

// We also need the special purpose key info generator (for key agreement).
kekParams.setKeyInfoGenerator(
  ExtendedDefaultSecurityConfigurationBootstrap
    .buildDefaultKeyAgreementKeyInfoGeneratorFactory().newInstance());

// Encrypt
Encrypter encrypter = new Encrypter();

EncryptedData encryptedData = encrypter.encryptElement(this.encryptedObject,
  dataEncryptionParameters, kekParams);
```

The decryption phase is the same as the previous example.


## PKCS11 RSA OAEP workaround
The standard Sun Java PKCS#11 API does not support RSA-OAEP decryption which is a problem if the decryption key is stored in a HSM accessed through a PKCS#11 API. See this [Stack Overflow](https://stackoverflow.com/questions/23844694/bad-padding-exception-rsa-ecb-oaepwithsha-256andmgf1padding-in-pkcs11) article.

The [Pkcs11Decrypter](https://github.com/swedenconnect/opensaml-security-ext/blob/master/src/main/java/se/swedenconnect/opensaml/xmlsec/encryption/support/Pkcs11Decrypter.java) extends OpenSAML's `Decrypter` implementation with a work-around for this problem.
This work-around comprises of:

- Performing a raw RSA decryption on the encrypted data.
- Performing OAEP padding processing on the decrypted data outside of the HSM to extract the decrypted plaintext.
        
---

Copyright &copy; 2016-2019, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
