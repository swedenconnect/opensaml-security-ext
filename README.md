![Logo](img/sc-logo.png)

# Eliptic Curve Diffie-Hellman extension to OpenSAML

OpenSAML is extended by this project by adding the capability to encrypt and decrypt xml data using ephemeral-static ECDH key agreement. The decrypter also offers a workaround for using RSA-OAEP with HSM protected keys where the PKCS#11 API does not support RSA-OAEP.

Algorithm choice between RSA-OAEP or ECDH is automatically made based on the type of provided public key. If the key is an RSA key, RSA-OAEP is selected and if the key is an EC key, then ECDH is selected.

The following extensions/amendments are done to OpenSAML

- Two new XML elements with Builder, Impl, Marshaller and Unmarshaller:
  - ConcatKDF
  - KeyDerivationMethod
- A new KeyInfoGeneratorFactory
- A new extended encrypter, extending the OpenSAML encrypter
- A new extended decrypter, extending the OpenSAML decrypter

### Maven dependency

TBD

### Initialization
Invocation of these extensions is done through the following steps:

- Inclusion of the maven dependency above
- Using the OpenSAMLInitializer provided in this project, or a compatible custom initializer.


## Encryption and decryption

The following sample class implements ECDH capable encryption and decryption of SAML assertions using the extensions in this project.

```
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import se.swedenconnect.opensaml.ecdh.deploy.EncrypterFactory;
import se.swedenconnect.opensaml.ecdh.deploy.SAMLObjectDecrypter;
import se.swedenconnect.opensaml.ecdh.deploy.XmlEncryptModel;
import java.security.cert.X509Certificate;

public class EncryptAssertionUtil {

  private static EncrypterFactory encrypterFactory = new EncrypterFactory();

  public static void encrypt(
    Response response,
    X509Certificate receiverCertificate)
    throws Exception
  {
    encrypt(response, receiverCertificate, null);
  }

  public static void encrypt(
    Response response,
    X509Certificate receiverCertificate,
    XmlEncryptModel xmlEncryptModel)
    throws Exception
  {
    Encrypter encrypter = encrypterFactory.getEncrypter(
      receiverCertificate,
      xmlEncryptModel);
    EncryptedAssertion encrypted = encrypter.encrypt(
      response.getAssertions().get(0));
    response.getEncryptedAssertions().add(encrypted);
    response.getAssertions().clear();
  }

  public static Assertion decrypt(
    EncryptedAssertion enc,
    Credential credential)
    throws DecryptionException
  {
    SAMLObjectDecrypter decrypter = new SAMLObjectDecrypter(credential);
    return (Assertion) decrypter.decrypt(enc, Assertion.class);
  }
}

```

The optional XmlEncryptModel object holds configurable values for selection of detailed algorithm choices. Providing null or no XmlEncryptModel object uses the following defaults:

 - AES-256-GCM data encryption algorithm.
 - rsa-oaep-mgf1p as standard RSA OAEP mask generation function.
 - SHA-256 as RSA-OAEP digest method.
 - No RSA-OAEP parameter.
 - SHA-256 as ConcatKDF hash function.

More information about configuration option is provided in Javadoc.

## PKCS11 RSA OAEP workaround
The standard Sun Java PKCS#11 API does not support RSA-OAEP decryption which is a problem if the decryption key is stored in a HSM accessed through a PKCS#11 API.

The SAMLObjectDecrypter includes implementation of a workaround which performs RSA-OAEP decryption in the following manner if the decrytpion key is a PKCS11 private key.

- Performs raw RSA decryption on the encrypted data.
- Performs OAEP padding processing on the decrypted data outside of the HSM to extract the decrypted plaintext.

This feature is activated by the applying the following function to the SAMLObjectDecrypter:

    SAMLObjectDecrypter decrypter = new SAMLObjectDecrypter(credential);
    decrypter.setPkcs11Workaround(true);
