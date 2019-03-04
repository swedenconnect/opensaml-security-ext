package se.swedenconnect.opensaml.ecdh.deploy;

import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support.SupportedConcatKDFHash;

/**
 * Data model for setting up encryption parameters
 * <p>
 * <p>Default parameters:
 * <ul>
 *   <li><b>Data encryption algoritm:</b> AES256-GCM</li>
 *   <li><b>RSA OAEP MGF:</b> mgf1p with default MGF1-SHA1</li>
 *   <li><b>RSA OAEP Hash:</b> SHA-256</li>
 *   <li><b>RSA OAEP Parameter:</b> null</li>
 *   <li><b>ConcatKDF hash:</b> SHA-256</li>
 * </ul>
 *
 */
public class XmlEncryptModel {
  /** XML Data encryption algorithm */
  private String dataEncryptionAlgo;
  /** MGF1 function URI identifier. A null value specifies the use of rsa-oaep-mgf1p with default MGF1-SHA1 */
  private String mgf;
  /** OAEP digest method */
  private String oaepDigestMethod;
  /** Optional OAEP parameter string. A Base64 encoded string of the UTF-8 byte representation of this string will be included as OAEP parameter */
  private String oaepParameter;
  /** The ECDH ConcatKDF hash algorithm */
  private SupportedConcatKDFHash concatKDFHash;

  /**
   * Providing the default xml encryption model:
   */
  public XmlEncryptModel() {
    this(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
  }

  /**
   * Providing xml encryption model with specific encryption algorithm and default parameters.
   * @param dataEncryptionAlgo xml data encryption parameters
   */
  public XmlEncryptModel(String dataEncryptionAlgo) {
    this.dataEncryptionAlgo = dataEncryptionAlgo;
    this.mgf = null;
    this.oaepDigestMethod = EncryptionConstants.ALGO_ID_DIGEST_SHA256;
    this.oaepParameter=null;
    this.concatKDFHash = SupportedConcatKDFHash.sha256;
  }

  /**
   * Constructor for setting specific values
   * @param dataEncryptionAlgo algorithm for encrypting XML content
   * @param mgf MGF function for RSA OAEP. Set to null for using oaep-mgf1p
   * @param oaepDigestMethod OAEP hash function
   * @param oaepParameter
   * @param concatKDFHash hash algorithm for the ConcatKDF key derivation function
   */
  public XmlEncryptModel(String dataEncryptionAlgo, String mgf, String oaepDigestMethod, String oaepParameter,
    SupportedConcatKDFHash concatKDFHash) {
    this.dataEncryptionAlgo = dataEncryptionAlgo;
    this.mgf = mgf;
    this.oaepDigestMethod = oaepDigestMethod;
    this.oaepParameter = oaepParameter;
    this.concatKDFHash = concatKDFHash;
  }

  public String getDataEncryptionAlgo() {
    return dataEncryptionAlgo;
  }

  public void setDataEncryptionAlgo(String dataEncryptionAlgo) {
    this.dataEncryptionAlgo = dataEncryptionAlgo;
  }

  public String getMgf() {
    return mgf;
  }

  public void setMgf(String mgf) {
    this.mgf = mgf;
  }

  public String getOaepDigestMethod() {
    return oaepDigestMethod;
  }

  public void setOaepDigestMethod(String oaepDigestMethod) {
    this.oaepDigestMethod = oaepDigestMethod;
  }

  public String getOaepParameter() {
    return oaepParameter;
  }

  public void setOaepParameter(String oaepParameter) {
    this.oaepParameter = oaepParameter;
  }

  public SupportedConcatKDFHash getConcatKDFHash() {
    return concatKDFHash;
  }

  public void setConcatKDFHash(SupportedConcatKDFHash concatKDFHash) {
    this.concatKDFHash = concatKDFHash;
  }
}
