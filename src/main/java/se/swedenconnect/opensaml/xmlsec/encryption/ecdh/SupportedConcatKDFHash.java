package se.swedenconnect.opensaml.xmlsec.encryption.ecdh;

import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

public enum SupportedConcatKDFHash {
  sha256(EncryptionConstants.ALGO_ID_DIGEST_SHA256),
  sha512(EncryptionConstants.ALGO_ID_DIGEST_SHA512);

  private String id;

  SupportedConcatKDFHash(String id) {
    this.id = id;
  }

  public String getId() {
    return id;
  }
}
