package se.swedenconnect.opensaml.xmlsec.encryption.ecdh;

import java.util.Arrays;
import java.util.Optional;

/**
 * Enumeration of supported named curves
 */
public enum NamedEcCurve {
  secp192r1("1.2.840.10045.3.1.1", 192),
  secp224r1("1.3.132.0.33", 224),
  secp256r1("1.2.840.10045.3.1.7", 256),
  secp384r1("1.3.132.0.34", 384),
  secp521r1("1.3.132.0.35", 521),
  brainpoolP160r1("1.3.36.3.3.2.8.1.1.1", 160),
  brainpoolP192r1("1.3.36.3.3.2.8.1.1.3", 192),
  brainpoolP224r1("1.3.36.3.3.2.8.1.1.5", 224),
  brainpoolP256r1("1.3.36.3.3.2.8.1.1.7", 256),
  brainpoolP320r1("1.3.36.3.3.2.8.1.1.9", 320),
  brainpoolP384r1("1.3.36.3.3.2.8.1.1.11", 384),
  brainpoolP512r1("1.3.36.3.3.2.8.1.1.13", 512);

  String oid;
  int keyLen;

  NamedEcCurve(String oid, int keyLen) {
    this.oid = oid;
    this.keyLen = keyLen;
  }

  public String getOid() {
    return oid;
  }

  public int getKeyLen() {
    return keyLen;
  }

  /**
   * Gets the named EC curve based on an OID string
   * @param oid the string representation of the oid representing the named curve
   * @return the named curve enum or null if no matching curve was found
   */
  public static NamedEcCurve getCurveByOid(String oid) {
    if (oid == null) {
      return null;
    }
    Optional<NamedEcCurve> namedEcCurveOptional = Arrays.stream(values())
      .filter(namedEcCurve -> namedEcCurve.getOid().equalsIgnoreCase(oid))
      .findFirst();
    return namedEcCurveOptional.isPresent() ? namedEcCurveOptional.get() : null;
  }

  /**
   * Gets the named EC curve based on an OID string and minimum key length
   * @param oid the string representation of the oid representing the named curve
   * @param minLen minimum acceptable key length
   * @return the named curve enum or null if no matching curve was found
   */
  public static NamedEcCurve getCurveByOid(String oid, int minLen){
    NamedEcCurve curve = getCurveByOid(oid);
    if (curve.getKeyLen() < minLen){
      return null;
    }
    return curve;
  }

}
