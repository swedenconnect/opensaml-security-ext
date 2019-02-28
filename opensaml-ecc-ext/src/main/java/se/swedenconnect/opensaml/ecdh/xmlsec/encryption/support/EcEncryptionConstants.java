package se.swedenconnect.opensaml.ecdh.xmlsec.encryption.support;

public class EcEncryptionConstants {

  /** XML Encryption 1.1 namespace. */
  public static final String XMLENC11_NS = "http://www.w3.org/2009/xmlenc11#";

  /** Key Derivation - ConcatKDF. */
  public static final String ALGO_ID_KEYDERIVATION_CONCAT = XMLENC11_NS + "ConcatKDF";

  /** Key Agreement - ECDH-ES. */
  public static final String ALGO_ID_KEYAGREEMENT_ECDH_ES = XMLENC11_NS + "ECDH-ES";


}
