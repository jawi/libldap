/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl.encoding;


import java.io.*;


/**
 * Ber defines common fields and constants. Based on code from the SUN JDK.
 */
public interface Ber
{
  // CONSTANTS

  public static final int ASN_BOOLEAN = 0x01;
  public static final int ASN_INTEGER = 0x02;
  public static final int ASN_BIT_STRING = 0x03;
  public static final int ASN_SIMPLE_STRING = 0x04;
  public static final int ASN_OCTET_STR = 0x04;
  public static final int ASN_NULL = 0x05;
  public static final int ASN_OBJECT_ID = 0x06;
  public static final int ASN_SEQUENCE = 0x10;
  public static final int ASN_SET = 0x11;

  public static final int ASN_PRIMITIVE = 0x00;
  public static final int ASN_UNIVERSAL = 0x00;
  public static final int ASN_CONSTRUCTOR = 0x20;
  public static final int ASN_APPLICATION = 0x40;
  public static final int ASN_CONTEXT = 0x80;
  public static final int ASN_PRIVATE = 0xC0;

  public static final int ASN_ENUMERATED = 0x0a;

  // INNER TYPES

  /**
   * DecodeException
   */
  static final class DecodeException extends IOException
  {
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new DecodeException object.
     *
     * @param aMsg
     *          the message.
     */
    DecodeException( final String aMsg )
    {
      super( aMsg );
    }
  }

  /**
   * EncodeException
   */
  static final class EncodeException extends IOException
  {
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new EncodeException object.
     *
     * @param aMsg
     *          the message.
     */
    EncodeException( final String aMsg )
    {
      super( aMsg );
    }
  }
}
