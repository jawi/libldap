/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl.encoding;


import java.io.*;


/**
 * Provides base64-encoding methods found somewhere on the Internet (cannot remember exact source).
 */
public final class Base64
{
  // METHODS

  /**
   * Encodes a given byte array as base64.
   * 
   * @param aByteData
   *          the byte data to encode, may be <code>null</code>.
   * @return the base64 encoded string representation of the given byte data, or
   *         <code>null</code> in case the given byte data was <code>null</code>
   *         .
   */
  public static final byte[] encode( final byte[] aByteData )
  {
    if ( aByteData == null )
    {
      return null;
    }

    int srcIdx; // index into source (byteData)
    int dstIdx; // index into destination (byteDest)

    final int dataLength = aByteData.length;

    byte[] byteDest = new byte[( ( dataLength + 2 ) / 3 ) * 4];

    for ( srcIdx = 0, dstIdx = 0; srcIdx < ( dataLength - 2 ); srcIdx += 3 )
    {
      byteDest[dstIdx++] = ( byte )( ( aByteData[srcIdx] >>> 2 ) & 077 );
      byteDest[dstIdx++] = ( byte )( ( ( aByteData[srcIdx + 1] >>> 4 ) & 017 ) | ( ( aByteData[srcIdx] << 4 ) & 077 ) );
      byteDest[dstIdx++] = ( byte )( ( ( aByteData[srcIdx + 2] >>> 6 ) & 003 ) | ( ( aByteData[srcIdx + 1] << 2 ) & 077 ) );
      byteDest[dstIdx++] = ( byte )( aByteData[srcIdx + 2] & 077 );
    }

    if ( srcIdx < dataLength )
    {
      byteDest[dstIdx++] = ( byte )( ( aByteData[srcIdx] >>> 2 ) & 077 );
      if ( srcIdx < ( dataLength - 1 ) )
      {
        byteDest[dstIdx++] = ( byte )( ( ( aByteData[srcIdx + 1] >>> 4 ) & 017 ) | ( ( aByteData[srcIdx] << 4 ) & 077 ) );
        byteDest[dstIdx++] = ( byte )( ( aByteData[srcIdx + 1] << 2 ) & 077 );
      }
      else
      {
        byteDest[dstIdx++] = ( byte )( ( aByteData[srcIdx] << 4 ) & 077 );
      }
    }

    for ( srcIdx = 0; srcIdx < dstIdx; srcIdx++ )
    {
      if ( byteDest[srcIdx] < 26 )
      {
        byteDest[srcIdx] = ( byte )( byteDest[srcIdx] + 'A' );
      }
      else if ( byteDest[srcIdx] < 52 )
      {
        byteDest[srcIdx] = ( byte )( byteDest[srcIdx] + 'a' - 26 );
      }
      else if ( byteDest[srcIdx] < 62 )
      {
        byteDest[srcIdx] = ( byte )( byteDest[srcIdx] + '0' - 52 );
      }
      else if ( byteDest[srcIdx] < 63 )
      {
        byteDest[srcIdx] = '+';
      }
      else
      {
        byteDest[srcIdx] = '/';
      }
    }

    for ( ; srcIdx < byteDest.length; srcIdx++ )
    {
      byteDest[srcIdx] = '=';
    }

    return byteDest;
  }

  /**
   * Encodes a given UTF8-string as base64.
   * 
   * @param aInput
   *          the input to encode, may be <code>null</code>.
   * @return the base64 encoded string representation of the given input, or
   *         <code>null</code> in case the given input was <code>null</code>.
   */
  public static final String encode( final String aInput )
  {
    return encode( aInput, "UTF-8" );
  }

  /**
   * Encodes a given string as base64.
   * 
   * @param aInput
   *          the input to encode, may be <code>null</code>.
   * @param aEncoding
   *          the character encoding to use for the given input, like "ASCII",
   *          or "UTF-16LE".
   * @return the base64 encoded string representation of the given input, or
   *         <code>null</code> in case the given input was <code>null</code>.
   * @throws RuntimeException
   *           in case of an unsupported encoding.
   */
  public static final String encode( final String aInput, final String aEncoding )
  {
    if ( aInput == null )
    {
      return null;
    }

    try
    {
      final byte[] byteData = aInput.getBytes( aEncoding );
      return new String( encode( byteData ), "ASCII" );
    }
    catch ( UnsupportedEncodingException e )
    {
      throw new RuntimeException( e );
    }
  }

  /**
   * Encodes the given byte data to base64 as double-byte data.
   * 
   * @param aByteData
   *          the byte data to encode.
   * @return the double-byte encoded base64 data.
   */
  public static final byte[] encodeAsDoubleByte( final byte[] aByteData )
  {
    final byte[] doubleByteEncoded = new byte[2 * aByteData.length];

    for ( int i = 0; i < aByteData.length; i++ )
    {
      final int j = ( i * 2 );
      doubleByteEncoded[j] = aByteData[i];
      doubleByteEncoded[j + 1] = 0x00;
    }

    return Base64.encode( doubleByteEncoded );
  }
}
