/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl.encoding;


import java.io.*;


/**
 * BerDecoder is a simple BER-value decoder (used in ASN.1). Based on code from the SUN JDK.
 */
public final class BerDecoder implements Ber
{
  // VARIABLES

  private final byte[] buf;
  private final int bufsize;
  private int offset;

  private final int origOffset; // The start point in buf to decode

  // CONSTRUCTORS

  /**
   * Creates a BER decoder that reads bytes from the specified buffer.
   *
   * @param aBuf
   *          the buffer to decode;
   * @param aOffset
   *          the offset in the buffer;
   * @param aBufSize
   *          the size of the buffer to decode.
   */
  public BerDecoder( final byte[] aBuf, final int aOffset, final int aBufSize )
  {
    this.buf = aBuf;
    this.bufsize = aBufSize;
    this.origOffset = aOffset;

    reset();
  }

  // METHODS

  /**
   * Returns the number of unparsed bytes in this BER buffer.
   *
   * @return the number of bytes left (>= 0).
   */
  public int bytesLeft()
  {
    return this.bufsize - this.offset;
  }

  /**
   * Returns the current parse position. It points to the byte that will be
   * parsed next. Useful for parsing sequences.
   *
   * @return the current parse position.
   */
  public int getParsePosition()
  {
    return this.offset;
  }

  /**
   * Parses an ASN_BOOLEAN tagged integer from this BER buffer.
   *
   * @return true if the tagged integer is 0; false otherwise.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public boolean parseBoolean() throws DecodeException
  {
    return ( ( parseIntWithTag( ASN_BOOLEAN ) == 0x00 ) ? false : true );
  }

  /**
   * Parses the next byte in this BER buffer.
   *
   * @return The byte parsed.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public int parseByte() throws DecodeException
  {
    if ( ( this.bufsize - this.offset ) < 1 )
    {
      throw new DecodeException( "Insufficient data" );
    }
    return this.buf[this.offset++] & 0xff;
  }

  /**
   * Parses an ASN_ENUMERATED tagged integer from this BER buffer.
   *
   * @return The tag of enumeration.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public int parseEnumeration() throws DecodeException
  {
    return parseIntWithTag( ASN_ENUMERATED );
  }

  /**
   * Parses an ASN_INTEGER tagged integer from this BER buffer.
   *
   * @return The value of the integer.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public int parseInt() throws DecodeException
  {
    return parseIntWithTag( ASN_INTEGER );
  }

  /**
   * Parses a possibly variable length field.
   *
   * @return the parsed length, as integer.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public int parseLength() throws DecodeException
  {
    int lengthbyte = parseByte();

    if ( ( lengthbyte & 0x80 ) == 0x80 )
    {
      lengthbyte &= 0x7f;

      if ( lengthbyte == 0 )
      {
        throw new DecodeException( "Indefinite length not supported" );
      }

      if ( lengthbyte > 4 )
      {
        throw new DecodeException( "Encoding too long" );
      }

      if ( ( this.bufsize - this.offset ) < lengthbyte )
      {
        throw new DecodeException( "Insufficient data" );
      }

      int retval = 0;

      for ( int i = 0; i < lengthbyte; i++ )
      {
        retval = ( retval << 8 ) + ( this.buf[this.offset++] & 0xff );
      }
      return retval;
    }
    else
    {
      return lengthbyte;
    }
  }

  /**
   * Parses an octet string of a given type(tag) from this BER buffer.
   * <blockquote>
   *
   * <pre>
   * BER Binary Data of type "tag" ::= tag length {byte}*
   * </pre>
   *
   * </blockquote>
   *
   * @param aTag
   *          the tag to look for;
   * @param aReturnLen
   *          an array for returning the relative parsed position. If
   *          <code>null</code>, the relative parsed position is not returned.
   * @return A non-null array containing the octet string.
   * @throws DecodeException
   *           If the next byte in the BER buffer is not <tt>tag</tt>, or if
   *           length specified in the BER buffer exceeds the number of bytes
   *           left in the buffer.
   */
  public byte[] parseOctetString( final int aTag, final int[] aReturnLen ) throws DecodeException
  {
    final int origOffset = this.offset;
    int st;
    if ( ( st = parseByte() ) != aTag )
    {
      throw new DecodeException( "Encountered ASN.1 tag " + Integer.toString( st ) + " (expected tag "
          + Integer.toString( aTag ) + ")" );
    }

    final int len = parseLength();

    if ( len > ( this.bufsize - this.offset ) )
    {
      throw new DecodeException( "Insufficient data" );
    }

    final byte[] retarr = new byte[len];
    if ( len > 0 )
    {
      System.arraycopy( this.buf, this.offset, retarr, 0, len );
      this.offset += len;
    }

    if ( aReturnLen != null )
    {
      aReturnLen[0] = this.offset - origOffset;
    }

    return retarr;
  }

  /**
   * Parses the next sequence in this BER buffer.
   *
   * @param aReturnLen
   *          an array for returning size of the sequence in bytes. If
   *          <code>null</code>, the size is not returned.
   * @return The sequence's tag.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public int parseSeq( final int[] aReturnLen ) throws DecodeException
  {
    final int seq = parseByte();
    final int len = parseLength();
    if ( aReturnLen != null )
    {
      aReturnLen[0] = len;
    }
    return seq;
  }

  /**
   * Parses a simple string (ASN_SIMPLE).
   *
   * @param aDecodeUTF8
   *          If <code>true</code>, use UTF-8 when decoding the string;
   *          otherwise use ISO-Latin-1 (8859_1). Use <code>true</code> for
   *          LDAPv3; <code>false</code> for LDAPv2;
   * @return the parsed string, never <code>null</code>.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public String parseString( final boolean aDecodeUTF8 ) throws DecodeException
  {
    return parseStringWithTag( ASN_SIMPLE_STRING, aDecodeUTF8, null );
  }

  /**
   * Parses a string of a given tag from this BER buffer. <blockquote>
   *
   * <pre>
   * BER simple string ::= tag length {byte}*
   * </pre>
   *
   * </blockquote>
   *
   * @param aTag
   *          the tag that precedes the string;
   * @param aDecodeUTF8
   *          If <code>true</code>, use UTF-8 when decoding the string;
   *          otherwise use ISO-Latin-1 (8859_1). Use <code>true</code> for
   *          LDAPv3; <code>false</code> for LDAPv2;
   * @param aReturnLen
   *          an array for holding the relative parsed offset; if
   *          <code>null</code> offset not set.
   * @return The non-null parsed string.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public String parseStringWithTag( final int aTag, final boolean aDecodeUTF8, final int[] aReturnLen )
      throws DecodeException
  {
    int st;
    final int origOffset = this.offset;

    if ( ( st = parseByte() ) != aTag )
    {
      throw new DecodeException( "Encountered ASN.1 tag " + Integer.toString( ( byte )st ) + " (expected tag " + aTag
          + ")" );
    }

    final int len = parseLength();

    if ( len > ( this.bufsize - this.offset ) )
    {
      throw new DecodeException( "Insufficient data" );
    }

    String retstr;
    if ( len == 0 )
    {
      retstr = "";
    }
    else
    {
      final byte[] buf2 = new byte[len];

      System.arraycopy( this.buf, this.offset, buf2, 0, len );
      if ( aDecodeUTF8 )
      {
        try
        {
          retstr = new String( buf2, "UTF8" );
        }
        catch ( final UnsupportedEncodingException e )
        {
          throw new DecodeException( "UTF8 not available on platform" );
        }
      }
      else
      {
        try
        {
          retstr = new String( buf2, "8859_1" );
        }
        catch ( final UnsupportedEncodingException e )
        {
          throw new DecodeException( "8859_1 not available on platform" );
        }
      }
      this.offset += len;
    }

    if ( aReturnLen != null )
    {
      aReturnLen[0] = this.offset - origOffset;
    }

    return retstr;
  }

  /**
   * Returns the next byte in this BER buffer without consuming it.
   *
   * @return The next byte.
   * @throws DecodeException
   *           in case decoding failed.
   */
  public int peekByte() throws DecodeException
  {
    if ( ( this.bufsize - this.offset ) < 1 )
    {
      throw new DecodeException( "Insufficient data" );
    }
    return this.buf[this.offset] & 0xff;
  }

  /**
   * Resets this decode to start parsing from the initial offset (ie., same
   * state as after calling the constructor).
   */
  public void reset()
  {
    this.offset = this.origOffset;
  }

  /**
   * Used to skip bytes. Usually used when trying to recover from parse error.
   * Don't need to be public right now?
   *
   * @param aNumber
   *          The number of bytes to skip.
   * @throws DecodeException
   *           in case decoding failed.
   */
  void seek( final int aNumber ) throws DecodeException
  {
    if ( ( ( this.offset + aNumber ) > this.bufsize ) || ( ( this.offset + aNumber ) < 0 ) )
    {
      throw new DecodeException( "array index out of bounds" );
    }
    this.offset += aNumber;
  }

  /**
   * Parses an integer that's preceded by a tag. <blockquote>
   *
   * <pre>
   * BER integer ::= tag length byte {byte}*
   * </pre>
   *
   * </blockquote>
   *
   * @param aTag
   *          the tag to expect during parsing.
   * @return the parsed integer.
   * @throws DecodeException
   *           in case decoding failed.
   */
  private int parseIntWithTag( final int aTag ) throws DecodeException
  {
    if ( parseByte() != aTag )
    {
      throw new DecodeException( "Encountered ASN.1 tag " + Integer.toString( this.buf[this.offset - 1] & 0xff )
          + " (expected tag " + Integer.toString( aTag ) + ")" );
    }

    final int len = parseLength();

    if ( len > 4 )
    {
      throw new DecodeException( "INTEGER too long" );
    }
    else if ( len > ( this.bufsize - this.offset ) )
    {
      throw new DecodeException( "Insufficient data" );
    }

    final byte fb = this.buf[this.offset++];
    int value = 0;

    value = fb & 0x7F;
    for ( int i = 1 /* first byte already read */; i < len; i++ )
    {
      value <<= 8;
      value |= ( this.buf[this.offset++] & 0xff );
    }

    if ( ( fb & 0x80 ) == 0x80 )
    {
      value = -value;
    }

    return value;
  }
}
