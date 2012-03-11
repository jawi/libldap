/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl.encoding;


import java.io.*;


/**
 * BerEncoder is a simple BER-value encoder (used in ASN.1). Based on code from the SUN JDK.
 */
public final class BerEncoder implements Ber
{
  // CONSTANTS

  private static final int INITIAL_SEQUENCES = 16;
  private static final int DEFAULT_BUFSIZE = 1024;

  // When buf is full, expand its size by the following factor.
  private static final int BUF_GROWTH_FACTOR = 8;

  // VARIABLES

  private byte[] buf;
  private int bufsize;
  private int curSeqIndex;
  private int offset;
  private int[] seqOffset;

  // CONSTRUCTORS

  /**
   * Creates a BER buffer for encoding.
   */
  public BerEncoder()
  {
    this( DEFAULT_BUFSIZE );
  }

  /**
   * Creates a BER buffer of a specified size for encoding. Specify the initial
   * bufsize. Buffer will be expanded as needed.
   * 
   * @param aBufSize
   *          The number of bytes for the buffer.
   */
  public BerEncoder( final int aBufSize )
  {
    this.buf = new byte[aBufSize];
    this.bufsize = aBufSize;
    this.offset = 0;

    this.seqOffset = new int[INITIAL_SEQUENCES];
    this.curSeqIndex = 0;
  }

  // METHODS

  /**
   * Begin encoding a sequence with a aTag.
   * 
   * @param aTag
   *          the expected sequence aTag.
   */
  public void beginSeq( final int aTag )
  {
    // Double the size of the SEQUENCE array if it overflows
    if ( this.curSeqIndex >= this.seqOffset.length )
    {
      final int[] seqOffsetTmp = new int[this.seqOffset.length * 2];

      for ( int i = 0; i < this.seqOffset.length; i++ )
      {
        seqOffsetTmp[i] = this.seqOffset[i];
      }
      this.seqOffset = seqOffsetTmp;
    }

    encodeByte( aTag );
    this.seqOffset[this.curSeqIndex] = this.offset;

    // Save space for sequence length.
    // %%% Currently we save enough space for sequences up to 64k.
    // For larger sequences we'll need to shift the data to the right
    // in endSeq(). If we could instead pad the length field with
    // zeros, it would be a big win.
    ensureFreeBytes( 3 );
    this.offset += 3;

    this.curSeqIndex++;
  }

  /**
   * Encodes a boolean. <blockquote>
   * 
   * <pre>
   * BER boolean ::= 0x01 0x01 {0xff|0x00}
   * </pre>
   * 
   * </blockquote>
   * 
   * @param aBoolean
   *          the boolean value to encode.
   */
  public void encodeBoolean( final boolean aBoolean )
  {
    encodeBoolean( aBoolean, ASN_BOOLEAN );
  }

  /**
   * Encodes a boolean and a aTag <blockquote>
   * 
   * <pre>
   * BER boolean w aTag ::= aTag 0x01 {0xff|0x00}
   * </pre>
   * 
   * </blockquote>
   * 
   * @param aBoolean
   *          the boolean value to encode;
   * @param aTag
   *          the aTag to encode.
   */
  public void encodeBoolean( final boolean aBoolean, final int aTag )
  {
    ensureFreeBytes( 3 );

    this.buf[this.offset++] = ( byte )aTag;
    this.buf[this.offset++] = 0x01;
    this.buf[this.offset++] = aBoolean ? ( byte )0xff : ( byte )0x00;
  }

  /**
   * Encode a single byte.
   * 
   * @param aByte
   *          the byte to encode.
   */
  public void encodeByte( final int aByte )
  {
    ensureFreeBytes( 1 );
    this.buf[this.offset++] = ( byte )aByte;
  }

  /**
   * Encodes an int. <blockquote>
   * 
   * <pre>
   * BER integer ::= 0x02 berlength byte {byte}*
   * </pre>
   * 
   * </blockquote>
   * 
   * @param aInt
   *          the integer to encode.
   */
  public void encodeInt( final int aInt )
  {
    encodeInt( aInt, 0x02 );
  }

  /**
   * Encodes an int and a aTag. <blockquote>
   * 
   * <pre>
   * BER integer w aTag ::= aTag berlength byte {byte}*
   * </pre>
   * 
   * </blockquote>
   * 
   * @param aInt
   *          the integer to encode;
   * @param aTag
   *          the aTag to encode.
   */
  public void encodeInt( int aInt, final int aTag )
  {
    final int mask = 0xff800000;
    int intsize = 4;

    while ( ( ( ( aInt & mask ) == 0 ) || ( ( aInt & mask ) == mask ) ) && ( intsize > 1 ) )
    {
      intsize--;
      aInt <<= 8;
    }

    encodeInt( aInt, aTag, intsize );
  }

  /**
   * Encodes an octet string and a aTag.
   * 
   * @param aBuf
   *          the string (byte array) to encode;
   * @param aTag
   *          the aTag to encode.
   * @throws EncodeException
   *           in case encoding failed.
   */
  public void encodeOctetString( final byte[] aBuf, final int aTag ) throws EncodeException
  {
    encodeOctetString( aBuf, aTag, 0, aBuf.length );
  }

  /**
   * Encodes a portion of an octet string and a aTag.
   * 
   * @param aBuf
   *          the string (byte array) to encode;
   * @param aTag
   *          the aTag to encode;
   * @param aOffset
   *          the offset in the byte array to encode;
   * @param aLength
   *          the length to encode.
   * @throws EncodeException
   *           in case encoding failed.
   */
  public void encodeOctetString( final byte[] aBuf, final int aTag, final int aOffset, final int aLength )
      throws EncodeException
  {
    encodeByte( aTag );
    encodeLength( aLength );

    if ( aLength > 0 )
    {
      ensureFreeBytes( aLength );
      System.arraycopy( aBuf, aOffset, this.buf, this.offset, aLength );
      this.offset += aLength;
    }
  }

  /**
   * Encodes a string. <blockquote>
   * 
   * <pre>
   * BER string ::= 0x04 strlen byte1 byte2...
   * </pre>
   * 
   * </blockquote>
   * <p>
   * The string is converted into bytes using UTF-8 or ISO-Latin-1.
   * </p>
   * 
   * @param aString
   *          the string to encode;
   * @param aEncodeUTF8
   *          If <code>true</code>, use UTF-8 when encoding the string;
   *          otherwise use ISO-Latin-1 (8859_1). Use <code>true</code> for
   *          LDAPv3; <code>false</code> for LDAPv2.
   * @throws EncodeException
   *           in case encoding failed.
   */
  public void encodeString( final String aString, final boolean aEncodeUTF8 ) throws EncodeException
  {
    encodeString( aString, ASN_OCTET_STR, aEncodeUTF8 );
  }

  /**
   * Encodes a string and a aTag. <blockquote>
   * 
   * <pre>
   * BER string w aTag ::= aTag strlen byte1 byte2...
   * </pre>
   * 
   * </blockquote>
   * 
   * @param aString
   *          the string to encode;
   * @param aTag
   *          the aTag to encode;
   * @param aEncodeUTF8
   *          If <code>true</code>, use UTF-8 when encoding the string;
   *          otherwise use ISO-Latin-1 (8859_1). Use <code>true</code> for
   *          LDAPv3; <code>false</code> for LDAPv2.
   * @throws EncodeException
   *           in case encoding failed.
   */
  public void encodeString( final String aString, final int aTag, final boolean aEncodeUTF8 ) throws EncodeException
  {
    encodeByte( aTag );

    int i = 0;
    int count;
    byte[] bytes = null;

    if ( aString == null )
    {
      count = 0;
    }
    else if ( aEncodeUTF8 )
    {
      try
      {
        bytes = aString.getBytes( "UTF8" );
        count = bytes.length;
      }
      catch ( final UnsupportedEncodingException e )
      {
        throw new EncodeException( "UTF8 not available on platform" );
      }
    }
    else
    {
      try
      {
        bytes = aString.getBytes( "8859_1" );
        count = bytes.length;
      }
      catch ( final UnsupportedEncodingException e )
      {
        throw new EncodeException( "8859_1 not available on platform" );
      }
    }

    encodeLength( count );

    ensureFreeBytes( count );
    while ( i < count )
    {
      this.buf[this.offset++] = bytes[i++];
    }
  }

  /**
   * Encodes an array of strings.
   * 
   * @param aStrings
   *          the string array to encode;
   * @param aEncodeUTF8
   *          If <code>true</code>, use UTF-8 when encoding the string;
   *          otherwise use ISO-Latin-1 (8859_1). Use <code>true</code> for
   *          LDAPv3; <code>false</code> for LDAPv2.
   * @throws EncodeException
   *           in case encoding failed.
   */
  public void encodeStringArray( final String[] aStrings, final boolean aEncodeUTF8 ) throws EncodeException
  {
    if ( aStrings == null )
    {
      return;
    }
    for ( final String str : aStrings )
    {
      encodeString( str, aEncodeUTF8 );
    }
  }

  /**
   * Terminate a BER sequence.
   * 
   * @throws EncodeException
   *           in case encoding failed;
   * @throws IllegalStateException
   *           in case no sequence was started.
   */
  public void endSeq() throws EncodeException
  {
    this.curSeqIndex--;
    if ( this.curSeqIndex < 0 )
    {
      throw new IllegalStateException( "BER encode error: Unbalanced SEQUENCEs." );
    }

    final int start = this.seqOffset[this.curSeqIndex] + 3; // index beyond
    // length field
    final int len = this.offset - start;

    if ( len <= 0x7f )
    {
      shiftSeqData( start, len, -2 );
      this.buf[this.seqOffset[this.curSeqIndex]] = ( byte )len;
    }
    else if ( len <= 0xff )
    {
      shiftSeqData( start, len, -1 );
      this.buf[this.seqOffset[this.curSeqIndex]] = ( byte )0x81;
      this.buf[this.seqOffset[this.curSeqIndex] + 1] = ( byte )len;
    }
    else if ( len <= 0xffff )
    {
      this.buf[this.seqOffset[this.curSeqIndex]] = ( byte )0x82;
      this.buf[this.seqOffset[this.curSeqIndex] + 1] = ( byte )( len >> 8 );
      this.buf[this.seqOffset[this.curSeqIndex] + 2] = ( byte )len;
    }
    else if ( len <= 0xffffff )
    {
      shiftSeqData( start, len, 1 );
      this.buf[this.seqOffset[this.curSeqIndex]] = ( byte )0x83;
      this.buf[this.seqOffset[this.curSeqIndex] + 1] = ( byte )( len >> 16 );
      this.buf[this.seqOffset[this.curSeqIndex] + 2] = ( byte )( len >> 8 );
      this.buf[this.seqOffset[this.curSeqIndex] + 3] = ( byte )len;
    }
    else
    {
      throw new EncodeException( "SEQUENCE too long" );
    }
  }

  /**
   * Gets the buffer that contains the BER encoding. Throws an exception if
   * unmatched beginSeq() and endSeq() pairs were encountered. Not entire buffer
   * contains encoded bytes. Use getDataLen() to determine number of encoded
   * bytes. Use getBuffer(true) to get rid of excess bytes in array.
   * 
   * @return the byte buffer containing the BER-encoded value(s).
   * @throws IllegalStateException
   *           If buffer contains unbalanced sequence.
   */
  public byte[] getBuf()
  {
    if ( this.curSeqIndex != 0 )
    {
      throw new IllegalStateException( "BER encode error: Unbalanced SEQUENCEs." );
    }
    return this.buf;
  }

  /**
   * Gets the number of encoded bytes in this BER buffer.
   * 
   * @return the number of encoded bytes.
   */
  public int getDataLen()
  {
    return this.offset;
  }

  /**
   * Gets the buffer that contains the BER encoding, trimming unused bytes.
   * 
   * @return the buffer.
   */
  public byte[] getTrimmedBuf()
  {
    final int len = getDataLen();
    final byte[] trimBuf = new byte[len];

    System.arraycopy( getBuf(), 0, trimBuf, 0, len );
    return trimBuf;
  }

  /**
   * Resets encoder to state when newly constructed. Zeros out internal data
   * structures.
   */
  public void reset()
  {
    while ( this.offset > 0 )
    {
      this.buf[--this.offset] = 0;
    }
    while ( this.curSeqIndex > 0 )
    {
      this.seqOffset[--this.curSeqIndex] = 0;
    }
  }

  /**
   * Encodes an int using numbytes for the actual encoding.
   * 
   * @param aInt
   *          the integer to encode;
   * @param aTag
   *          the tag to encode;
   * @param aIntSize
   *          the size of the integer to encode.
   * @throws IllegalArgumentException
   *           in case the integer was too big to be encoded.
   */
  private void encodeInt( int aInt, final int aTag, int aIntSize )
  {
    //
    // integer ::= 0x02 asnlength byte {byte}*
    //

    if ( aIntSize > 4 )
    {
      throw new IllegalArgumentException( "BER encode error: INTEGER too long." );
    }

    ensureFreeBytes( 2 + aIntSize );

    this.buf[this.offset++] = ( byte )aTag;
    this.buf[this.offset++] = ( byte )aIntSize;

    final int mask = 0xff000000;

    while ( aIntSize-- > 0 )
    {
      this.buf[this.offset++] = ( byte )( ( aInt & mask ) >> 24 );
      aInt <<= 8;
    }
  }

  /**
   * Encodes a length.
   * 
   * @param aLength
   *          the length value to encode.
   * @throws EncodeException
   *           in case encoding failed.
   */
  private void encodeLength( final int aLength ) throws EncodeException
  {
    ensureFreeBytes( 4 ); // worst case

    if ( aLength < 128 )
    {
      this.buf[this.offset++] = ( byte )aLength;
    }
    else if ( aLength <= 0xff )
    {
      this.buf[this.offset++] = ( byte )0x81;
      this.buf[this.offset++] = ( byte )aLength;
    }
    else if ( aLength <= 0xffff )
    {
      this.buf[this.offset++] = ( byte )0x82;
      this.buf[this.offset++] = ( byte )( aLength >> 8 );
      this.buf[this.offset++] = ( byte )( aLength & 0xff );
    }
    else if ( aLength <= 0xffffff )
    {
      this.buf[this.offset++] = ( byte )0x83;
      this.buf[this.offset++] = ( byte )( aLength >> 16 );
      this.buf[this.offset++] = ( byte )( aLength >> 8 );
      this.buf[this.offset++] = ( byte )( aLength & 0xff );
    }
    else
    {
      throw new EncodeException( "string too long" );
    }
  }

  /**
   * Ensures that there are at least "len" unused bytes in "buf". When more
   * space is needed "buf" is expanded by a factor of BUF_GROWTH_FACTOR, then
   * "len" bytes are added if "buf" still isn't large enough.
   * 
   * @param aLen
   *          the number of bytes that should be free at least.
   */
  private void ensureFreeBytes( final int aLen )
  {
    if ( ( this.bufsize - this.offset ) < aLen )
    {
      int newsize = this.bufsize * BUF_GROWTH_FACTOR;
      if ( ( newsize - this.offset ) < aLen )
      {
        newsize += aLen;
      }
      final byte[] newbuf = new byte[newsize];
      // Only copy bytes in the range [0, offset)
      System.arraycopy( this.buf, 0, newbuf, 0, this.offset );

      this.buf = newbuf;
      this.bufsize = newsize;
    }
  }

  /**
   * Shifts contents of buf in the range [start,start+len) a specified amount.
   * Positive shift value means shift to the right.
   * 
   * @param aStart
   *          the start index;
   * @param aLen
   *          the length;
   * @param aShift
   *          the (relative) shift index.
   */
  private void shiftSeqData( final int aStart, final int aLen, final int aShift )
  {
    if ( aShift > 0 )
    {
      ensureFreeBytes( aShift );
    }
    System.arraycopy( this.buf, aStart, this.buf, aStart + aShift, aLen );
    this.offset += aShift;
  }
}
