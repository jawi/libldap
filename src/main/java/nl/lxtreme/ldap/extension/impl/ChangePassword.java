/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl;

import java.io.*;

import javax.naming.*;
import javax.naming.ldap.*;

import nl.lxtreme.ldap.*;
import nl.lxtreme.ldap.extension.*;
import nl.lxtreme.ldap.extension.impl.encoding.*;


/**
 * ChangePassword provides a pure Java implementation of RFC 3062, the "LDAP
 * Password Modify Extended Operation" supported by most LDAPv3 servers.
 * <p>
 * This class is based on code found on <a href="d-dt.de/ldap">this site</a>.
 * </p>
 */
public final class ChangePassword extends BaseExtension implements IChangePassword
{
  // CONSTANTS

  /** For LDAPv3, always use UTF8. */
  private static final boolean USE_UTF8 = true;

  // INNER TYPES

  /**
   * ChangePasswordRequest
   * <p>
   * This class implements an LDAPv3 Extended Request for password changing as
   * defined in <a href="http://www.ietf.org/rfc/rfc3062.txt">RFC 3062 - LDAP
   * Password Modify Extended Operation</a>.
   * </p>
   * <p>
   * The object identifier for this operation is "1.3.6.1.4.1.4203.1.11.1". If
   * any of userIdentity, oldPasswd or newPasswd value is defined, a extended
   * request sequence is assembled.
   * </p>
   * <p>
   * <tt>PasswordChangeRequest</tt>/<tt>PasswordChangeResponse</tt> are used to
   * change passwords of directory entries which can hold userPassword, as
   * defined e.g. for person, inetOrgPerson, simpleSecurityObject and so on.
   * Whichever password encryption method is used to store a password (hash)
   * value in this attribute is determined by server itself. (It's not even
   * guaranteed that the attribute containing a user's password is named
   * userPassword)
   * </p>
   * <p>
   * PasswordChangeRequest takes an user identity, usually a DN, the old
   * password and the new password as parameters. Every of these values can be
   * left out by setting it to null. Depending on directory server
   * implementation, it is commonly sufficient only to provide the new password,
   * since user's identity and his authorization for changing is already granted
   * by bind operation thru its credentials. However a directory administrator,
   * such as "cn=Manager,dc=..." is able to change another's password by simply
   * specifying its DN.
   * </p>
   * <p>
   * Specifying old password normally is never required, but it may be used if
   * one want to change foreign passwords without having administrative rights
   * (Never tried this, but I think such would be only depends on server's ACL
   * settings.)
   * </p>
   * <p>
   * Omitting new password mentioning will ask the server to generate a random
   * password which will be replied to PasswordChangeResponse.
   * </p>
   */
  static final class ChangePasswordRequest implements ExtendedRequest
  {
    private static final long serialVersionUID = 1L;

    private final byte[]      request;

    /**
     * Creates a new ChangePasswordRequest object.
     *
     * @param aUserDN
     *          the DN of the user requesting the modify password operation;
     * @param aCurPasswd
     *          the current password of the user.
     */
    public ChangePasswordRequest( final String aUserDN, final String aCurPasswd )
    {
      this( aUserDN, aCurPasswd, null /* aNewPasswd */);
    }

    /**
     * Creates a new ChangePasswordRequest object.
     *
     * @param aUserDN
     *          the DN of the user requesting the modify password operation;
     * @param aCurPasswd
     *          the current password of the user;
     * @param aNewPasswd
     *          the new password of the user.
     * @throws IllegalStateException
     *           in case the given data could not be encoded into a BER-value.
     */
    public ChangePasswordRequest( final String aUserDN, final String aCurPasswd, final String aNewPasswd )
    {
      try
      {
        final BerEncoder encoder = new BerEncoder();

        if ( aUserDN != null )
        {
          encoder.beginSeq( Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR ); // = 0x30;

          // Tagged, optional context fields
          encoder.encodeString( aUserDN, Ber.ASN_CONTEXT | 0x00, !USE_UTF8 );

          if ( aCurPasswd != null )
          {
            encoder.encodeString( aCurPasswd, Ber.ASN_CONTEXT | 0x01, USE_UTF8 );
          }

          if ( aNewPasswd != null )
          {
            encoder.encodeString( aNewPasswd, Ber.ASN_CONTEXT | 0x02, USE_UTF8 );
          }
          encoder.endSeq();
        }

        this.request = encoder.getTrimmedBuf();
      }
      catch ( final IOException exception )
      {
        throw new IllegalStateException( "BER encoding error: " + exception.getMessage() );
      }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse createExtendedResponse( final String aId, final byte[] aBerValue, final int aOffset,
        final int aLength ) throws NamingException
    {
      final String[] generatedPasswd = new String[1];

      try
      {
        final BerDecoder decoder = new BerDecoder( aBerValue, aOffset, aLength );

        if ( decoder.bytesLeft() > 0 )
        {
          final int seqTag = decoder.parseSeq( null /* rlen */);
          if ( ( seqTag == ( Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR ) ) && ( decoder.bytesLeft() > 0 ) )
          {
            // Take the first (optional) argument of the sequence...
            generatedPasswd[0] = decoder.parseStringWithTag( Ber.ASN_CONTEXT | 0x00, USE_UTF8, null /* rlen */);
          }
        }
      }
      catch ( final IOException exception )
      {
        throw new IllegalStateException( "BER decoding error: " + exception.getMessage() );
      }

      return new ExtendedResponse()
      {
        private static final long serialVersionUID = 1L;

        /**
         * {@inheritDoc}
         */
        @Override
        public byte[] getEncodedValue()
        {
          return ( generatedPasswd[0] == null ) ? null : generatedPasswd[0].getBytes();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getID()
        {
          return aId;
        }
      };
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedValue()
    {
      return this.request;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final String getID()
    {
      return IChangePassword.OID;
    }
  }

  // CONSTRUCTORS

  /**
   * Creates a new ChangePassword object.
   *
   * @param aContextProvider
   *          the LDAP context provider to use.
   */
  public ChangePassword( final LdapContextProvider aContextProvider )
  {
    super( aContextProvider );
  }

  // METHODS

  /**
   * {@inheritDoc}
   */
  public void changePassword( final String aUserDN, final String aCurrentPassword, final String aNewPassword )
      throws NamingException
  {
    if ( ( aUserDN == null ) || ( aUserDN.trim().length() == 0 ) )
    {
      throw new IllegalArgumentException( "User DN cannot be null or empty!" );
    }
    if ( ( aNewPassword == null ) || ( aNewPassword.trim().length() == 0 ) )
    {
      throw new IllegalArgumentException( "Change password needs a new password!" );
    }

    extendedOperation( new ChangePasswordRequest( aUserDN, aCurrentPassword, aNewPassword ) );
  }

  /**
   * {@inheritDoc}
   */
  public String generatePassword( final String aUserDN, final String aCurrentPassword ) throws NamingException
  {
    if ( ( aUserDN == null ) || ( aUserDN.trim().length() == 0 ) )
    {
      throw new IllegalArgumentException( "User DN cannot be null or empty!" );
    }

    final ExtendedResponse response = extendedOperation( new ChangePasswordRequest( aUserDN, aCurrentPassword ) );
    return new String( response.getEncodedValue() );
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String getOID()
  {
    return OID;
  }
}
