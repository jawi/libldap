/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension;


import javax.naming.*;

import nl.lxtreme.ldap.*;


/**
 * IChangePassword provides a pure Java implementation of RFC 3062, the "LDAP
 * Password Modify Extended Operation" supported by most LDAPv3 servers.
 */
public interface IChangePassword extends LdapExtension
{
  // CONSTANTS

  /** The object ID of this extension, as defined in RFC 3062. */
  public static final String OID = "1.3.6.1.4.1.4203.1.11.1";

  // METHODS

  /**
   * Changes the password of the user denoted by a given DN and password to the
   * new password given.
   *
   * @param aUserDN
   *          the DN of the user requesting the modify password operation, may
   *          not be <code>null</code>;
   * @param aCurrentPassword
   *          the current password of the user, may be <code>null</code> if the
   *          user currently has no password set;
   * @param aNewPassword
   *          the new password of the user, may not be <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   */
  public abstract void changePassword( final String aUserDN, final String aCurrentPassword, final String aNewPassword )
      throws NamingException;

  /**
   * Changes the password of the user denoted by a given DN to a
   * server-generated password and returns it.
   *
   * @param aUserDN
   *          the DN of the user requesting the modify password operation, may
   *          not be <code>null</code>;
   * @param aCurrentPassword
   *          the current password of the user, may be <code>null</code> if the
   *          user currently has no password set.
   * @return the generated password, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   */
  public abstract String generatePassword( final String aUserDN, final String aCurrentPassword ) throws NamingException;
}
