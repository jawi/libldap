/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension;


import javax.naming.*;

import nl.lxtreme.ldap.*;


/**
 * IWhoAmI performs a simple "who am I" query on the LDAP server as defined in
 * RFC 4532.
 */
public interface IWhoAmI extends LdapExtension
{
  // CONSTANTS

  /** The object ID of this extension, as defined in RFC 4532. */
  public static final String OID = "1.3.6.1.4.1.4203.1.11.3";

  // METHODS

  /**
   * Returns the identity of the current authenticated user.
   *
   * @return a DN of the current authenticated user, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public abstract String whoAmI() throws NamingException;
}
