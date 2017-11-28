/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl;


import javax.naming.*;
import javax.naming.ldap.*;

import nl.lxtreme.ldap.*;


/**
 * BaseExtension provides a common base class for all extensions.
 */
abstract class BaseExtension implements LdapExtension
{
  // VARIABLES

  private final LdapContextProvider ldapContextProvider;

  // CONSTRUCTORS

  /**
   * Creates a new BaseExtension object.
   *
   * @param aLdapContextProvider
   *          the LDAP context provider, cannot be <code>null</code>.
   * @throws IllegalArgumentException
   *           in case the given provider was <code>null</code>.
   */
  public BaseExtension( final LdapContextProvider aLdapContextProvider )
  {
    if ( aLdapContextProvider == null )
    {
      throw new IllegalArgumentException( "LDAP context provider cannot be null!" );
    }
    this.ldapContextProvider = aLdapContextProvider;
  }

  // METHODS

  /**
   * Returns the LDAP context.
   *
   * @return a LDAP context, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final LdapContext getContext() throws NamingException
  {
    return this.ldapContextProvider.getContext();
  }

  /**
   * Convenience method to perform an LDAPv3 "extended operation".
   *
   * @param aExtendedRequest
   *          the extended request to perform, cannot be <code>null</code>.
   * @return the extended response (created by the given extended request), may
   *         be <code>
   *         null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  protected final ExtendedResponse extendedOperation( final ExtendedRequest aExtendedRequest ) throws NamingException
  {
    return getContext().extendedOperation( aExtendedRequest );
  }
}
