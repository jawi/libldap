/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl;


import nl.lxtreme.ldap.*;
import nl.lxtreme.ldap.extension.*;


/**
 * Denotes the active directory extension used for Windows 2K3 and up.
 */
public class ActiveDirectoryWin2k3 extends BaseExtension implements IActiveDirectoryWin2k3
{
  // CONSTRUCTORS

  /**
   * @param aLdapContextProvider
   */
  public ActiveDirectoryWin2k3( final LdapContextProvider aLdapContextProvider )
  {
    super( aLdapContextProvider );
  }

  // METHODS

  /**
   * {@inheritDoc}
   */
  @Override
  public String getOID()
  {
    return OID;
  }
}
