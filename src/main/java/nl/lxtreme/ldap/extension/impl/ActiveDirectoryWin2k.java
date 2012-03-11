/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl;


import nl.lxtreme.ldap.*;
import nl.lxtreme.ldap.extension.*;


/**
 * Denotes the active directory extension used for Windows 2K and up.
 */
public class ActiveDirectoryWin2k extends BaseExtension implements IActiveDirectoryWin2k
{
  // CONSTRUCTORS

  /**
   * @param aLdapContextProvider
   */
  public ActiveDirectoryWin2k( final LdapContextProvider aLdapContextProvider )
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
