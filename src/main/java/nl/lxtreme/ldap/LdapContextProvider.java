/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap;


import javax.naming.*;
import javax.naming.ldap.*;


/**
 * Basic interface for LDAP-context providers.
 */
public interface LdapContextProvider
{
  // METHOD

  /**
   * Returns the LDAP context.
   * 
   * @return a LDAP context, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public abstract LdapContext getContext() throws NamingException;
}
