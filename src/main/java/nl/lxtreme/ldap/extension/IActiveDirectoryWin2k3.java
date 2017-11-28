/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension;


import nl.lxtreme.ldap.*;


/**
 * IActiveDirectoryW2K performs a query which indicates the server is an Active
 * Directory server (Win2k3 and later).
 */
public interface IActiveDirectoryWin2k3 extends LdapExtension
{
  // CONSTANTS

  /** The object ID of this extension. */
  public static final String OID = "1.2.840.113556.1.4.1670";
}
