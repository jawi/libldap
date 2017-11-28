/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap;


/**
 * Base interface for all LDAPv3 extensions.
 */
public interface LdapExtension
{
  // METHODS

  /**
   * Returns the extension object ID.
   *
   * @return an extension object ID, like "1.3.12.x...", may not be
   *         <code>null</code>.
   */
  public abstract String getOID();
}
