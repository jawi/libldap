/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap;


/**
 * Denotes the various supported servers.
 */
public enum ServerType
{
  OPENLDAP( "OpenLDAP" ), //
  AD_W2k3( "Active Directory Win2k3 or later" ), //
  AD_W2k( "Active Directory Win2k or later" ), //
  AD_UNKNOWN( "Active Directory (unknown)" ), //
  UNKNOWN( "Unknown LDAP server" );

  private final String displayName;

  /**
   * Creates a new ServerType object.
   *
   * @param aDisplayName
   *          the display name of this server type.
   */
  private ServerType( final String aDisplayName )
  {
    this.displayName = aDisplayName;
  }

  /**
   * Returns the display name of this server type.
   *
   * @return a display name, never <code>null</code>.
   */
  public String getDisplayName()
  {
    return this.displayName;
  }
}
