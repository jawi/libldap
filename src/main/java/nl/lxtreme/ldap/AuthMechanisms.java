/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap;


/**
 * AuthMechanisms provides the various authentication methods that can be used
 * in LDAP implementations provided by the JDK.
 */
public enum AuthMechanisms
{
  /** Don't use authentication. */
  NONE( "none" ),
  /** Use simple (plain text) authentication. */
  SIMPLE( "simple" ),
  /** Use SASL Digest-MD5 authentication. */
  SASL_DIGEST_MD5( "DIGEST-MD5" ),
  /** Use SASL GSSAPI (Kerberos v5) authentication. */
  SASL_GGSAPI( "GSSAPI" ),
  /** Use SASL external authentication. */
  SASL_EXTERNAL( "EXTERNAL" );

  // VARIABLES

  private final String name;

  // CONSTRUCTORS

  /**
   * Creates a new AuthMechanisms object.
   * 
   * @param aName
   *          the name to use.
   */
  private AuthMechanisms( final String aName )
  {
    this.name = aName;
  }

  /**
   * Returns the name of this authentication mechanism, as used in the LDAP
   * provider of the JDK.
   * 
   * @return a name, never <code>null</code>.
   */
  public String getName()
  {
    return this.name;
  }
}
