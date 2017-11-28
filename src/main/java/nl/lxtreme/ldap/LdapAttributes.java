/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap;


/**
 * Provides some constants for very common LDAP attributes.
 */
interface LdapAttributes
{
  // CONSTANTS

  /** the attribute name to obtain all supported LDAPv3 extensions. */
  static final String ATTR_SUPPORTED_EXTENSION = "supportedExtension";

  /** OpenLDAP base DN attribute */
  static final String ATTR_NAMING_CONTEXT = "namingContexts";

  /** Novell base DN attribute */
  static final String ATTR_DSA_NAME = "dsaName";

  /** Microsoft Active Directory base DN attribute */
  static final String ATTR_DEFAULT_NAMING_CONTEXT = "defaultNamingContext";

}
