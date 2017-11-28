/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl;


import javax.naming.*;
import javax.naming.ldap.*;

import nl.lxtreme.ldap.*;
import nl.lxtreme.ldap.extension.*;


/**
 * WhoAmI performs a simple "who am I" query on the LDAP server.
 */
public class WhoAmI extends BaseExtension implements IWhoAmI
{
  // INNER TYPES

  /**
   * WhoAmIRequest
   */
  static final class WhoAmIRequest implements ExtendedRequest
  {
    private static final long serialVersionUID = 1L;

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse createExtendedResponse( final String aId, final byte[] aBerValue, final int aOffset,
        final int aLength ) throws NamingException
    {
      return new ExtendedResponse()
      {
        private static final long serialVersionUID = 1L;

        @Override
        public byte[] getEncodedValue()
        {
          return aBerValue;
        }

        @Override
        public String getID()
        {
          return aId;
        }
      };
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedValue()
    {
      return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final String getID()
    {
      return IWhoAmI.OID;
    }
  }

  // CONSTRUCTORS

  /**
   * Creates a new WhoAmI object.
   *
   * @param aContextProvider
   *          the LDAP context provider to use.
   */
  public WhoAmI( final LdapContextProvider aContextProvider )
  {
    super( aContextProvider );
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

  /**
   * {@inheritDoc}
   */
  public String whoAmI() throws NamingException
  {
    final ExtendedResponse response = extendedOperation( new WhoAmIRequest() );
    return new String( response.getEncodedValue() );
  }
}
