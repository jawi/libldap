/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension.impl;


import java.io.*;

import javax.naming.*;
import javax.naming.ldap.*;
import javax.net.ssl.*;

import nl.lxtreme.ldap.*;
import nl.lxtreme.ldap.extension.*;


/**
 * StartTLS enforces the LDAPv3 server to use TLS (SSL) communication, as
 * defined in RFC 2830, RFC 4511, RFC 4513.
 */
public class StartTLS extends BaseExtension implements IStartTLS
{
  // VARIABLES

  private HostnameVerifier hostNameVerifier;
  private StartTlsResponse tlsResponse;

  // CONSTRUCTORS

  /**
   * Creates a new StartTLS object.
   * 
   * @param aContextProvider
   *          the LDAP context provider to use.
   */
  public StartTLS( final LdapContextProvider aContextProvider )
  {
    super( aContextProvider );
    this.hostNameVerifier = null;
  }

  // METHODS

  /**
   * {@inheritDoc}
   */
  @Override
  public void closeTLS() throws NamingException, IOException, IllegalStateException
  {
    if ( this.tlsResponse == null )
    {
      throw new IllegalStateException( "Cannot close TLS connection: it is not started!" );
    }

    try
    {
      final StartTlsResponse response = getTlsResponse();
      response.close();
    }
    finally
    {
      // Make sure the start-TLS response is cleared; next time we either get
      // a illegal state exception, or simply re-create it...
      this.tlsResponse = null;
    }
  }

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
  @Override
  public void setHostnameVerifier( final HostnameVerifier aHostnameVerifier ) throws IllegalArgumentException
  {
    this.hostNameVerifier = aHostnameVerifier;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void startTLS() throws NamingException, IOException
  {
    final StartTlsResponse response = getTlsResponse();
    response.negotiate();
  }

  /**
   * Returns the start-TLS response, lazy creating the request if necessary.
   * 
   * @return a start-TLS response, never <code>null</code>.
   * @throws NamingException
   *           in case of connection problems.
   */
  private StartTlsResponse getTlsResponse() throws NamingException
  {
    if ( this.tlsResponse == null )
    {
      this.tlsResponse = ( StartTlsResponse )extendedOperation( new StartTlsRequest() );
      if ( this.hostNameVerifier != null )
      {
        this.tlsResponse.setHostnameVerifier( this.hostNameVerifier );
      }
    }
    return this.tlsResponse;
  }
}
