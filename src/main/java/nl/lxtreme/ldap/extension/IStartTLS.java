/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.extension;


import java.io.*;

import javax.naming.*;
import javax.naming.ldap.*;
import javax.net.ssl.*;

import nl.lxtreme.ldap.*;


/**
 * IStartTLS enforces the LDAPv3 server to use TLS (SSL) communication, as
 * defined in RFC 2830.
 */
public interface IStartTLS extends LdapExtension
{
  // CONSTANTS

  /** The object ID of this extension, as defined in RFC 2830. */
  public static final String OID = StartTlsRequest.OID;

  // METHODS

  /**
   * Closes/stops the TLS communication with the LDAP server.
   * <ul>
   * <li>Note 1: The i-Planet Directory Server, v5.0, does not respond to this
   * method, leaving the client blocked;</li>
   * <li>Note 2: The OpenLDAP server, upon receiving the close message, will
   * shut down the connection instead of downgrading it to a plain connection.</li>
   * </ul>
   * 
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   * @throws IOException
   *           in case of I/O (network) problems during the closing of the TLS
   *           connection;
   * @throws IllegalStateException
   *           in case the TLS connection was never started.
   * @see #startTLS()
   */
  public abstract void closeTLS() throws NamingException, IOException, IllegalStateException;

  /**
   * Sets the hostname verifier to use during the TLS negotiation.
   * 
   * @param aHostnameVerifier
   *          a hostname verifier, may be <code>null</code> to disable its use.
   */
  public abstract void setHostnameVerifier( final HostnameVerifier aHostnameVerifier );

  /**
   * Starts the TLS communication with the LDAP server.
   * <p>
   * Note that after starting a TLS-session with your LDAP server you
   * <em>must</em> reconnect to the LDAP server to make the authenticated user
   * known for this session.
   * </p>
   * 
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   * @throws IOException
   *           in case of I/O (network) problems during the closing of the TLS
   *           connection.
   */
  public abstract void startTLS() throws NamingException, IOException;
}
