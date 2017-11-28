/*
 * LibLDAP - Small LDAP library for Java.
 *
 * (C) Copyright 2010-2017, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap.tool;


import java.io.*;
import java.util.*;

import javax.naming.*;
import javax.naming.directory.*;

import nl.lxtreme.ldap.*;


/**
 *
 */
public final class LdapTool
{
  // CONSTANTS

  private static final String ATTR_SUPPORTED_SASL_MECHANISMS = "supportedSASLMechanisms";
  private static final String ATTR_SUPPORTED_LDAP_VERSION = "supportedLDAPVersion";

  // VARIABLES

  private String serverURL;
  private String bindDN;

  private LibLdap simpleLDAP;

  private final List<String> commandArgs = new ArrayList<String>();
  private Map<String, String> settings;

  private String command;

  // CONSTRUCTORS

  /**
   * Creates a new LdapTool.
   */
  public LdapTool()
  {
    // NO-op
  }

  /**
   * Creates a new LdapTool object.
   *
   * @param aArgs
   *          the cmd line arguments.
   */
  public LdapTool( final String... aArgs )
  {
    String server = null;
    String bindDN = null;
    String userDN = null;
    String passwd = null;

    // No command...
    this.command = null;

    final int argLength = ( aArgs == null ) ? 0 : aArgs.length;
    for ( int i = 0; i < argLength; i++ )
    {
      final String arg = aArgs[i];
      if ( "-server".equalsIgnoreCase( arg ) || "-serverURL".equalsIgnoreCase( arg ) )
      {
        server = aArgs[++i];
      }
      if ( "-binddn".equalsIgnoreCase( arg ) )
      {
        bindDN = aArgs[++i];
      }
      else if ( "-userdn".equalsIgnoreCase( arg ) )
      {
        userDN = aArgs[++i];
      }
      else if ( "-passwd".equalsIgnoreCase( arg ) )
      {
        passwd = aArgs[++i];
      }
      else if ( "-?".equals( arg ) || "-h".equals( arg ) || "-help".equals( arg ) )
      {
        System.out.println( getHelp() );
      }
      else if ( !arg.startsWith( "-" ) )
      {
        if ( this.command == null )
        {
          this.command = arg;
        }
        else
        {
          this.commandArgs.add( arg );
        }
      }
    }

    if ( server == null )
    {
      System.err.println( "No server provided!" );
      System.out.println( getHelp() );
    }
    if ( bindDN == null )
    {
      System.err.println( "No bind-DN provided!" );
      System.out.println( getHelp() );
    }
    if ( this.command == null )
    {
      this.command = "ping";
    }

    // Keep the server URL & bind stuff...
    this.serverURL = server;

    // Ensure the bind-DN always starts with a leading slash...
    if ( !bindDN.startsWith( "/" ) )
    {
      bindDN = "/".concat( bindDN );
    }

    this.settings = new HashMap<String, String>();
    this.settings.put( Context.PROVIDER_URL, server + bindDN );
    if ( userDN != null )
    {
      this.settings.put( Context.SECURITY_AUTHENTICATION, "simple" );
      this.settings.put( Context.SECURITY_PRINCIPAL, userDN );
      if ( passwd != null )
      {
        this.settings.put( Context.SECURITY_CREDENTIALS, passwd );
      }
    }
  }

  // METHODS

  /**
   * MAIN ENTRY POINT
   *
   * @param aArgs
   *          the cmd line arguments.
   * @throws Exception
   *           IllegalArgumentException in case of illegal arguments;
   */
  public static void main( final String... aArgs ) throws Exception
  {
    final LdapTool tool = new LdapTool( aArgs );
    tool.run();
  }

  /**
   * Binds to the server with the supplied credentials.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _bind() throws Exception
  {
    if ( ( this.serverURL == null ) || this.serverURL.isEmpty() )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    Console con = System.console();

    final String userDN = con.readLine( "User DN : " );
    final String passwd = new String( con.readPassword( "Password: " ) );

    final Map<String, String> settings = new HashMap<String, String>();
    if ( userDN != null )
    {
      settings.put( Context.SECURITY_AUTHENTICATION, "simple" );
      settings.put( Context.SECURITY_PRINCIPAL, userDN );
      if ( passwd != null )
      {
        settings.put( Context.SECURITY_CREDENTIALS, passwd );
      }
    }

    // Is the base/bind DN given? If not, try to determine it ourselves...
    if ( this.bindDN == null )
    {
      // First attempt to connect without any base/bind DN...
      this.simpleLDAP = new LibLdap( this.serverURL, "", userDN, passwd );
      this.simpleLDAP.reconnect();

      // Check what the server tells us...
      final String[] baseDNs = this.simpleLDAP.getBaseDNs();
      if ( ( baseDNs != null ) && ( baseDNs.length > 0 ) )
      {
        this.bindDN = baseDNs[0];
        System.out.println( "Determined bind DN to be " + this.bindDN );
      }
    }

    // Ensure the bind-DN always starts with a leading slash...
    if ( this.bindDN != null )
    {
      if ( !this.bindDN.isEmpty() && !this.bindDN.startsWith( "/" ) )
      {
        this.bindDN = "/".concat( this.bindDN );
      }
      // Give the correct provider URL...
      settings.put( Context.PROVIDER_URL, this.serverURL + this.bindDN );
    }

    this.simpleLDAP = new LibLdap( this.serverURL, settings );
    this.simpleLDAP.reconnect();
  }

  /**
   * Performs an LDAP query.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _changePasswd() throws Exception
  {
    final BufferedReader reader = new BufferedReader( new InputStreamReader( System.in ) );

    final String userDN, oldPassword, newPassword;

    final Console cons = System.console();
    if ( cons != null )
    {
      userDN = new String( cons.readLine( "User DN (empty = current user DN): " ) ).trim();
      oldPassword = new String( cons.readPassword( "Old password: " ) ).trim();
      newPassword = new String( cons.readPassword( "New password: " ) ).trim();
    }
    else
    {
      System.out.println( "User DN (empty = current user DN): " );
      userDN = reader.readLine().trim();
      System.out.println( "Old password: " );
      oldPassword = reader.readLine().trim();
      System.out.println( "New password: " );
      newPassword = reader.readLine().trim();
    }

    boolean result = this.simpleLDAP.changePassword( userDN, oldPassword, newPassword );
    System.out.println( "Change password was " + ( result ? "successful" : "failed!" ) );
  }

  /**
   * Closes the LDAP connection.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _close() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    this.simpleLDAP.close();
  }

  /**
   * Connects to the LDAP server and (optional) bind-DN.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _connect() throws Exception
  {
    Console con = System.console();

    this.serverURL = con.readLine( "Server URL: " );
    this.bindDN = con.readLine( "Bind DN: " );

    if ( ( this.serverURL == null ) || this.serverURL.isEmpty() )
    {
      System.out.print( "ERROR: no server URL given!" );
    }

    if ( this.simpleLDAP != null )
    {
      try
      {
        this.simpleLDAP.close();
      }
      finally
      {
        this.simpleLDAP = null;
      }
    }
  }

  /**
   * Shows the supported LDAP versions.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _ldapVersion() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    final List<Object> ldapVersion = this.simpleLDAP.getAttributeValue( this.simpleLDAP.getServerURL(),
        ATTR_SUPPORTED_LDAP_VERSION );

    System.out.println( "Supported LDAP version: " + ldapVersion );
  }

  /**
   * Lists the supported (SASL) authentication mechanisms.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _listAuthMech() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    // List supported authentication methods...
    final Map<String, List<Object>> saslMechs = this.simpleLDAP.getAttributes( this.simpleLDAP.getServerURL(),
        ATTR_SUPPORTED_SASL_MECHANISMS );
    System.out.println( "Supported SASL mechanisms: " + saslMechs.values() );
  }

  /**
   * Lists the supported extensions.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _listExt() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    System.out.println( "Supported extensions: " );

    // Show supported extensions...
    final String[] supportedServerExtensions = this.simpleLDAP.getSupportedServerExtensions();
    for ( final String extOID : supportedServerExtensions )
    {
      System.out.println( "\t" + extOID );
    }
  }

  /**
   * Tries to ping the server.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _ping() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    this.simpleLDAP.getBaseDNs();
    System.out.println( "Server alive..." );
  }

  /**
   * Performs an LDAP query.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _q() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }

    Console con = System.console();

    String command = con.readLine( "DN (<enter> for default): " );
    String filter = con.readLine( "Filter: " );

    // In case only one argument is given, use that one as filter and leave
    // the command empty...
    if ( ( filter == null ) && ( command != null ) )
    {
      filter = command;
      command = null;
    }

    final Collection<SearchResult> results = this.simpleLDAP.query( command, filter );
    System.out.println( "Query result for '" + command + "' with filter '" + filter + "': " );

    for ( final SearchResult result : results )
    {
      Attributes attributes = result.getAttributes();

      final NamingEnumeration<? extends Attribute> allAttrs = attributes.getAll();
      while ( allAttrs.hasMoreElements() )
      {
        final Attribute attr = allAttrs.next();

        final StringBuilder sb = new StringBuilder();
        writeAttribute( sb, attr );

        System.out.println( "\t" + sb.toString() );
      }
    }
  }

  /**
   * Tries to determine the LDAP server type.
   *
   * @param aCI
   *          the command interpreter to use.
   */
  public void _serverType() throws Exception
  {
    if ( this.simpleLDAP == null )
    {
      System.out.println( "ERROR: not connected!" );
      return;
    }
    final ServerType type = this.simpleLDAP.getServerType();
    System.out.println( "LDAP server appears to be " + type.getDisplayName() + "." );
  }

  /**
   * {@inheritDoc}
   */
  private String getHelp()
  {
    final StringBuilder sb = new StringBuilder();
    sb.append( "--- LDAP commands ---\n" );
    sb.append( "\tconnect <server URL> [<bind DN>] - connects to the server using the optional bind DN;\n" );
    sb.append( "\tclose - closes the connection;\n" );
    sb.append( "\tbind <user DN> <passwd> - binds to the server with the given username and password;\n" );
    sb.append( "\tping - pings the server;\n" );
    sb.append( "\tserverType - tries to determine the server kind\n" );
    sb.append( "\tlistExt - list the supported server extensions\n" );
    sb.append( "\tlistAuthMech - list the supported authentication mechanisms\n" );
    sb.append( "\tchangePW <old passwd> <new passwd> - changes the password\n" );
    sb.append( "\tldapVersion - queries for the LDAP version\n" );
    sb.append( "\tq <query> - executes the query on the server.\n" );
    return sb.toString();
  }

  /**
   * Runs the tool.
   *
   * @throws Exception
   *           IllegalArgumentException in case of illegal arguments;
   */
  private void run() throws Exception
  {
    final LibLdap ldap = new LibLdap( this.serverURL, this.settings );
    ldap.reconnect();

    if ( "ping".equalsIgnoreCase( this.command ) )
    {
      _ping();
    }
    else if ( "ldapVersion".equalsIgnoreCase( this.command ) )
    {
      _ldapVersion();
    }
    else if ( "listExt".equalsIgnoreCase( this.command ) )
    {
      _listExt();
    }
    else if ( "listAuthMech".equalsIgnoreCase( this.command ) )
    {
      _listAuthMech();
    }
    else if ( "serverType".equalsIgnoreCase( this.command ) )
    {
      _serverType();
    }
    else if ( "changePW".equalsIgnoreCase( this.command ) || "changePassword".equalsIgnoreCase( this.command ) )
    {
      _changePasswd();
    }
    else
    {
      final String filter = this.commandArgs.isEmpty() ? "" : this.commandArgs.get( 0 );

      final Collection<SearchResult> results = ldap.query( this.command, filter );
      System.out.println( "Query result for '" + this.command + "' with filter '" + filter + "': " );
      for ( final SearchResult result : results )
      {
        Attributes attributes = result.getAttributes();

        final NamingEnumeration<? extends Attribute> allAttrs = attributes.getAll();
        while ( allAttrs.hasMoreElements() )
        {
          final Attribute attr = allAttrs.next();

          final StringBuilder sb = new StringBuilder();
          writeAttribute( sb, attr );
          System.out.println( "\t" + sb.toString() );
        }
      }
    }

    ldap.close();
  }

  /**
   * @param aSB
   * @param aAttribute
   * @throws NamingException
   */
  private void writeAttribute( final StringBuilder aSB, final Attribute aAttribute ) throws NamingException
  {
    aSB.append( '(' );
    aSB.append( aAttribute.getID() );
    aSB.append( " = " );
    writeAttributeValues( aSB, aAttribute );
    aSB.append( ')' );
  }

  /**
   * @param aSB
   * @param aAttribute
   * @throws NamingException
   */
  private void writeAttributeValues( final StringBuilder aSB, final Attribute aAttribute ) throws NamingException
  {
    final int size = aAttribute.size();
    if ( size > 1 )
    {
      aSB.append( "[" );
    }
    for ( int i = 0; i < size; i++ )
    {
      if ( i > 0 )
      {
        aSB.append( ", " );
      }
      aSB.append( aAttribute.get( i ) );
    }
    if ( size > 1 )
    {
      aSB.append( "]" );
    }
  }
}
