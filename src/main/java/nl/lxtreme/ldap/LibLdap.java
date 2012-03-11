/*
 * LibLDAP - Small LDAP library for Java.
 * 
 * (C) Copyright 2010-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package nl.lxtreme.ldap;


import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.logging.*;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

import nl.lxtreme.ldap.extension.*;
import nl.lxtreme.ldap.extension.impl.*;


/**
 * {@link LibLdap} provides a simple LDAP facade for accessing LDAP from Java.
 */
public class LibLdap implements LdapContextProvider, LdapAttributes
{
  // CONSTANTS

  /** the registry containing all extensions this library can use. */
  private static final Map<String, Class<? extends LdapExtension>> EXTENSION_REGISTRY = new HashMap<String, Class<? extends LdapExtension>>();

  private static final String DEBUG_KEY = "nl.lxtreme.libldap.debug";
  private static final boolean DEBUG;

  private static final Logger LOG;

  static
  {
    // Default supported extensions.
    registerExtension( IChangePassword.OID, ChangePassword.class );
    registerExtension( IWhoAmI.OID, WhoAmI.class );
    registerExtension( IStartTLS.OID, StartTLS.class );
    registerExtension( IActiveDirectoryWin2k.OID, ActiveDirectoryWin2k.class );
    registerExtension( IActiveDirectoryWin2k3.OID, ActiveDirectoryWin2k3.class );

    final Boolean debugValue = Boolean.parseBoolean( System.getProperty( DEBUG_KEY, "true" ) );
    DEBUG = debugValue.booleanValue();

    LOG = Logger.getAnonymousLogger();
  }

  // VARIABLES

  private LdapContext context;
  private final Map<String, String> environment;
  private final String serverURL;

  // CONSTRUCTORS

  /**
   * Creates a new SimpleLDAP object.
   * <p>
   * Use this constructor in case you want full control about how the LDAP
   * context is created. The given environment parameter is typically filled as:
   * </p>
   * 
   * <pre>
   * final Hashtable&lt;String, String&gt; env = new Hashtable&lt;String, String&gt;();
   * env.put( Context.PROVIDER_URL, aServerURL + &quot;/dc=planon,dc=nl&quot; );
   * env.put( Context.SECURITY_AUTHENTICATION, &quot;simple&quot; );
   * env.put( Context.SECURITY_PRINCIPAL, &quot;my-ldap-username&quot; );
   * env.put( Context.SECURITY_CREDENTIALS, &quot;my-password&quot; );
   * </pre>
   * 
   * @param aServerURL
   *          the server URL to use, like "ldap://localhost:369/";
   * @param aEnvironment
   *          the environment to use.
   * @throws IllegalArgumentException
   *           in case the given server URL did not start with "ldap://" or
   *           "ldaps:///".
   */
  public LibLdap( final String aServerURL, final Map<String, String> aEnvironment ) throws IllegalArgumentException
  {
    if ( ( aServerURL == null ) || ( !aServerURL.startsWith( "ldap://" ) && !aServerURL.startsWith( "ldaps://" ) ) )
    {
      throw new IllegalArgumentException(
          "Invalid server URL: should be not null and start with 'ldap://' or 'ldaps://'!" );
    }
    if ( aEnvironment == null )
    {
      throw new IllegalArgumentException( "Invalid environment: cannot be null!" );
    }
    if ( !aEnvironment.containsKey( Context.PROVIDER_URL ) || ( aEnvironment.get( Context.PROVIDER_URL ) == null ) )
    {
      throw new IllegalArgumentException( "Invalid environment: No provider URL (Context.PROVIDER_URL) set!" );
    }
    if ( !aEnvironment.get( Context.PROVIDER_URL ).startsWith( aServerURL ) )
    {
      throw new IllegalArgumentException(
          "Invalid environment: provider URL value does not start with given server URL!" );
    }

    // Make sure the initial context factory is available...
    if ( !aEnvironment.containsKey( Context.INITIAL_CONTEXT_FACTORY ) )
    {
      aEnvironment.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
    }

    this.serverURL = aServerURL;
    this.environment = new Hashtable<String, String>( aEnvironment );
  }

  /**
   * Creates a new SimpleLDAP object with <em>simple</em> authentication.
   * <p>
   * Use this constructor in case of "simple" authentication, using username and
   * password.
   * </p>
   * 
   * @param aServerURL
   *          the server URL to use, like "ldap://localhost:369/";
   * @param aBaseDN
   *          the base DN, something like "dc=planon,dc=nl", to connect to the
   *          LDAP server;
   * @throws IllegalArgumentException
   *           in case the given server URL did not start with "ldap://" or
   *           "ldaps:///".
   */
  public LibLdap( final String aServerURL, final String aBaseDN ) throws IllegalArgumentException
  {
    if ( ( aServerURL == null ) || ( !aServerURL.startsWith( "ldap://" ) && !aServerURL.startsWith( "ldaps://" ) ) )
    {
      throw new IllegalArgumentException(
          "Invalid server URL: should be not null and start with 'ldap://' or 'ldaps://'!" );
    }

    this.serverURL = aServerURL;

    this.environment = new Hashtable<String, String>();
    this.environment.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
    this.environment.put( Context.PROVIDER_URL, aServerURL + "/" + aBaseDN );
    this.environment.put( Context.SECURITY_AUTHENTICATION, "simple" );
  }

  /**
   * Creates a new SimpleLDAP object and directly "binds" to the LDAP server
   * using the given username and password.
   * <p>
   * Use this constructor in case of "simple" authentication, using username and
   * password.
   * </p>
   * 
   * @param aServerURL
   *          the server URL to use, like "ldap://localhost:369/";
   * @param aBaseDN
   *          the base DN, something like "dc=planon,dc=nl", to connect to the
   *          LDAP server;
   * @param aUserDN
   *          the user DN, or the user that is connecting to the LDAP server;
   * @param aPassword
   *          the password of the user that is connecting to the LDAP server.
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   * @throws IllegalArgumentException
   *           in case the given server URL did not start with "ldap://" or
   *           "ldaps:///".
   */
  public LibLdap( final String aServerURL, final String aBaseDN, final String aUserDN, final String aPassword )
      throws NamingException, IllegalArgumentException
  {
    this( aServerURL, aBaseDN );
    bind( aUserDN, aPassword );
  }

  // METHODS

  /**
   * Registers a LDAPv3 extension.
   * 
   * @param aExtensionOID
   *          the extension OID to register;
   * @param aLdapExtension
   *          the class of the extension to register.
   * @throws IllegalArgumentException
   *           in case an extension with the given object ID already is
   *           registered.
   */
  public static final void registerExtension( final String aExtensionOID,
      final Class<? extends LdapExtension> aLdapExtension ) throws IllegalArgumentException
  {
    if ( EXTENSION_REGISTRY.containsKey( aExtensionOID ) )
    {
      throw new IllegalArgumentException( "Attempt to overwrite existing extension: " + aExtensionOID );
    }
    try
    {
      final Constructor<? extends LdapExtension> constructor = aLdapExtension
          .getConstructor( LdapContextProvider.class );
      if ( ( constructor.getModifiers() & Modifier.PUBLIC ) != Modifier.PUBLIC )
      {
        throw new IllegalArgumentException( "Extension " + aExtensionOID + " (" + aLdapExtension.getSimpleName()
            + ") has no public constructor accepting ILdapContextProvider!" );
      }
    }
    catch ( NoSuchMethodException exception )
    {
      throw new IllegalArgumentException( "Extension " + aExtensionOID + " (" + aLdapExtension.getSimpleName()
          + ") has no public constructor accepting ILdapContextProvider!" );
    }

    EXTENSION_REGISTRY.put( aExtensionOID, aLdapExtension );
  }

  /**
   * Parses the given array of controls for a PagedResultsResponseControl and if
   * found returns its cookie.
   * 
   * @param aControls
   *          the controls to parse, may be <code>null</code>.
   * @return the cookie in case a PagedResultsResponseControl was found, or an
   *         empty byte array in case it isn't found.
   * @throws NamingException
   *           in case of LDAP communication errors.
   */
  protected static byte[] parseControls( final Control[] aControls ) throws NamingException
  {
    byte[] cookie = null;

    if ( aControls != null )
    {
      for ( Control control : aControls )
      {
        if ( control instanceof PagedResultsResponseControl )
        {
          cookie = ( ( PagedResultsResponseControl )control ).getCookie();
        }
      }
    }

    return ( cookie == null ) ? new byte[0] : cookie;
  }

  /**
   * Encodes the given password as unicode (UTF-16 LE).
   * <p>
   * NOTE: the given password is prefixed and suffixed with double quotes. This
   * is needed for changing passwords on Microsoft Active Directory servers!
   * </p>
   * 
   * @param aPassword
   *          the password to encode, cannot be <code>null</code>.
   * @return the base64-encoded password, never <code>null</code>.
   * @throws UnsupportedEncodingException
   *           in case we cannot get the password as UTF-16.
   */
  private static byte[] encodePassword( final String aPassword ) throws UnsupportedEncodingException
  {
    return ( '"' + aPassword + '"' ).getBytes( "UTF-16LE" );
  }

  /**
   * Binds to the LDAP server with the given username and credentials.
   * 
   * @param aUserDN
   *          the username to connect to the LDAP server;
   * @param aPassword
   *          the password to connect to the LDAP server.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final void bind( final String aUserDN, final String aPassword ) throws NamingException
  {
    this.environment.put( Context.SECURITY_CREDENTIALS, aPassword );
    this.environment.put( Context.SECURITY_PRINCIPAL, aUserDN );

    final LdapContext ctx = getContext();
    if ( ctx == null )
    {
      throw new NamingException( "No LDAP context returned?!" );
    }
  }

  /**
   * Convenience method to change the password for a user.
   * <p>
   * This method first checks whether the current LDAP-server supports the RFC
   * 3062 extension (ChangePassword; OID = 1.3.6.1.4.1.4203.1.11.1). If
   * <em>not</em> supported, it will check whether it is talking to an Active
   * Directory server (win2k and later), and if so, will try to replace the
   * "unicodePwd" attribute of the user.<br/>
   * If neither talking to an Active Directory server, nor support for RFC 3062
   * is present, this method will do nothing.
   * </p>
   * <p>
   * The old password parameter is optional, which can be used to perform a
   * "replace password" operation on Active Directory servers. The user calling
   * this method should have sufficient rights on the AD to make these changes
   * for other users (or for itself).
   * </p>
   * <p>
   * Note that on Active Directory the default policy is to enforce users to
   * change their password <b>once a day</b>! In case the user tries to change
   * their password more than once, it will get an error like
   * <code>DSID-03190F00, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att
   * 9005a (unicodePwd)</code>. In general when this exception is thrown it
   * means that a policy violation occurred.
   * </p>
   * 
   * @param aUserDN
   *          the DN of the user to change the password for;
   * @param aOldPassword
   *          the old password of the user to change, may be <code>null</code>
   *          in case to replace the user password with the given new password
   * @param aNewPassword
   *          the new password of the user to change, may never be
   *          <code>null</code>.
   * @return <code>true</code> if the operation went successful,
   *         <code>false</code> if the operation could not be performed on the
   *         LDAP server.
   * @throws NamingException
   *           in case of LDAP errors;
   * @throws RuntimeException
   *           in case of unsupported UTF-16 character encoding.
   */
  public boolean changePassword( final String aUserDN, final String aOldPassword, final String aNewPassword )
      throws NamingException
  {
    boolean result = false;

    // First check whether we can change the password using the RFC 3062
    // extension; OpenLDAP v3 supports this extension...
    if ( isExtensionSupportedByServer( IChangePassword.OID ) )
    {
      if ( DEBUG )
      {
        LOG.fine( "Using RFC 3062 password change method..." );
      }

      final IChangePassword changePwExt = getExtension( IChangePassword.OID );
      changePwExt.changePassword( aUserDN, aOldPassword, aNewPassword );

      // If we're here we can safely assume it went correctly...
      result = true;
    }
    else if ( isExtensionSupported( IActiveDirectoryWin2k.OID ) )
    {
      if ( DEBUG )
      {
        LOG.fine( "Using Active Directory password change method..." );
      }

      // Try to use the unicodePwd method as used by ActiveDirectory; see also
      // http://support.microsoft.com/kb/269190 &
      // http://support.microsoft.com/kb/263991
      // See also for Java code examples:
      // http://forums.sun.com/thread.jspa?threadID=592611&tstart=50
      // http://forums.sun.com/thread.jspa?threadID=705973
      final String unicodePwd = "unicodePwd";

      final ModificationItem[] mods;
      if ( ( aOldPassword != null ) && !aOldPassword.isEmpty() )
      {
        // Remove & add the password (= safe method for normal users)...
        if ( DEBUG )
        {
          LOG.fine( "Removing old & adding new user password..." );
        }
        try
        {
          mods = new ModificationItem[] { //
              new ModificationItem( DirContext.REMOVE_ATTRIBUTE, new BasicAttribute( unicodePwd,
                  encodePassword( aOldPassword ) ) ), //
              new ModificationItem( DirContext.ADD_ATTRIBUTE, new BasicAttribute( unicodePwd,
                  encodePassword( aNewPassword ) ) ) //
          };
        }
        catch ( UnsupportedEncodingException exception )
        {
          throw new RuntimeException( "Failed to use UTF-16 encoding?!", exception );
        }
      }
      else
      {
        // Replace password (= advanced method for users with the proper
        // rights)...
        if ( DEBUG )
        {
          LOG.fine( "Replacing user password..." );
        }
        try
        {
          mods = new ModificationItem[] { //
          new ModificationItem( DirContext.REPLACE_ATTRIBUTE, new BasicAttribute( unicodePwd,
              encodePassword( aNewPassword ) ) ) //
          };
        }
        catch ( UnsupportedEncodingException exception )
        {
          throw new RuntimeException( "Failed to use UTF-16 encoding?!", exception );
        }
      }

      // Perform the actual modification query...
      getContext().modifyAttributes( aUserDN, mods );

      // If we're here we can safely assume it went correctly...
      result = true;
    }
    else
    {
      if ( DEBUG )
      {
        LOG.fine( "LDAP password change not supported!" );
      }
    }

    return result;
  }

  /**
   * Closes the connection to the LDAP server.
   * 
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   * @throws IllegalStateException
   *           in case no connection to the LDAP server was made.
   */
  public final void close() throws NamingException, IllegalStateException
  {
    if ( this.context == null )
    {
      throw new IllegalStateException( "Cannot close unbound LDAP connection!" );
    }
    getContext().close();
  }

  /**
   * Retrieves all attributes for a given distinguished name.
   * 
   * @param aDN
   *          the distinguished name to retrieve the attributes for, cannot be
   *          <code>
   *                     null</code>;
   * @param aAttributes
   *          the attribute IDs to retrieve.
   * @return the attributes of the given DN as map of {ID -> value}.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final Map<String, List<Object>> getAttributes( final String aDN, final String... aAttributes )
      throws NamingException
  {
    return convertAttributes( getContext().getAttributes( aDN, aAttributes ) );
  }

  /**
   * Returns the first attribute value of a given attribute value.
   * 
   * @param aAttribute
   *          the attribute to search in.
   * @return the attribute value if found, <code>null</code> if not found.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final Object getAttributeValue( final Attribute aAttribute ) throws NamingException
  {
    if ( ( aAttribute != null ) && ( aAttribute.size() > 0 ) )
    {
      return aAttribute.get( 0 );
    }
    return null;
  }

  /**
   * Finds a given attribute value in a given attribute.
   * 
   * @param aAttributes
   *          the attributes to search in;
   * @param aAttributeID
   *          the ID of the attribute to look for;
   * @return the attribute value if found, <code>null</code> if not found.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public Object getAttributeValue( final Attributes aAttributes, final String aAttributeID ) throws NamingException
  {
    return getAttributeValue( aAttributes.get( aAttributeID ) );
  }

  /**
   * Retrieves directly a value for a given attribute.
   * 
   * @param aDN
   *          the distinguished name to retrieve the attributes for, cannot be
   *          <code>
   *                    null</code>;
   * @param aAttribute
   *          the attribute ID to retrieve the value for.
   * @return the attribute value, can be <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final List<Object> getAttributeValue( final String aDN, final String aAttribute ) throws NamingException
  {
    final Map<String, List<Object>> results = getAttributes( aDN, aAttribute );
    return results.get( aAttribute );
  }

  /**
   * Returns the first attribute value of a given attribute value.
   * 
   * @param aAttribute
   *          the attribute to search in.
   * @return the attribute value if found, <code>null</code> if not found.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final Object[] getAttributeValues( final Attribute aAttribute ) throws NamingException
  {
    if ( ( aAttribute != null ) && ( aAttribute.size() > 0 ) )
    {
      final Object[] result = new Object[aAttribute.size()];
      for ( int i = 0; i < aAttribute.size(); i++ )
      {
        result[i] = aAttribute.get( i );
      }
      return result;
    }
    return null;
  }

  /**
   * Finds a given attribute value in a given attribute.
   * 
   * @param aAttributes
   *          the attributes to search in;
   * @param aAttributeID
   *          the ID of the attribute to look for;
   * @return the attribute value if found, <code>null</code> if not found.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public Object[] getAttributeValues( final Attributes aAttributes, final String aAttributeID ) throws NamingException
  {
    return getAttributeValues( aAttributes.get( aAttributeID ) );
  }

  /**
   * Tries to determine which base DN the server uses.
   * 
   * @return
   * @throws NamingException
   */
  public final String[] getBaseDNs() throws NamingException
  {
    final LdapContext ctx = getContext();
    if ( ctx == null )
    {
      throw new NamingException( "No LDAP context returned?!" );
    }

    Object[] results = null;
    Attributes attr;

    // OpenLDAP
    attr = ctx.getAttributes( getServerURL(), new String[] { ATTR_NAMING_CONTEXT } );
    results = getAttributeValues( attr, ATTR_NAMING_CONTEXT );
    if ( ( results != null ) && ( results.length > 0 ) )
    {
      return convertToStringArray( results );
    }

    // Novell
    attr = ctx.getAttributes( getServerURL(), new String[] { ATTR_DSA_NAME } );
    results = getAttributeValues( attr, ATTR_DSA_NAME );
    if ( ( results != null ) && ( results.length > 0 ) )
    {
      return convertToStringArray( results );
    }

    // Microsoft Active Directory
    attr = ctx.getAttributes( getServerURL(), new String[] { ATTR_DEFAULT_NAMING_CONTEXT } );
    results = getAttributeValues( attr, ATTR_DSA_NAME );
    if ( ( results != null ) && ( results.length > 0 ) )
    {
      return convertToStringArray( results );
    }

    return new String[0];
  }

  /**
   * Returns the current LDAP context creating it when necessary.
   * 
   * @return the LDAP context, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  @Override
  public final LdapContext getContext() throws NamingException
  {
    if ( this.context == null )
    {
      this.context = new InitialLdapContext( ( Hashtable<String, String> )this.environment, null /* connCtls */);
    }
    return this.context;
  }

  /**
   * Creates a new instance of the extension denoted by the given object ID.
   * 
   * @param aExtensionOID
   *          the object ID of the extension to create an instance for, should
   *          be a valid extension.
   * @return an instance of the requested extension, never <code>null</code>.
   * @throws UnsupportedOperationException
   *           in case the extension does not exist, or could not be
   *           instantiated correctly. See internal cause to further
   *           information.
   * @see #isExtensionSupported(String)
   * @see #isExtensionSupportedByServer(String)
   */
  @SuppressWarnings( "unchecked" )
  public final <T extends LdapExtension> T getExtension( final String aExtensionOID )
      throws UnsupportedOperationException
  {
    try
    {
      final Class<T> extClass = ( Class<T> )EXTENSION_REGISTRY.get( aExtensionOID );
      if ( extClass == null )
      {
        throw new UnsupportedOperationException( "Unsupported extension: " + aExtensionOID );
      }

      final Constructor<T> constructor = extClass.getConstructor( LdapContextProvider.class );
      constructor.setAccessible( true );

      return constructor.newInstance( this );
    }
    catch ( NoSuchMethodException exception )
    {
      throw new UnsupportedOperationException( "Extension: " + aExtensionOID, exception );
    }
    catch ( InstantiationException exception )
    {
      throw new UnsupportedOperationException( "Extension: " + aExtensionOID, exception );
    }
    catch ( IllegalAccessException exception )
    {
      throw new UnsupportedOperationException( "Extension: " + aExtensionOID, exception );
    }
    catch ( InvocationTargetException exception )
    {
      throw new UnsupportedOperationException( "Extension: " + aExtensionOID, exception );
    }
  }

  /**
   * Tries to determine what kind of LDAP server we're talking to.
   * <p>
   * This mehod makes a best-effort approach in determining the type of the
   * remote LDAP server. It does this by comparing (parts of) the OIDs returned
   * by the supported extensions of the server.
   * </p>
   * 
   * @return a server type, never <code>null</code>.
   * @throws NamingException
   *           in case of LDAP problems.
   */
  public ServerType getServerType() throws NamingException
  {
    ServerType result = ServerType.UNKNOWN;

    final String openLDAP_oid = "1.3.6.1.4.1.4203";
    final String microsoft_oid = "1.2.840.113556.1";

    final Map<String, List<Object>> supportedExtsAndCaps = convertAttributes( getSupportedLdapServerExtensions() );
    for ( List<Object> ids : supportedExtsAndCaps.values() )
    {
      for ( Object id : ids )
      {
        final String idStr = String.valueOf( id ).trim();

        if ( DEBUG )
        {
          LOG.fine( "Checking OID " + idStr );
        }

        if ( idStr.startsWith( openLDAP_oid ) )
        {
          if ( DEBUG )
          {
            LOG.fine( "Starts with OpenLDAP OID..." );
          }
          return ServerType.OPENLDAP;
        }
        else if ( idStr.startsWith( microsoft_oid ) )
        {
          if ( DEBUG )
          {
            LOG.fine( "Starts with Microsoft OID..." );
          }

          if ( idStr.equals( IActiveDirectoryWin2k3.OID ) )
          {
            if ( DEBUG )
            {
              LOG.fine( "Equals to Microsoft AD Win2k3 OID..." );
            }
            if ( ( result == ServerType.AD_W2k ) || ( result == ServerType.AD_UNKNOWN ) )
            {
              result = ServerType.AD_W2k3;
            }
          }
          else if ( idStr.equals( IActiveDirectoryWin2k.OID ) )
          {
            if ( DEBUG )
            {
              LOG.fine( "Equals to Microsoft AD Win2k OID..." );
            }
            if ( result == ServerType.AD_UNKNOWN )
            {
              result = ServerType.AD_W2k;
            }
          }
          else
          {
            result = ServerType.AD_UNKNOWN;
          }
        }
      }
    }

    return result;
  }

  /**
   * Returns the server URL.
   * 
   * @return the server URL, like "ldap://localhost".
   */
  public final String getServerURL()
  {
    return this.serverURL;
  }

  /**
   * Convenience method to determine whether the server supports a particular
   * LDAPv3 extension.
   * 
   * @return an array of all supported server extensions (their object IDs),
   *         never <code>
   *         null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final String[] getSupportedServerExtensions() throws NamingException
  {
    final Attributes exts = getSupportedLdapServerExtensions();

    final Attribute supportedExts = exts.get( ATTR_SUPPORTED_EXTENSION );
    if ( ( supportedExts != null ) && ( supportedExts.size() > 0 ) )
    {
      final List<String> result = new ArrayList<String>( supportedExts.size() );
      for ( int i = 0; i < supportedExts.size(); i++ )
      {
        final String supportedExt = ( String )supportedExts.get( i );
        if ( isExtensionSupported( supportedExt ) )
        {
          result.add( supportedExt );
        }
      }
      return result.toArray( new String[result.size()] );
    }
    return new String[0];
  }

  /**
   * Convenience method to determine whether the extension denoted by the given
   * object ID is supported by this library.
   * 
   * @param aExtensionOID
   *          the object ID of the extension (something like "1.3.5...").
   * @return <code>true</code> if this library supports the given extension,
   *         <code>false</code> otherwise.
   * @see #isExtensionSupportedByServer(String)
   */
  public final boolean isExtensionSupported( final String aExtensionOID )
  {
    return EXTENSION_REGISTRY.containsKey( aExtensionOID );
  }

  /**
   * Returns whether the given extension is supported by the server.
   * 
   * @param aExtension
   *          the extension to check for server support.
   * @return <code>true</code> if the server supports the requested extension,
   *         <code>false</code> otherwise.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final boolean isExtensionSupportedByServer( final LdapExtension aExtension ) throws NamingException
  {
    return isExtensionSupportedByServer( aExtension.getOID() );
  }

  /**
   * Convenience method to determine whether the server supports a particular
   * LDAPv3 extension.
   * 
   * @param aExtensionOID
   *          the object ID of the extension (something like "1.3.5...").
   * @return <code>true</code> if the server supports the requested extension,
   *         <code>false</code> otherwise.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final boolean isExtensionSupportedByServer( final String aExtensionOID ) throws NamingException
  {
    final Attributes exts = getSupportedLdapServerExtensions();
    return findAttributeValue( exts, ATTR_SUPPORTED_EXTENSION, aExtensionOID ) != null;
  }

  /**
   * Performs a simple LDAP query with subtree scope and returns the results.
   * 
   * @param aQuery
   *          the LDAP query to execute.
   * @return a collection of search results, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   * @see #query(String, int)
   */
  public Collection<SearchResult> query( final String aQuery ) throws NamingException
  {
    return query( aQuery, SearchControls.SUBTREE_SCOPE );
  }

  /**
   * Performs a simple LDAP query and returns the results.
   * 
   * @param aQuery
   *          the LDAP query to execute;
   * @param aSearchScope
   *          the scope of searching, must be one of
   *          {@link SearchControls#OBJECT_SCOPE},
   *          {@link SearchControls#ONELEVEL_SCOPE} or
   *          {@link SearchControls#SUBTREE_SCOPE}.
   * @return a collection of search results, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public Collection<SearchResult> query( final String aQuery, final int aSearchScope ) throws NamingException
  {
    final List<SearchResult> searchResults = new ArrayList<SearchResult>();

    final SearchControls ctrl = new SearchControls();
    ctrl.setSearchScope( aSearchScope );

    final NamingEnumeration<SearchResult> enumeration = getContext().search( "", aQuery, ctrl );
    while ( enumeration.hasMore() )
    {
      searchResults.add( enumeration.next() );
    }

    return searchResults;
  }

  /**
   * Performs a simple LDAP query with subtree scope and returns the results.
   * 
   * @param aDN
   *          the distinguished name to search under (may be <code>null</code>
   *          or empty);
   * @param aFilter
   *          the LDAP query to execute.
   * @return a collection of search results, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   * @see #query(String, int)
   */
  public Collection<SearchResult> query( final String aDN, final String aFilter ) throws NamingException
  {
    return query( aDN, aFilter, SearchControls.SUBTREE_SCOPE );
  }

  /**
   * Performs a simple LDAP query and returns the results.
   * 
   * @param aDN
   *          DOCUMENT ME!
   * @param aFilter
   *          the LDAP query to execute;
   * @param aSearchScope
   *          the scope of searching, must be one of
   *          {@link SearchControls#OBJECT_SCOPE},
   *          {@link SearchControls#ONELEVEL_SCOPE} or
   *          {@link SearchControls#SUBTREE_SCOPE}.
   * @return a collection of search results, never <code>null</code>.
   * @throws NamingException
   *           in case the connection to the LDAP server failed;
   * @throws RuntimeException
   *           in case the connection control settings failed.
   */
  public Collection<SearchResult> query( final String aDN, final String aFilter, final int aSearchScope )
      throws NamingException
  {
    final List<SearchResult> searchResults = new ArrayList<SearchResult>();

    final int pageSize = 100;
    final String dn = ( aDN == null ) ? "" : aDN;

    final SearchControls ctrl = new SearchControls();
    ctrl.setSearchScope( aSearchScope );

    try
    {
      final LdapContext ctx = getContext();
      ctx.setRequestControls( new Control[] { new PagedResultsControl( pageSize, Control.CRITICAL ) } );

      byte[] cookie = null;

      do
      {
        final NamingEnumeration<SearchResult> results = ctx.search( dn, aFilter, ctrl );
        while ( ( results != null ) && results.hasMoreElements() )
        {
          final SearchResult sr = results.next();
          searchResults.add( sr );
        }

        cookie = parseControls( ctx.getResponseControls() );

        // pass the cookie back to the server for the next page
        ctx.setRequestControls( new Control[] { new PagedResultsControl( pageSize, cookie, Control.CRITICAL ) } );
      }
      while ( ( cookie != null ) && ( cookie.length != 0 ) );
    }
    catch ( IOException exception )
    {
      throw new RuntimeException( "Unexpected I/O exception!", exception );
    }

    return searchResults;
  }

  /**
   * Reconnects to the LDAP server using the current credentials.
   * <p>
   * Use this method for example after starting a TLS-connection with the LDAP
   * server.
   * </p>
   * 
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  public final void reconnect() throws NamingException
  {
    getContext().reconnect( null /* connCtls */);
  }

  /**
   * Sets the authentication mechanisms to use for binding with the LDAP server.
   * 
   * @param aAuthMechanisms
   *          the authentication mechanisms to use, can be <code>null</code> or
   *          empty to use no authentication.
   */
  public final void setAuthenticationMechanisms( final AuthMechanisms... aAuthMechanisms )
  {
    String authMechs;
    if ( aAuthMechanisms != null )
    {
      StringBuilder sb = new StringBuilder();
      for ( AuthMechanisms authMech : aAuthMechanisms )
      {
        if ( sb.length() > 0 )
        {
          sb.append( " " );
        }
        sb.append( authMech.getName() );
      }

      authMechs = sb.toString();
    }
    else
    {
      authMechs = AuthMechanisms.NONE.getName();
    }

    this.environment.put( Context.SECURITY_AUTHENTICATION, authMechs );
  }

  /**
   * Retrieves all attributes for a given distinguished name.
   * 
   * @param aAttributes
   *          the attributes to retrieve the values for.
   * @return the attributes of the given DN as map of {ID -> value}.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  protected final Map<String, List<Object>> convertAttributes( final Attributes aAttributes ) throws NamingException
  {
    final Map<String, List<Object>> results = new HashMap<String, List<Object>>();
    if ( ( aAttributes != null ) && ( aAttributes.size() > 0 ) )
    {
      final NamingEnumeration<? extends Attribute> attributes = aAttributes.getAll();
      while ( attributes.hasMoreElements() )
      {
        final Attribute attribute = attributes.next();

        if ( DEBUG )
        {
          LOG.fine( "\t" + attribute );
        }

        List<Object> values = results.get( attribute.getID() );
        if ( values == null )
        {
          values = new ArrayList<Object>();
          results.put( attribute.getID(), values );
        }

        for ( int i = 0; i < attribute.size(); i++ )
        {
          values.add( attribute.get( i ) );
        }
      }
    }

    return Collections.unmodifiableMap( results );
  }

  /**
   * Returns the supported LDAPv3 extensions of the server.
   * 
   * @return the attributes containing the server extensions.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  protected final Attributes getSupportedLdapServerExtensions() throws NamingException
  {
    return getContext().getAttributes( getServerURL(), new String[] { ATTR_SUPPORTED_EXTENSION } );
  }

  /**
   * Converts a given object-array into a string-array.
   * 
   * @param aInput
   *          the input array to convert, can be <code>null</code> or empty.
   * @return the string array, never <code>null</code>.
   */
  private String[] convertToStringArray( final Object[] aInput )
  {
    if ( ( aInput == null ) || ( aInput.length == 0 ) )
    {
      return new String[0];
    }
    final String[] result = new String[aInput.length];
    for ( int i = 0; i < aInput.length; i++ )
    {
      result[i] = ( aInput[i] == null ) ? null : String.valueOf( aInput[i] );
    }
    return result;
  }

  /**
   * Finds a given attribute value in a given attribute.
   * 
   * @param aAttribute
   *          the attribute to search in;
   * @param aAttributeValue
   *          the value to look for.
   * @return the attribute value if found, <code>null</code> if not found.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  private Object findAttributeValue( final Attribute aAttribute, final Object aAttributeValue ) throws NamingException
  {
    if ( aAttribute != null )
    {
      for ( int i = 0; i < aAttribute.size(); i++ )
      {
        final Object supportedExt = aAttribute.get( i );
        if ( aAttributeValue.equals( supportedExt ) )
        {
          return supportedExt;
        }
      }
    }
    return null;
  }

  /**
   * Finds a given attribute value in a given attribute.
   * 
   * @param aAttributes
   *          the attributes to search in;
   * @param aAttributeID
   *          the ID of the attribute to look for;
   * @param aAttributeValue
   *          the value to look for.
   * @return the attribute value if found, <code>null</code> if not found.
   * @throws NamingException
   *           in case the connection to the LDAP server failed.
   */
  private Object findAttributeValue( final Attributes aAttributes, final String aAttributeID,
      final Object aAttributeValue ) throws NamingException
  {
    return findAttributeValue( aAttributes.get( aAttributeID ), aAttributeValue );
  }
}
