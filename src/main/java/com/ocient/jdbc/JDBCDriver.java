package com.ocient.jdbc;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JDBCDriver implements Driver
{

	private static String version = "7.0.1";
	private String clientVersion = getClass().getPackage().getImplementationVersion();
	private static final Logger LOGGER = Logger.getLogger("com.ocient.jdbc");
	private static String logFileName;
	private static FileHandler logHandler;
	private final Object logMonitor = new Object();

	static
	{
		try
		{
			DriverManager.registerDriver(new JDBCDriver());
		}
		catch (final SQLException e)
		{
		}
	}

	private static HashMap<XGConnection,XGConnection> seenConnections = new HashMap<XGConnection,XGConnection>();

	@Override
	public boolean acceptsURL(final String arg0) throws SQLException
	{
		if (arg0.length() < 14)
		{
			return false;
		}

		final String protocol = arg0.substring(0, 14);
		if (!protocol.equals("jdbc:ocient://"))
		{
			return false;
		}

		return true;
	}

	private void configLogger(final Properties props)
	{
		synchronized (logMonitor)
		{
			final String loglevel = props.getProperty("loglevel");
			final String logfile = props.getProperty("logfile");
			if (loglevel == null || logfile == null)
			{
				LOGGER.setLevel(Level.OFF);
				return;
			}

			if (loglevel != null)
			{
				if (loglevel.equalsIgnoreCase("OFF"))
				{
					LOGGER.setLevel(Level.OFF);
					return;
				}
				else if (loglevel.equalsIgnoreCase("DEBUG"))
				{
					LOGGER.setLevel(Level.ALL);
				}
				else if (loglevel.equalsIgnoreCase("ERROR"))
				{
					LOGGER.setLevel(Level.WARNING);
				}
			}

			/* If logfile hasn't changed, return */
			if (logfile.equals(logFileName))
			{
				return;
			}

			/* Clean up the old handler */
			LOGGER.setUseParentHandlers(false);
			LOGGER.log(Level.INFO, "Resetting logger");
			final Handler[] handlers = LOGGER.getHandlers();
			for (final Handler handler : handlers)
			{
				LOGGER.removeHandler(handler);
			}

			try
			{
				logHandler = new FileHandler(logfile, true);
				logHandler.setFormatter(new ThreadFormatter());
				logFileName = logfile;
				LOGGER.addHandler(logHandler);
				LOGGER.log(Level.INFO, String.format("Enabling logger with jdbc jar version: %s", clientVersion));
			}
			catch (final IOException | IllegalArgumentException e)
			{
				// An illegal file argument was entered most likely.
				LOGGER.setLevel(Level.OFF);
				return;
			}
		}
	}

	@Override
	public Connection connect(final String arg0, final Properties arg1) throws SQLException
	{
		try
		{
			final String protocol = arg0.substring(0, 14);
			if (!protocol.equals("jdbc:ocient://"))
			{
				return null;
			}

			final int dbDelim = arg0.indexOf("/", "jdbc:ocient://".length());
			if (dbDelim < 0)
			{
				throw SQLStates.MALFORMED_URL.clone();
			}

			final String hosts = arg0.substring("jdbc:ocient://".length(), dbDelim);
			final String[] hostList = hosts.split(",");
			String db = "";

			// Check for properties
			int propertyDelim = arg0.indexOf(";");
			if (propertyDelim > 0)
			{
				db = arg0.substring(dbDelim + 1, propertyDelim);
			}
			else
			{
				db = arg0.substring(dbDelim + 1);
			}

			while (propertyDelim > 0)
			{
				// Get the property name
				final int equalPos = arg0.indexOf("=", propertyDelim + 1);
				if (equalPos < 0)
				{
					throw SQLStates.MALFORMED_URL.clone();
				}

				final String key = arg0.substring(propertyDelim + 1, equalPos);

				// Find the end of this property
				int propertyEnd = arg0.indexOf(";", equalPos + 1);
				if (propertyEnd < 0)
				{
					propertyEnd = arg0.length();
				}

				final String value = arg0.substring(propertyDelim + 1 + key.length() + 1, propertyEnd);
				arg1.setProperty(key, value);

				if (propertyEnd == arg0.length())
				{
					propertyDelim = -1;
				}
				else
				{
					propertyDelim = propertyEnd;
				}
			}

			if (arg1.getProperty("force") == null)
			{
				arg1.setProperty("force", "false");
			}

			configLogger(arg1);
			Exception lastException = null;
			for (final String host : hostList)
			{
				final String[] hostnameAndPort = host.split(":");
				if (hostnameAndPort.length != 2)
				{
					LOGGER.log(Level.SEVERE, "Host list in URL is malformed");
					throw SQLStates.MALFORMED_URL.clone();
				}

				int portNum = 0;
				try
				{
					portNum = Integer.parseInt(hostnameAndPort[1]);
				}
				catch (final Exception e)
				{
					LOGGER.log(Level.SEVERE, "Port number in URL was not an integer");
					throw SQLStates.MALFORMED_URL.clone();
				}

				try
				{
					final Connection conn = createConnection(hostnameAndPort[0], portNum, db, arg1);
					return conn;
				}
				catch (final Exception e)
				{
					lastException = e;
				}
			}

			if (lastException != null)
			{
				throw lastException;
			}
		}catch (RuntimeException e) 
		{
			throw e;
		}
		catch (final Exception e)
		{
			if (e instanceof SQLException)
			{
				throw (SQLException) e;
			}

			throw SQLStates.newGenericException(e);
		}

		// if we get it here, it is a malformed URL
		throw SQLStates.MALFORMED_URL.clone();
	}

	private Connection createConnection(final String hostname, final int portNum, final String database, final Properties properties) throws SQLException
	{
		final Socket sock = null;
		final String user = properties.getProperty("user");
		final String pwd = properties.getProperty("password");
		final String force = properties.getProperty("force");
		final String tlsStr = properties.getProperty("tls", "UNVERIFIED").toUpperCase();
		final XGConnection.Tls tls = XGConnection.Tls.valueOf(tlsStr);
		XGConnection conn = null;

		try
		{
			final InetAddress[] addrs = InetAddress.getAllByName(hostname);
			LOGGER.log(Level.INFO, String.format("Received %d IP addresses for hostname %s", addrs.length, hostname));
			boolean connected = false;
			Throwable lastError = null;
			for (final InetAddress addr : addrs)
			{
				try
				{
					final String url = "jdbc:ocient://" + hostname + ":" + Integer.toString(portNum) + "/" + database;
					// If we've already seen this connection, don't do the connect
					conn = new XGConnection(user, pwd, addr.getHostAddress(), portNum, url, database, version, clientVersion, force, tls, properties);
					boolean doConnect = false;
					synchronized (seenConnections)
					{
						if (!seenConnections.containsKey(conn))
						{
							LOGGER.log(Level.INFO, "Driver generated a new connection");
							doConnect = true;
						} else {
							LOGGER.log(Level.INFO, "Driver retrieved a cached connection");
							conn.defaultSchema = seenConnections.get(conn).setSchema;
							conn.setSchemaLocal(seenConnections.get(conn).getSchemaLocal());
							conn.setServerVersion(seenConnections.get(conn).getServerVersion());
						}
					}

					if (doConnect)
					{
						LOGGER.log(Level.INFO, "About to attempt connection");
						conn.connect();
						if (properties.containsKey("defaultSchema") && properties.get("defaultSchema") != null)
						{
							String userDefaultSchema = properties.getProperty("defaultSchema");
							conn.setSchema(userDefaultSchema);
							conn.defaultSchema = userDefaultSchema;
						}
						else
						{
							conn.setSchema = conn.getSchema();
							conn.defaultSchema = conn.setSchema;
						}
						LOGGER.log(Level.INFO, "Successfully connected");
						connected = true;
						synchronized (seenConnections)
						{
							seenConnections.put(conn, conn);
						}
					}
					break;
				}
				catch (final Throwable e)
				{
					conn = null;
					lastError = e;
					LOGGER.log(Level.WARNING, String.format("Failed connecting to %s with exception %s with message %s", addr.toString(), e.toString(), e.getMessage()));
				}
			}
			if (!connected && lastError != null)
			{
				// Represents failure to connect. Socket will be cleaned up in catch block.
				throw lastError;
			}
		}
		catch (final Throwable e)
		{
			final SQLException g = SQLStates.FAILED_CONNECTION.clone();
			final Exception connInfo = new Exception("Connection failed connecting to " + hostname + ":" + portNum + " - " + e.getMessage());
			g.initCause(connInfo);
			connInfo.initCause(e);
			throw g;
		}
		
		return conn;
	}

	public String getDriverVersion()
	{
		return version;
	}

	@Override
	public int getMajorVersion()
	{
		return Integer.parseInt(version.substring(0, version.indexOf(".")));
	}

	@Override
	public int getMinorVersion()
	{
		final int i = version.indexOf(".") + 1;
		return Integer.parseInt(version.substring(i, version.indexOf(".", i)));
	}

	@Override
	public Logger getParentLogger()
	{
		return LOGGER;
	}

	@Override
	public DriverPropertyInfo[] getPropertyInfo(final String arg0, final Properties arg1) throws SQLException
	{
		final DriverPropertyInfo[] retval = new DriverPropertyInfo[15];
		final DriverPropertyInfo user = new DriverPropertyInfo("user", null);
		user.description = "The userid to use for the connection";
		user.required = true;
		retval[0] = user;

		final DriverPropertyInfo pwd = new DriverPropertyInfo("password", null);
		pwd.description = "The password to use for the connection";
		pwd.required = true;
		retval[1] = pwd;

		final DriverPropertyInfo loglevel = new DriverPropertyInfo("loglevel", null);
		loglevel.description = "Logging Level";
		loglevel.required = false;
		loglevel.choices = new String[3];
		loglevel.choices[0] = "OFF";
		loglevel.choices[1] = "ERROR";
		loglevel.choices[2] = "DEBUG";

		retval[2] = loglevel;

		final DriverPropertyInfo logfile = new DriverPropertyInfo("logfile", null);
		logfile.description = "Log file";
		logfile.required = false;
		retval[3] = logfile;

		final DriverPropertyInfo maxRows = new DriverPropertyInfo("maxRows", null);
		maxRows.description = "Maximum allowed result set size in number of rows";
		maxRows.required = false;
		retval[4] = maxRows;

		final DriverPropertyInfo maxTempDisk = new DriverPropertyInfo("maxTempDisk", null);
		maxTempDisk.description = "Maximum allowed temp disk usage as a percentage (0 - 100)";
		maxTempDisk.required = false;
		retval[5] = maxTempDisk;

		final DriverPropertyInfo maxTime = new DriverPropertyInfo("maxTime", null);
		maxTime.description = "Maximum allowed runtime of a query in seconds before it is cancelled on the server";
		maxTime.required = false;
		retval[6] = maxTime;

		final DriverPropertyInfo networkTimeout = new DriverPropertyInfo("networkTimeout", "10000");
		networkTimeout.description = "Network connection timeout in milliseconds";
		networkTimeout.required = false;
		retval[7] = networkTimeout;

		final DriverPropertyInfo priority = new DriverPropertyInfo("priority", "1.0");
		priority.description = "Default query priority";
		priority.required = false;
		retval[8] = priority;

		final DriverPropertyInfo longQueryThreshold = new DriverPropertyInfo("longQueryThreshold", "0");
		longQueryThreshold.description = "Estimated query runtime in milliseconds before deeper query optimization runs. 0 = use database server default. -1 = never run deeper optimization";
		longQueryThreshold.required = false;
		retval[9] = longQueryThreshold;

		final DriverPropertyInfo defaultSchema = new DriverPropertyInfo("defaultSchema", null);
		defaultSchema.description = "Default schema";
		defaultSchema.required = false;
		retval[10] = defaultSchema;

		final DriverPropertyInfo concurrency = new DriverPropertyInfo("concurrency", null);
		concurrency.description = "Number of concurrent queries allowed before queueing";
		concurrency.required = false;
		retval[11] = concurrency;

		final DriverPropertyInfo timeoutMillis = new DriverPropertyInfo("timeoutMillis", "0");
		timeoutMillis.description = "Number of milliseconds before cancellable operations are timed out and killed by the driver. 0 = no timeout";
		timeoutMillis.required = false;
		retval[12] = timeoutMillis;

		final DriverPropertyInfo tls = new DriverPropertyInfo("tls", null);
		tls.description = "TLS encryption";
		tls.required = false;
		tls.choices = new String[3];
		tls.choices[0] = "OFF";
		tls.choices[1] = "UNVERIFIED";
		tls.choices[2] = "ON";
		retval[13] = tls;

		final DriverPropertyInfo handshake = new DriverPropertyInfo("handshake", null);
		handshake.description = "Handshake Encryption Type";
		handshake.required = false;
		handshake.choices = new String[2];
		tls.choices[0] = "GCM";
		tls.choices[1] = "CBC";
		retval[14] = handshake;
		
		return retval;
	}

	@Override
	public boolean jdbcCompliant()
	{
		return false;
	}
}
