package com.ocient.cli;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import com.ocient.jdbc.JDBCDriver;
import com.ocient.jdbc.XGConnection;
import com.ocient.jdbc.XGDatabaseMetaData;
import com.ocient.jdbc.XGStatement;
import com.ocient.jdbc.proto.ClientWireProtocol.SysQueriesRow;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.XMLConstants;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ocient.jdbc.StPolygon;
import com.ocient.jdbc.StPoint;
import com.ocient.jdbc.StLinestring;

public class CLI
{
	private static Connection conn;
	private static boolean timing = false;
	private static boolean trace = false;
	private static boolean performance = false;
	private static String outputCSVFile = "";
	private static String outputKMLFile = "";
	private static String db;
	private static String user;
	private static String pwd;
	private static Collection<File> sources = new HashSet<>();

	private static char quote = '\0';
	private static boolean comment = false;

	private static Pattern connectToSyntax = Pattern.compile(
		"connect\\s+to\\s+(?<preurl>jdbc:ocient://?)(?<hosts>.+?)(?<posturl>/.+?)(?<up>\\s+user\\s+(" + userTk() + ")\\s+using\\s+(?<q>\"?)(?<pwd>.+?)\\k<q>)?(?<force>\\s+force)?",
		Pattern.CASE_INSENSITIVE);

	private static Pattern listTablesSyntax = Pattern.compile("list\\s+tables(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);

	private static Pattern listSystemTablesSyntax = Pattern.compile("list\\s+system\\s+tables(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);

	private static Pattern listViewsSyntax = Pattern.compile("list\\s+views(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);

	private static Pattern describeTableSyntax = Pattern.compile("describe(\\s+table\\s+)?((" + tk("schema") + ")\\.)?(" + tk("table") + ")(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);

	private static Pattern describeViewSyntax = Pattern.compile("describe(\\s+view\\s+)?((" + tk("schema") + ")\\.)?(" + tk("view") + ")(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);

	private static Pattern listIndexesSyntax = Pattern.compile("list\\s+ind(ic|ex)es\\s+((" + tk("schema") + ")\\.)?(" + tk("table") + ")(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);

	private static final char[] hexArray = "0123456789abcdef".toCharArray();

	private static Statement stmt;

	private static String bytesToHex(final byte[] bytes)
	{
		final char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++)
		{
			final int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	private static void cancelQuery(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			printWarnings(stmt);
			end = System.currentTimeMillis();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void connectTo(final String cmd)
	{
		if (isConnected())
		{
			try
			{
				if (stmt != null && !stmt.isClosed())
				{
					stmt.close();
				}
				conn.close();
			}
			catch (final Exception e)
			{
				System.out.println("Error: " + e.getMessage());
				return;
			}
		}

		try
		{
			final Matcher m = connectToSyntax.matcher(cmd);
			if (!m.matches())
			{
				System.out.println("Syntax: connect to <jdbc url>( user <username> using <password>)?( force)?");
				return;
			}
			final String hosts = m.group("hosts");
			final String preurl = m.group("preurl");
			final String posturl = m.group("posturl");

			final Exception lastException = null;

			final String url = preurl + hosts + posturl;
			try
			{
				if (m.group("up") == null)
				{
					doConnect(user, pwd, m.group("force") != null, url);
				}
				else
				{
					doConnect(getTk(m, "user", null), m.group("pwd"), m.group("force") != null, url);
				}
				// No exception thrown means connection was successful, and connectTo may return
				stmt = conn.createStatement();
			}
			catch (final SQLException e)
			{
				System.out.println("Failed to connect to " + hosts + "(" + e.getCause().getMessage() + ")");
				throw e;
			}
			catch (final Exception e)
			{
				System.out.println("Failed to connect to " + hosts);
				throw e;
			}

		}
		catch (final Exception e)
		{
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void describeTable(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			final Matcher m = describeTableSyntax.matcher(cmd);
			if (!m.matches())
			{
				System.out.println("Syntax: describe (<schema>.)?<table>");
				return;
			}

			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();

			if (outputCSVFile.isEmpty())
			{
				if (m.group("verbose") != null)
				{
					printResultSet(rs, meta);
				}
				else
				{
					final StringBuilder line = new StringBuilder(1024);
					while (rs.next())
					{
						line.append(rs.getString("COLUMN_NAME"));
						line.append(" (");
						final String type = rs.getString("TYPE_NAME").replace("SHORT", "SMALLINT").replace("LONG", "BIGINT");

						line.append(type);
						// TODO: figure out precision stuff
						if (rs.getString("TYPE_NAME").equals("DECIMAL"))
						{
							line.append("(");
							line.append(rs.getString("DECIMAL_PRECISION"));
							line.append(",");
							line.append(rs.getString("DECIMAL_SCALE"));
							line.append(")");
						}
						else if (rs.getString("TYPE_NAME").equals("VARCHAR") || rs.getString("TYPE_NAME").equals("BINARY") || rs.getString("TYPE_NAME").equals("HASH"))
						{
							line.append("(");
							line.append(rs.getString("COLUMN_SIZE"));
							line.append(")");
						}

						line.append(")");
						if (rs.getInt("NULLABLE") != 0)
						{
							line.append(" nullable");
						}
						line.append("\n");
					}
					if (line.length() != 0)
					{
						System.out.print(line);
					}
				}
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(rs);
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}

			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void describeView(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			final Matcher m = describeViewSyntax.matcher(cmd);
			if (!m.matches())
			{
				System.out.println("Syntax: describe view (<schema>.)?<view>");
				return;
			}

			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				if (m.group("verbose") != null)
				{
					printResultSet(rs, meta);
				}
				else
				{
					final StringBuilder line = new StringBuilder(1024);

					while (rs.next())
					{
						line.append(rs.getString("VIEW_QUERY_TEXT"));
					}

					if (line.length() != 0)
					{
						line.setLength(line.length());
						System.out.println(line);
					}
				}
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(rs);
			end = System.currentTimeMillis();
			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}

			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void doConnect(final String user, final String pwd, final boolean force, final String url) throws Exception
	{
		final Properties prop = new Properties();
		prop.setProperty("user", user);
		prop.setProperty("password", pwd);
		prop.setProperty("force", force ? "true" : "false");
		conn = DriverManager.getConnection(url, prop);
		CLI.db = ((XGConnection) conn).getDB();

		System.out.println("Connected to " + ((XGConnection) conn).getURL());
	}

	private static boolean endsWithIgnoreCase(final String in, final String cmp)
	{
		return in.toUpperCase().endsWith(cmp.toUpperCase());
	}

	private static void executePlan(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();

			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(stmt);
			printWarnings(rs);
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void explain(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();

			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void explainPipeline(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(stmt);
			end = System.currentTimeMillis();
			rs.close();
			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void explainPlan(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}

			rs.close();

			printWarnings(stmt);
			end = System.currentTimeMillis();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void exportTable(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(stmt);
			end = System.currentTimeMillis();
			rs.close();
			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void exportTranslation(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(stmt);
			end = System.currentTimeMillis();
			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void exportView(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(stmt);
			end = System.currentTimeMillis();
			rs.close();
			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void checkData(final String cmd) {
		long start = 0;
		long end = 0;
		if (!isConnected()) {
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try {
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty()) {
				printResultSet(rs, meta);
			} else {
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(stmt);
			end = System.currentTimeMillis();
			rs.close();
			printTime(start, end);
		} catch (final Exception e) {
			try {
				if(rs != null)
				{
					rs.close();
				}
			} catch (final Exception f) {
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void forceExternal(final String cmd)
	{
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		else if (!cmd.toLowerCase().endsWith("on") && !cmd.toLowerCase().endsWith("off"))
		{
			System.out.println("force external command requires argument \"on\" or \"off\"");
			return;
		}

		final boolean force = cmd.toLowerCase().endsWith("on");
		try
		{
			((XGConnection) stmt.getConnection()).forceExternal(force);
		}
		catch (final Exception e)
		{
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void getSchema(final String cmd)
	{
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;
		try
		{
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			rs.close();
		}
		catch (final Exception e)
		{
			e.printStackTrace();
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	// Get a token from its generated regex according to SQL case-sensitivity rules
	// (sensitive iff quoted).
	// Do not call on a matcher that has not yet called matches().
	private static String getTk(final Matcher m, final String name, final String def)
	{
		if (m.group(name) == null)
		{
			return def;
		}
		if (m.group("q0" + name).length() == 0)
		{
			return m.group(name).toLowerCase();
		}
		return m.group(name);
	}

	private static boolean isConnected()
	{
		if (conn != null)
		{
			return ((XGConnection) conn).connected();
		}
		return false;
	}

	private static void killQuery(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			printWarnings(stmt);
			end = System.currentTimeMillis();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void listAllCompletedQueries(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}

			printWarnings(rs);
			end = System.currentTimeMillis();

			printTime(start, end);
			rs.close();
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void listAllQueries(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		ResultSet rs = null;
		try
		{
			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();
			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}

			printWarnings(rs);
			end = System.currentTimeMillis();

			printTime(start, end);
			rs.close();
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void listIndexes(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			final Matcher m = listIndexesSyntax.matcher(cmd);
			if (!m.matches())
			{
				System.out.println("Syntax: list indexes (<schema>.)?<table>");
				return;
			}

			start = System.currentTimeMillis();
			// final DatabaseMetaData dbmd = conn.getMetaData();
			// this behavior is slightly different from the jdbc call itself--
			// the call allows schema to be null, in which case it doesn't filter on it.
			// we assume the current schema for convenience & to limit results to one table
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();

			if (outputCSVFile.isEmpty())
			{
				if (m.group("verbose") != null)
				{
					printResultSet(rs, meta);
				}
				else
				{
					final StringBuilder line = new StringBuilder(1024);
					final ArrayList<String> indexNames = new ArrayList<>();
					String currIndex = "";
					while (rs.next())
					{
						final String nextIndex = rs.getString("INDEX_NAME");
						if (!nextIndex.equals(currIndex))
						{
							currIndex = nextIndex;
							if (line.length() > 0)
							{
								line.setLength(line.length() - 2);
								line.append(")");
								indexNames.add(line.toString());
								line.setLength(0);
							}
							line.append(currIndex);
							line.append(" (");
						}
						line.append(rs.getString("COLUMN_NAME"));
						line.append(", ");
					}
					if (line.length() != 0)
					{
						line.setLength(line.length() - 2);
						line.append(")");
						indexNames.add(line.toString());
					}
					if (!indexNames.isEmpty())
					{
						// TODO: This is a lexicographic sort. Clients ordering their tables by number
						// will not see the ordering they expect.
						Collections.sort(indexNames);
						for (final String indexName : indexNames)
						{
							System.out.println(indexName);
						}
					}
				}
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}

			printWarnings(rs);
			end = System.currentTimeMillis();
			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}

			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void listPlan()
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		try
		{
			start = System.currentTimeMillis();
			final ArrayList<String> planNames = ((XGStatement) stmt).listPlan();
			if (planNames.size() > 0)
			{
				System.out.println("    Plan Name    ");
				System.out.println("-----------------");
				for (final String planName : planNames)
				{
					System.out.println(planName);
				}
			}

			printWarnings(stmt);
			end = System.currentTimeMillis();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void listPrivileges(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{

			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();

			if (outputCSVFile.isEmpty())
			{
				printResultSet(rs, meta);
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(rs);
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}

			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void listTables(final String cmd, final boolean isSystemTables)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			final Matcher m = isSystemTables ? listSystemTablesSyntax.matcher(cmd) : listTablesSyntax.matcher(cmd);
			if (!m.matches())
			{
				// this line will never be reached,
				// but we have to call matches() anyway
				return;
			}

			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();

			if (outputCSVFile.isEmpty())
			{
				if (m.group("verbose") != null)
				{
					printResultSet(rs, meta);
				}
				else
				{
					final ArrayList<String> tableNames = new ArrayList<>();
					while (rs.next())
					{
						tableNames.add(rs.getString("TABLE_SCHEM") + "." + rs.getString("TABLE_NAME"));
					}
					if (!tableNames.isEmpty())
					{
						// TODO: This is a lexicographic sort. Clients ordering their tables by number
						// will not see the ordering they expect.
						Collections.sort(tableNames);
						for (final String tableName : tableNames)
						{
							System.out.println(tableName);
						}
					}
				}
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(rs);
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}

			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void listViews(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			final DatabaseMetaData md = conn.getMetaData();
			final XGDatabaseMetaData dbmd = (XGDatabaseMetaData) md;
			final Matcher m = listViewsSyntax.matcher(cmd);
			if (!m.matches())
			{
				// this line will never be reached,
				// but we have to call matches() anyway
				return;
			}

			start = System.currentTimeMillis();
			stmt.execute(cmd);
			rs = stmt.getResultSet();
			final ResultSetMetaData meta = rs.getMetaData();

			if (outputCSVFile.isEmpty())
			{
				if (m.group("verbose") != null)
				{
					printResultSet(rs, meta);
				}
				else
				{
					final ArrayList<String> viewNames = new ArrayList<>();
					while (rs.next())
					{
						viewNames.add(rs.getString("VIEW_SCHEM") + "." + rs.getString("VIEW_NAME"));
					}
					if (!viewNames.isEmpty())
					{
						// TODO: This is a lexicographic sort. Clients ordering their tables by number
						// will not see the ordering they expect.
						Collections.sort(viewNames);
						for (final String viewName : viewNames)
						{
							System.out.println(viewName);
						}
					}
				}
			}
			else
			{
				outputResultSet(rs, meta);
				outputCSVFile = "";
			}
			printWarnings(rs);
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}

			System.out.println("Error: " + e.getMessage());
		}
	}

	public static void main(final String[] args)
	{
		Terminal terminal;
		LineReader reader;
		try
		{
			Class.forName("com.ocient.jdbc.JDBCDriver");
		}
		catch (final Exception e)
		{
			System.out.println("Unable to load JDBC driver!");
			System.exit(1);
		}

		boolean echo = false;
		final Console cons = System.console();
		try
		{
			if (cons == null)
			{
				echo = true;
			}
			final DefaultParser parser = new DefaultParser();
			// Prevents \ from disappearing and \\ from converting to \.
			parser.setEscapeChars(null);
			terminal = TerminalBuilder.builder().system(true).build();
			reader = LineReaderBuilder.builder().parser(parser).terminal(terminal).build();
		}
		catch (final IOException e)
		{
			System.out.println("Error setting up console");
			return;
		}

		// Usernames and passwords can contain any characters if appropriately quoted
		// (usernames use SQL case-sensitivity).
		// Quote for shell. Subsequent arguments are dropped.

		if (args.length == 0)
		{
			user = reader.readLine("Username: ");
		}
		else
		{
			user = args[0];
		}
		if (args.length < 2)
		{
			if (echo)
			{
				System.out.println();
			}
			pwd = reader.readLine("Password: ", '\0');
		}
		else
		{
			pwd = args[1];
		}
		System.out.println();

		boolean quit = false;
		String cmd = "";
		boolean scrubCmd = true;

		try
		{
			while (true)
			{
				// jline has ways to handle this, but they're underdocumented and overbuilt to
				// the point of obscenity
				if (!quit)
				{
					cmd = reader.readLine("Ocient> ") + " ";
				}
				if (startsWithIgnoreCase(cmd, "PLAN EXECUTE INLINE"))
				{
					// the scrubing logic looks for comments blocks in the SQL statement. Now, plans
					// have a
					// lots of
					// double/single quotes, and those can be closed or not. scrubing a plans is not
					// a good
					// idea. It can cause the CLI to misinterpret quotes.
					scrubCmd = false;
				}
				else
				{
					cmd = scrubCommand(cmd);
				}
				while (true)
				{
					if (quit || cmd.trim().equalsIgnoreCase("QUIT"))
					{
						try
						{
							if (conn != null && !conn.isClosed())
							{
								final Driver driver = DriverManager.getDriver(((XGConnection) conn).getURL());
								final JDBCDriver jdbcDriver = (JDBCDriver) driver;
								conn.close();
								jdbcDriver.cancelCacheThreads();
							}
						}
						catch (final Exception e)
						{
						}
						if (echo)
						{
							System.out.println();
						}
						return;
					}
					if (echo)
					{
						System.out.println();
					}

					if (!comment && quote == '\0' && cmd.trim().endsWith(";"))
					{
						// System.out.println("Finished scrubbing command: '" + cmd + "'");
						cmd = cmd.trim();
						cmd = cmd.substring(0, cmd.length() - 1).trim();
						if (trace && !endsWithIgnoreCase(cmd, " trace"))
						{
							cmd = cmd + " trace";
						}
						// System.out.println("Finished trimming scrubbed: '" + cmd + "'");
						break;
					}
					else
					{
						// System.out.println("Current command text: '" + cmd + "'");
						final String line = reader.readLine("(cont)> ") + " ";
						if (scrubCmd)
						{
							cmd += scrubCommand(line);
						}
						else
						{
							cmd += line;
						}
					}
				}
				if (startsWithIgnoreCase(cmd, "CLI SET MAX HISTORY"))
				{
					final int maxLines = Integer.parseInt(cmd.substring("CLI SET MAX HISTORY ".length()).trim());
					reader.setVariable(LineReader.HISTORY_SIZE, maxLines);
				}
				else
				{
					quit = processCommand(cmd);
				}
			}
		}
		catch (final UserInterruptException | EndOfFileException e)
		{
			return;
		}
	}

	private static void outputNextQuery(final String cmd)
	{
		try
		{
			outputCSVFile = cmd.substring("OUTPUT NEXT QUERY ".length()).trim();
			if (outputCSVFile.isEmpty())
			{
				System.out.println("Provide a filename to output the query to");
			}
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void outputGISQuery(final String cmd)
	{
		try
		{
			outputKMLFile = cmd.substring("OUTPUT GIS KML ".length()).trim();
			if (outputKMLFile.isEmpty())
			{
				System.out.println("Provide a filename to output the query to");
			}
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void outputResultSet(final ResultSet rs, final ResultSetMetaData meta) throws Exception
	{
		final FileWriter fw = new FileWriter(outputCSVFile);
		final BufferedWriter out = new BufferedWriter(fw);
		try
		{
			for (int i = 1; i <= meta.getColumnCount(); i++)
			{
				final String colType = meta.getColumnTypeName(i);
				if (colType != null)
				{
					out.write(colType);
				}
				if (i < meta.getColumnCount())
				{
					out.write(',');
				}
			}
			out.write('\n');
			for (int i = 1; i <= meta.getColumnCount(); i++)
			{
				final String colType = meta.getColumnLabel(i);
				if (colType != null)
				{
					out.write(colType);
				}
				if (i < meta.getColumnCount())
				{
					out.write(',');
				}
			}
			out.write('\n');
			int rowCount = 0;
			while (rs.next())
			{
				for (int i = 1; i <= meta.getColumnCount(); i++)
				{
					out.write('"');
					final Object o = rs.getObject(i);
					String valueString = "NULL";
					if (rs.wasNull())
					{
						valueString = "NULL";
					}
					else if (o instanceof byte[])
					{
						valueString = "0x" + bytesToHex((byte[]) o);
					}
					else if (o != null)
					{
						valueString = o.toString();
					}
					for (int j = 0; j < valueString.length(); j++)
					{
						if (valueString.charAt(j) == '"')
						{
							out.write("\"\"");
						}
						else
						{
							out.write(valueString.charAt(j));
						}
					}
					out.write('"');
					if (i < meta.getColumnCount())
					{
						out.write(',');
					}
				}
				out.write('\n');
				rowCount++;
			}
			out.close();
			System.out.println("Fetched " + rowCount + (rowCount == 1 ? " row" : " rows"));
		}
		catch (final Exception e)
		{
			out.close();
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void outputGeospatial(final ResultSet rs, final ResultSetMetaData meta) throws Exception {
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

		Document doc = docBuilder.newDocument();
		//create kmlElement
		Element kmlElement = doc.createElement("kml");
		doc.appendChild(kmlElement);

		//kml Attributes, should never need to change
		Attr kmlAttrXMLNS = doc.createAttribute("xmlns");
		kmlAttrXMLNS.setValue("http://www.opengis.net/kml/2.2");
		kmlElement.setAttributeNode(kmlAttrXMLNS);

		Attr kmlAttrGX = doc.createAttribute("xmlns:gx");
		kmlAttrGX.setValue("http://www.google.com/kml/ext/2.2");
		kmlElement.setAttributeNode(kmlAttrGX);

		Attr kmlAttrKML = doc.createAttribute("xmlns:kml");
		kmlAttrKML.setValue("http://www.opengis.net/kml/2.2");
		kmlElement.setAttributeNode(kmlAttrKML);

		Attr kmlAttrAtom = doc.createAttribute("xmlns:atom");
		kmlAttrAtom.setValue("http://www.w3.org/2005/Atom");
		kmlElement.setAttributeNode(kmlAttrAtom);

		//create doc element
		Element documentElement = doc.createElement("Document");
		kmlElement.appendChild(documentElement);
		
		Attr docID = doc.createAttribute("id");
		docID.setValue("1SYf0ab5Z9uWomNsdRt1GbNfojQtUNfC6");
		documentElement.setAttributeNode(docID);

		Element name = doc.createElement("name");
		documentElement.appendChild(name);
		
		int count = 0; //counts how many objects we've visited to get row/column count
		name.appendChild(doc.createTextNode("GIS")); //name of the GIS project

		//generate 1st gx cascading style, used when object is not being hovered over
		Element gx1 = doc.createElement("gx:CascadingStyle");
		documentElement.appendChild(gx1);
		Attr gx1ID = doc.createAttribute("kml:id");
		gx1ID.setValue("__managed_style_1D3A7EA0A81971D9081A");
		gx1.setAttributeNode(gx1ID);
		Element gx1Style = doc.createElement("Style");
		gx1.appendChild(gx1Style);
		
		Element gx1IconStyle = doc.createElement("IconStyle"); //style of st_points
		gx1Style.appendChild(gx1IconStyle);
		Element gx1Icon = doc.createElement("Icon");
		gx1IconStyle.appendChild(gx1Icon);
		Element gx1Href = doc.createElement("href");
		gx1Icon.appendChild(gx1Href);
		gx1Href.appendChild(doc.createTextNode("https://earth.google.com/earth/rpc/cc/icon?color=1976d2&id=2000&scale=4")); // link to image of map
		
		Element gx1LineStyle = doc.createElement("LineStyle"); // style of st_linestring
		gx1Style.appendChild(gx1LineStyle);
		Element gx1LineColor = doc.createElement("color"); 
		gx1LineStyle.appendChild(gx1LineColor);
		gx1LineColor.appendChild(doc.createTextNode("ff2dc0fb")); // lines are yellow
		Element gx1LineWidth = doc.createElement("width");
		gx1LineStyle.appendChild(gx1LineWidth);
		gx1LineWidth.appendChild(doc.createTextNode("2"));
		
		Element gx1PolyStyle= doc.createElement("PolyStyle"); //style of st_polygon
		gx1Style.appendChild(gx1PolyStyle);
		Element gx1PolyColor = doc.createElement("color");
		gx1PolyStyle.appendChild(gx1PolyColor);
		gx1PolyColor.appendChild(doc.createTextNode("40ffffff"));

		//generate 2nd gx cascading style used when object is highlighted/hovered over
		Element gx2 = doc.createElement("gx:CascadingStyle");
		documentElement.appendChild(gx2);
		Attr gx2ID = doc.createAttribute("kml:id");
		gx2ID.setValue("__managed_style_2C97020CD31971D9081A");
		gx2.setAttributeNode(gx2ID);
		Element gx2Style = doc.createElement("Style");
		gx2.appendChild(gx2Style);
		
		Element gx2IconStyle = doc.createElement("IconStyle"); //style of st_point
		gx2Style.appendChild(gx2IconStyle);
		Element gx2Scale = doc.createElement("scale");
		gx2IconStyle.appendChild(gx2Scale);
		gx2Scale.appendChild(doc.createTextNode("1.2"));
		Element gx2Icon = doc.createElement("Icon");
		gx2IconStyle.appendChild(gx2Icon);
		Element gx2Href = doc.createElement("href");
		gx2Icon.appendChild(gx2Href);
		gx2Href.appendChild(doc.createTextNode("https://earth.google.com/earth/rpc/cc/icon?color=1976d2&id=2000&scale=4")); // link to image for pointer to st_point
		
		Element gx2LineStyle = doc.createElement("LineStyle"); //style of st_linestring
		gx2Style.appendChild(gx2LineStyle);
		Element gx2LineColor = doc.createElement("color");
		gx2LineStyle.appendChild(gx2LineColor);
		gx2LineColor.appendChild(doc.createTextNode("ff2dc0fb"));
		Element gx2LineWidth = doc.createElement("width");
		gx2LineStyle.appendChild(gx2LineWidth);
		gx2LineWidth.appendChild(doc.createTextNode("3"));
		
		Element gx2PolyStyle= doc.createElement("PolyStyle"); //style of st_polygon
		gx2Style.appendChild(gx2PolyStyle);
		Element gx2PolyColor = doc.createElement("color");
		gx2PolyStyle.appendChild(gx2PolyColor);
		gx2PolyColor.appendChild(doc.createTextNode("40ffffff"));

		//generate stylemap
		Element stylemap = doc.createElement("StyleMap"); //stylemap, switches between the normal and highlighted styles
		documentElement.appendChild(stylemap);
		Attr stylemapID = doc.createAttribute("id");
		stylemapID.setValue("__managed_style_02DBC6391B1971D9081A");
		stylemap.setAttributeNode(stylemapID);

		Element stylemapNormal = doc.createElement("Pair");
		stylemap.appendChild(stylemapNormal);
		Element normalKey = doc.createElement("key");
		stylemapNormal.appendChild(normalKey);
		normalKey.appendChild(doc.createTextNode("normal"));
		Element normalURL = doc.createElement("styleUrl");
		stylemapNormal.appendChild(normalURL);
		normalURL.appendChild(doc.createTextNode("#__managed_style_1D3A7EA0A81971D9081A"));

		Element stylemapHighlight = doc.createElement("Pair");
		stylemap.appendChild(stylemapHighlight);
		Element highlightKey = doc.createElement("key");
		stylemapHighlight.appendChild(highlightKey);
		highlightKey.appendChild(doc.createTextNode("highlight"));
		Element highlightURL = doc.createElement("styleUrl");
		stylemapHighlight.appendChild(highlightURL);
		highlightURL.appendChild(doc.createTextNode("#__managed_style_2C97020CD31971D9081A"));

		while (rs.next())
		{
			for (int i = 1; i <= meta.getColumnCount(); i++)
			{
				final Object o = rs.getObject(i);
				if (!rs.wasNull()) //must be a non-null geospatial object
				{
					if(meta.getColumnTypeName(i).equals("ST_POINT")) {
						((StPoint)(o)).writeXML(doc, documentElement, "col" + (i - 1) + "row" + (count));
					} else if(meta.getColumnTypeName(i).equals("ST_LINESTRING")) {
						((StLinestring)(o)).writeXML(doc, documentElement, "col" + (i - 1) + "row" + (count));
					} else if(meta.getColumnTypeName(i).equals("ST_POLYGON")) {
						((StPolygon)(o)).writeXML(doc, documentElement, "col" + (i - 1) + "row" + (count));
					}
				}
			}
			count++;
		}
		
		//write the content into xml file
		TransformerFactory transformerFactory =  TransformerFactory.newInstance();
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		Transformer transformer = transformerFactory.newTransformer();
		DOMSource source = new DOMSource(doc);

		StreamResult result =  new StreamResult(new File(outputKMLFile)); //prints result to target file
		transformer.transform(source, result);

		System.out.println("Outputed GIS results to " + outputKMLFile);
	}

	private static void printAllQueries(final ArrayList<SysQueriesRow> queries)
	{
		System.out.format("%-40s%-15s%-15s%-20s%-20s%-15s%-20s%-15s%s%n", "query id", "user", "importance", "estimated time", "elapsed time", "status", "server", "database", "sql");
		System.out.println(new String(new char[170]).replace("\0", "-"));
		for (final SysQueriesRow row : queries)
		{
			System.out.format("%-40s%-15s%-15s%-20s%-20s%-15s%-20s%-15s%s%n", row.getQueryId(), row.getUserid(), row.getImportance(), row.getEstimatedTimeSec(), row.getElapsedTimeSec(),
				row.getStatus(), row.getQueryServer(), row.getDatabase(), row.getSqlText());
		}
	}

	private static void printResultSet(final ResultSet rs, final ResultSetMetaData meta) throws Exception
	{
		if (!performance)
		{
			final ArrayList<Integer> offsets = new ArrayList<>();
			int i = 1;
			final StringBuilder line = new StringBuilder(64 * 1024);
			final int colCount = meta.getColumnCount();
			while (i <= colCount)
			{
				offsets.add(line.length());
				final int nameWidth = meta.getColumnName(i).length();
				final int valsWidth = meta.getColumnDisplaySize(i);
				line.append(meta.getColumnName(i));
				int j = 0;
				while (j < Math.max(valsWidth - nameWidth, 1))
				{
					line.append(" ");
					j++;
				}

				i++;
			}

			System.out.println(line);
			final int len = line.length();
			line.setLength(0);
			i = 0;
			while (i < len)
			{
				line.append('-');
				i++;
			}

			System.out.println(line);
			line.setLength(0);
			long rowCount = 0;
			while (rs.next())
			{
				rowCount++;
				i = 1;
				final int s = line.length();
				while (i <= colCount)
				{
					final int target = s + offsets.get(i - 1);
					final int x = target - line.length();
					int y = 0;
					while (y < x)
					{
						line.append(" ");
						y++;
					}
					Object o = rs.getObject(i);
					if (rs.wasNull())
					{
						o = "NULL";
					}
					else if (o instanceof byte[])
					{
						o = "0x" + bytesToHex((byte[]) o);
					}
					line.append(o);
					line.append(" ");
					i++;
				}

				if (line.length() >= 32 * 1024)
				{
					System.out.println(line);
					line.setLength(0);
				}
				else
				{
					line.append("\n");
				}
			}

			if (line.length() != 0)
			{
				System.out.println(line);
			}
			System.out.println("Fetched " + rowCount + (rowCount == 1 ? " row" : " rows"));
		}
		else
		{
			long rowCount = 0;
			while (rs.next())
			{
				rowCount++;
			}

			System.out.println("Fetched " + rowCount + (rowCount == 1 ? " row" : " rows"));
		}
	}

	private static void printTime(final long start, final long end)
	{
		if (timing)
		{
			System.out.println("\nCommand took " + (end - start) / 1000.0 + " seconds");
		}
	}

	private static void printWarnings(final ResultSet rs) throws SQLException
	{
		SQLWarning warn = rs.getWarnings();
		while (warn != null)
		{
			System.out.println("Warning: " + warn.getMessage());
			warn = warn.getNextWarning();
		}
	}

	private static void printWarnings(final Statement st) throws SQLException
	{
		SQLWarning warn = st.getWarnings();
		while (warn != null)
		{
			System.out.println("Warning: " + warn.getMessage());
			warn = warn.getNextWarning();
		}
	}

	/*
	 * ! This function lists the table privileges.
	 */

	private static boolean processCommand(final String cmd)
	{
		boolean quit = false;
		// System.out.println("processCommand(" + cmd + ")");
		if (cmd.equals(""))
		{
			return quit;
		}
		if (startsWithIgnoreCase(cmd, "CONNECT TO"))
		{
			connectTo(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "SELECT") || startsWithIgnoreCase(cmd, "WITH"))
		{
			select(cmd);
		}
		else if (cmd.equalsIgnoreCase("TIMING ON"))
		{
			timing = true;
		}
		else if (cmd.equalsIgnoreCase("TIMING OFF"))
		{
			timing = false;
		}
		else if (cmd.equalsIgnoreCase("PERFORMANCE ON"))
		{
			performance = true;
		}
		else if (cmd.equalsIgnoreCase("PERFORMANCE OFF"))
		{
			performance = false;
		}
		else if (cmd.equalsIgnoreCase("TRACE ON"))
		{
			trace = true;
		}
		else if (cmd.equalsIgnoreCase("TRACE OFF"))
		{
			trace = false;
		}
		else if (startsWithIgnoreCase(cmd, "SET SCHEMA"))
		{
			setSchema(cmd);
		}
		else if (cmd.equalsIgnoreCase("GET SCHEMA"))
		{
			getSchema(cmd);
		}
		// recognize explain pipeline not as explain
		else if (startsWithIgnoreCase(cmd, "EXPLAIN PIPELINE"))
		{
			explainPipeline(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "EXPLAIN"))
		{
			explain(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "CREATE") || startsWithIgnoreCase(cmd, "DROP") || startsWithIgnoreCase(cmd, "ALTER") || startsWithIgnoreCase(cmd, "TRUNCATE")
			|| startsWithIgnoreCase(cmd, "SET PSO") || startsWithIgnoreCase(cmd, "SET MAXROWS") || startsWithIgnoreCase(cmd, "SET MAXTIME") || startsWithIgnoreCase(cmd, "SET MAXTEMPDISK")
			|| startsWithIgnoreCase(cmd, "SET CONCURRENCY") || startsWithIgnoreCase(cmd, "SET PRIORITY") || startsWithIgnoreCase(cmd, "GRANT") || startsWithIgnoreCase(cmd, "REVOKE")
			|| startsWithIgnoreCase(cmd, "INVALIDATE STATS") || startsWithIgnoreCase(cmd, "QUARANTINE"))
		{
			update(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "LIST TABLES"))
		{
			listTables(cmd, false);
		}
		else if (startsWithIgnoreCase(cmd, "LIST TABLE PRIVILEGES"))
		{
			listPrivileges(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "LIST SYSTEM TABLES"))
		{
			listTables(cmd, true);
		}
		else if (startsWithIgnoreCase(cmd, "LIST VIEWS"))
		{
			listViews(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "DESCRIBE TABLE"))
		{
			describeTable(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "DESCRIBE VIEW"))
		{
			describeView(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "LIST INDICES") || startsWithIgnoreCase(cmd, "LIST INDEXES"))
		{
			listIndexes(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "PLAN EXECUTE"))
		{
			executePlan(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "PLAN EXPLAIN"))
		{
			explainPlan(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "PLAN LIST"))
		{
			listPlan();
		}
		else if (startsWithIgnoreCase(cmd, "SOURCE"))
		{
			quit = source(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "CANCEL"))
		{
			cancelQuery(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "KILL"))
		{
			killQuery(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "LIST ALL QUERIES"))
		{
			listAllQueries(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "LIST ALL COMPLETED QUERIES"))
		{
			listAllCompletedQueries(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "OUTPUT NEXT QUERY"))
		{
			outputNextQuery(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "OUTPUT GIS KML"))
		{
			outputGISQuery(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "FORCE EXTERNAL"))
		{
			forceExternal(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "EXPORT TABLE"))
		{
			exportTable(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "EXPORT VIEW"))
		{
			exportView(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "EXPORT TRANSLATION"))
		{
			exportTranslation(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "SET TIMEOUT"))
		{
			setQueryTimeout(cmd);
		}
		else if (startsWithIgnoreCase(cmd, "CHECK DATA"))
		{
			checkData(cmd);
		}
		else
		{
			System.out.println("Invalid command: " + cmd);
		}

		return quit;
	}

	private static String scrubCommand(final String cmd)
	{
		final StringBuilder out = new StringBuilder(256);
		int i = 0;
		final int length = cmd.length();
		while (i < length)
		{
			final char c = cmd.charAt(i);
			if (!comment)
			{
				if (quote == '\0' && i + 1 != length)
				{
					if (c == '-' && cmd.charAt(i + 1) == '-')
					{
						break;
					}
					if (c == '/' && cmd.charAt(i + 1) == '*')
					{
						comment = true;
						i++;
						continue;
					}
				}
				if ((c == '\'' || c == '"') && (quote == '\0' || quote == c)) // char is an active quote
				{
					quote = quote == '\0' ? c : '\0';
				}
				out.append(c);
			}
			else if (i + 1 != length && c == '*' && cmd.charAt(i + 1) == '/')
			{
				comment = false;
				i++;
			}

			i++;
		}
		return out.toString();
	}

	private static void select(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		ResultSet rs = null;

		try
		{
			start = System.currentTimeMillis();
			rs = stmt.executeQuery(cmd);
			printWarnings(stmt);
			final ResultSetMetaData meta = rs.getMetaData();
			
			if(outputKMLFile.isEmpty()) {
				if (outputCSVFile.isEmpty())
				{
					printResultSet(rs, meta);
				}
				else
				{
					outputResultSet(rs, meta);
					outputCSVFile = "";
				}
			} else {
				outputGeospatial(rs, meta);
				outputKMLFile = "";
			}
			printWarnings(rs);
			end = System.currentTimeMillis();

			rs.close();

			printTime(start, end);
		}
		catch (final Exception e)
		{
			try
			{
				if (rs != null)
				{
					rs.close();
				}
			}
			catch (final Exception f)
			{
			}
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void setMaxRows(final String cmd)
	{
		final long start = 0;
		final long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		try
		{
			stmt.execute(cmd);
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void setQueryTimeout(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}
		try
		{
			start = System.currentTimeMillis();
			final int timeout = Integer.parseInt(cmd.substring("SET TIMEOUT ".length()).trim());
			((XGConnection) conn).setTimeout(timeout);
			end = System.currentTimeMillis();
			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("CLI Error: " + e.getMessage());
		}
	}

	private static void setSchema(final String cmd)
	{
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		try
		{
			stmt.execute(cmd);
		}
		catch (final Exception e)
		{
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static boolean source(final String cmd)
	{

		boolean quit = false;

		final String[] tokens = cmd.split("\\s+");
		if (1 == tokens.length)
		{
			System.out.println(tokens[0] + " error: filename missing");
			return quit;
		}

		if (3 < tokens.length || 3 == tokens.length && !tokens[2].equalsIgnoreCase("TRACE"))
		{
			System.out.println("Error: too many parameters: " + cmd);
			return quit;
		}

		final File file = new File(tokens[1]);
		final boolean added = sources.add(file);
		if (!added)
		{
			System.out.println(tokens[0] + " error: " + file + " (source file already open)");
			return quit;
		}

		final long start = System.currentTimeMillis();

		try
		{
			final InputStreamReader reader = new InputStreamReader(new FileInputStream(file), Charset.defaultCharset());
			final BufferedReader bufferedReader = new BufferedReader(reader);

			final char oldQuote = quote;
			quote = '\0';

			final boolean oldComment = comment;
			comment = false;

			if (3 == tokens.length)
			{
				System.out.println(tokens[0] + ": Sourcing " + tokens[1]);
			}

			try
			{
				quit = sourceCommands(bufferedReader);
			}
			catch (final Throwable e)
			{
			}

			if (3 == tokens.length)
			{
				System.out.println(tokens[0] + ": Closing " + tokens[1]);
			}

			comment = oldComment;
			quote = oldQuote;

			bufferedReader.close();
			reader.close();
		}
		catch (final Throwable e)
		{
			System.out.println(tokens[0] + " error: " + e.getMessage());
		}

		printTime(start, System.currentTimeMillis());
		sources.remove(file);

		return quit;
	}

	private static boolean sourceCommands(final BufferedReader reader) throws IOException
	{
		boolean quit = false;

		try
		{
			while (true)
			{
				String line = reader.readLine();
				if (line == null)
				{
					return quit;
				}

				String cmd = scrubCommand(line + " ");

				while (true)
				{
					quit = cmd.trim().equalsIgnoreCase("QUIT");
					if (quit)
					{
						try
						{
							if (conn != null && !conn.isClosed())
							{
								final Driver driver = DriverManager.getDriver(((XGConnection) conn).getURL());
								final JDBCDriver jdbcDriver = (JDBCDriver) driver;
								conn.close();
								jdbcDriver.cancelCacheThreads();
							}
						}
						catch (final Exception e)
						{
						}
						return quit;
					}

					if (!comment && quote == '\0' && cmd.trim().endsWith(";"))
					{
						cmd = cmd.trim();
						cmd = cmd.substring(0, cmd.length() - 1).trim();
						if (trace && !endsWithIgnoreCase(cmd, " trace"))
						{
							cmd = cmd + " trace";
						}
						break;
					}
					else
					{
						final String cont = reader.readLine();
						if (cont == null)
						{
							return quit;
						}
						line = cont;
						cmd += scrubCommand(line + " ");
					}
				}

				quit = processCommand(cmd);
				if (quit)
				{
					return quit;
				}
			}
		}
		catch (final UserInterruptException | EndOfFileException e)
		{
		}

		return quit;
	}

	private static boolean startsWithIgnoreCase(final String in, final String cmp)
	{
		int firstNonParentheses = 0;
		final int len = in.length();
		while (firstNonParentheses < len && in.charAt(firstNonParentheses) == '(')
		{
			firstNonParentheses++;
		}

		if (firstNonParentheses + cmp.length() > in.length())
		{
			return false;
		}

		if (in.substring(firstNonParentheses, firstNonParentheses + cmp.length()).toUpperCase().startsWith(cmp.toUpperCase()))
		{
			return true;
		}

		return false;
	}

	// Generate a regex for an unquoted alphanumeric ([a-zA-Z0-9_]) or quoted free
	// (.) token. Reluctant.
	// Do not insert multiple regexes for tokens of the same name (or "q0" + another
	// name) into a single pattern.
	private static String tk(final String name)
	{
		return "(?<q0" + name + ">\"?)(?<" + name + ">(\\w+?|(?<=\").+?(?=\")))\\k<q0" + name + ">";
	}

	private static void update(final String cmd)
	{
		long start = 0;
		long end = 0;
		if (!isConnected())
		{
			System.out.println("No database connection exists");
			return;
		}

		try
		{
			start = System.currentTimeMillis();
			final long numRows = stmt.executeUpdate(cmd);
			end = System.currentTimeMillis();

			System.out.println("Modified " + numRows + (numRows == 1 ? " row" : " rows"));
			printWarnings(stmt);

			printTime(start, end);
		}
		catch (final Exception e)
		{
			System.out.println("Error: " + e.getMessage());
		}
	}

	// Generate a regex for an unquoted alphanumeric ([a-zA-Z0-9_]) or quoted free
	// (.) token possibly followed
	// by @ and more unquoted alphanumeric ([a-zA-Z0-9_]) or quoted free (.) tokens.
	private static String userTk()
	{
		return "(?<q0user>\"?)(?<user>(\\w+?|(?<=\").+?(?=\"))(@(\\w+?|(?<=\").+?(?=\")))?)\\k<q0user>";
	}
}
