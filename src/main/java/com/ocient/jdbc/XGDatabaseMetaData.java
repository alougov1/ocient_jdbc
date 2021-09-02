package com.ocient.jdbc;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.RowIdLifetime;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ocient.jdbc.proto.ClientWireProtocol;

public class XGDatabaseMetaData implements DatabaseMetaData
{
	private static final Logger LOGGER = Logger.getLogger("com.ocient.jdbc");
	private int majorJdbcVersion = Integer.parseInt(getClass().getPackage().getImplementationVersion().split("\\.")[0]);
	private int minorJdbcVersion = Integer.parseInt(getClass().getPackage().getImplementationVersion().split("\\.")[1]);
	private final Connection conn;

	public XGDatabaseMetaData(final Connection conn)
	{
		this.conn = conn;
	}

	@Override
	public boolean allProceduresAreCallable() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called allProceduresAreCallable()");
		return false;
	}

	@Override
	public boolean allTablesAreSelectable() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called allTablesAreSelectable()");
		return true;
	}

	@Override
	public boolean autoCommitFailureClosesAllResultSets() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called autoCommitFailureClosesAllResultSets()");
		return true;
	}

	@Override
	public boolean dataDefinitionCausesTransactionCommit() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called dataDefinitionCausesTransactionCommit()");
		return false;
	}

	@Override
	public boolean dataDefinitionIgnoredInTransactions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called dataDefinitionIgnoredInTransactions()");
		return false;
	}

	@Override
	public boolean deletesAreDetected(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called deletesAreDetected()");
		return false;
	}

	@Override
	public boolean doesMaxRowSizeIncludeBlobs() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called doesMaxRowSizeIncludeBlobs()");
		return true;
	}

	@Override
	public boolean generatedKeyAlwaysReturned() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called generatedKeyAlwaysReturned()");
		return false;
	}

	@Override
	public ResultSet getAttributes(final String catalog, final String schemaPattern, final String typeNamePattern, final String attributeNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getAttributes()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());
		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();

		/*
		 * TYPE_CAT String => type catalog (may be null) TYPE_SCHEM String => type
		 * schema (may be null) TYPE_NAME String => type name ATTR_NAME String =>
		 * attribute name DATA_TYPE int => attribute type SQL type from java.sql.Types
		 * ATTR_TYPE_NAME String => Data source dependent type name. For a UDT, the type
		 * name is fully qualified. For a REF, the type name is fully qualified and
		 * represents the target type of the reference type. ATTR_SIZE int => column
		 * size. For char or date types this is the maximum number of characters; for
		 * numeric or decimal types this is precision. DECIMAL_DIGITS int => the number
		 * of fractional digits. Null is returned for data types where DECIMAL_DIGITS is
		 * not applicable. NUM_PREC_RADIX int => Radix (typically either 10 or 2)
		 * NULLABLE int => whether NULL is allowed attributeNoNulls - might not allow
		 * NULL values attributeNullable - definitely allows NULL values
		 * attributeNullableUnknown - nullability unknown REMARKS String => comment
		 * describing column (may be null) ATTR_DEF String => default value (may be
		 * null) SQL_DATA_TYPE int => unused SQL_DATETIME_SUB int => unused
		 * CHAR_OCTET_LENGTH int => for char types the maximum number of bytes in the
		 * column ORDINAL_POSITION int => index of the attribute in the UDT (starting at
		 * 1) IS_NULLABLE String => ISO rules are used to determine the nullability for
		 * a attribute. YES --- if the attribute can include NULLs NO --- if the
		 * attribute cannot include NULLs empty string --- if the nullability for the
		 * attribute is unknown SCOPE_CATALOG String => catalog of table that is the
		 * scope of a reference attribute (null if DATA_TYPE isn't REF) SCOPE_SCHEMA
		 * String => schema of table that is the scope of a reference attribute (null if
		 * DATA_TYPE isn't REF) SCOPE_TABLE String => table name that is the scope of a
		 * reference attribute (null if the DATA_TYPE isn't REF) SOURCE_DATA_TYPE short
		 * => source type of a distinct type or user-generated Ref type,SQL type from
		 * java.sql.Types (null if DATA_TYPE isn't DISTINCT or user-generated REF)
		 */

		cols2Pos.put("type_cat", 0);
		cols2Pos.put("type_schem", 1);
		cols2Pos.put("type_name", 2);
		cols2Pos.put("attr_name", 3);
		cols2Pos.put("data_type", 4);
		cols2Pos.put("attr_type_name", 5);
		cols2Pos.put("attr_size", 6);
		cols2Pos.put("decimal_digits", 7);
		cols2Pos.put("num_prec_radix", 8);
		cols2Pos.put("nullable", 9);
		cols2Pos.put("remarks", 10);
		cols2Pos.put("attr_def", 11);
		cols2Pos.put("sql_data_type", 12);
		cols2Pos.put("sql_datetime_sub", 13);
		cols2Pos.put("char_octet_length", 14);
		cols2Pos.put("ordinal_position", 15);
		cols2Pos.put("is_nullable", 16);
		cols2Pos.put("scope_catalog", 17);
		cols2Pos.put("scope_schema", 18);
		cols2Pos.put("scope_table", 19);
		cols2Pos.put("source_data_type", 20);

		pos2Cols.put(0, "type_cat");
		pos2Cols.put(1, "type_schem");
		pos2Cols.put(2, "type_name");
		pos2Cols.put(3, "attr_name");
		pos2Cols.put(4, "data_type");
		pos2Cols.put(5, "attr_type_name");
		pos2Cols.put(6, "attr_size");
		pos2Cols.put(7, "decimal_digits");
		pos2Cols.put(8, "num_prec_radix");
		pos2Cols.put(9, "nullable");
		pos2Cols.put(10, "remarks");
		pos2Cols.put(11, "attr_def");
		pos2Cols.put(12, "sql_data_type");
		pos2Cols.put(13, "sql_datetime_sub");
		pos2Cols.put(14, "char_octet_length");
		pos2Cols.put(15, "ordinal_position");
		pos2Cols.put(16, "is_nullable");
		pos2Cols.put(17, "scope_catalog");
		pos2Cols.put(18, "scope_schema");
		pos2Cols.put(19, "scope_table");
		pos2Cols.put(20, "source_data_type");

		cols2Types.put("type_cat", "CHAR");
		cols2Types.put("type_schem", "CHAR");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("attr_name", "CHAR");
		cols2Types.put("data_type", "INT");
		cols2Types.put("attr_type_name", "CHAR");
		cols2Types.put("attr_size", "INT");
		cols2Types.put("decimal_digits", "INT");
		cols2Types.put("num_prec_radix", "INT");
		cols2Types.put("nullable", "INT");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("attr_def", "CHAR");
		cols2Types.put("sql_data_type", "INT");
		cols2Types.put("sql_datetime_sub", "INT");
		cols2Types.put("char_octet_length", "INT");
		cols2Types.put("ordinal_position", "INT");
		cols2Types.put("is_nullable", "CHAR");
		cols2Types.put("scope_catalog", "CHAR");
		cols2Types.put("scope_schema", "CHAR");
		cols2Types.put("scope_table", "CHAR");
		cols2Types.put("source_data_type", "SHORT");

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getBestRowIdentifier(final String catalog, final String schema, final String table, final int scope, final boolean nullable) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getBestRowIdentifier()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * SCOPE short => actual scope of result bestRowTemporary - very temporary,
		 * while using row bestRowTransaction - valid for remainder of current
		 * transaction bestRowSession - valid for remainder of current session
		 * COLUMN_NAME String => column name DATA_TYPE int => SQL data type from
		 * java.sql.Types TYPE_NAME String => Data source dependent type name, for a UDT
		 * the type name is fully qualified COLUMN_SIZE int => precision BUFFER_LENGTH
		 * int => not used DECIMAL_DIGITS short => scale - Null is returned for data
		 * types where DECIMAL_DIGITS is not applicable. PSEUDO_COLUMN short => is this
		 * a pseudo column like an Oracle ROWID bestRowUnknown - may or may not be
		 * pseudo column bestRowNotPseudo - is NOT a pseudo column bestRowPseudo - is a
		 * pseudo column
		 */

		final HashMap<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final HashMap<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("scope", 0);
		cols2Pos.put("column_name", 1);
		cols2Pos.put("data_type", 2);
		cols2Pos.put("type_name", 3);
		cols2Pos.put("column_size", 4);
		cols2Pos.put("buffer_length", 5);
		cols2Pos.put("decimal_digits", 6);
		cols2Pos.put("pseudo_column", 7);
		pos2Cols.put(0, "scope");
		pos2Cols.put(1, "column_name");
		pos2Cols.put(2, "data_type");
		pos2Cols.put(3, "type_name");
		pos2Cols.put(4, "column_size");
		pos2Cols.put(5, "buffer_length");
		pos2Cols.put(6, "decimal_digits");
		pos2Cols.put(7, "pseudo_column");
		cols2Types.put("scope", "SHORT");
		cols2Types.put("column_name", "CHAR");
		cols2Types.put("data_type", "INT");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("column_size", "INT");
		cols2Types.put("buffer_length", "INT");
		cols2Types.put("decimal_digits", "SHORT");
		cols2Types.put("pseudo_column", "SHORT");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getCatalogs() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getCatalogs()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());
		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("table_cat", 0);
		pos2Cols.put(0, "table_cat");
		cols2Types.put("table_cat", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);

		return retval;
	}

	@Override
	public String getCatalogSeparator() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getCatalogSeparator()");
		return ".";
	}

	@Override
	public String getCatalogTerm() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getCatalogTerm()");
		return "database";
	}

	@Override
	public ResultSet getClientInfoProperties() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getClientInfoProperties()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * NAME String=> The name of the client info property MAX_LEN int=> The maximum
		 * length of the value for the property DEFAULT_VALUE String=> The default value
		 * of the property DESCRIPTION String=> A description of the property. This will
		 * typically contain information as to where this property is stored in the
		 * database.
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("name", 0);
		cols2Pos.put("max_len", 1);
		cols2Pos.put("default_value", 2);
		cols2Pos.put("description", 3);
		pos2Cols.put(0, "name");
		pos2Cols.put(1, "max_len");
		pos2Cols.put(2, "default_value");
		pos2Cols.put(3, "description");
		cols2Types.put("name", "CHAR");
		cols2Types.put("max_len", "INT");
		cols2Types.put("default_value", "CHAR");
		cols2Types.put("description", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);

		return retval;
	}

	@Override
	public ResultSet getColumnPrivileges(final String catalog, final String schema, final String table, final String columnNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnPrivileges()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try {
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_COLUMN_PRIVILEGES, schema, table, columnNamePattern,
			true);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getColumnPrivileges with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getColumns(final String catalog, final String schemaPattern, final String tableNamePattern, final String columnNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumns()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try {
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_COLUMNS, schemaPattern, tableNamePattern,
			columnNamePattern, true);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getColumns with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public Connection getConnection() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getConnection()");
		return conn;
	}

	@Override
	public ResultSet getCrossReference(final String parentCatalog, final String parentSchema, final String parentTable, final String foreignCatalog, final String foreignSchema,
		final String foreignTable) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getCrossReference()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * PKTABLE_CAT String => parent key table catalog (may be null) PKTABLE_SCHEM
		 * String => parent key table schema (may be null) PKTABLE_NAME String => parent
		 * key table name PKCOLUMN_NAME String => parent key column name FKTABLE_CAT
		 * String => foreign key table catalog (may be null) being exported (may be
		 * null) FKTABLE_SCHEM String => foreign key table schema (may be null) being
		 * exported (may be null) FKTABLE_NAME String => foreign key table name being
		 * exported FKCOLUMN_NAME String => foreign key column name being exported
		 * KEY_SEQ short => sequence number within foreign key( a value of 1 represents
		 * the first column of the foreign key, a value of 2 would represent the second
		 * column within the foreign key). UPDATE_RULE short => What happens to foreign
		 * key when parent key is updated: importedNoAction - do not allow update of
		 * parent key if it has been imported importedKeyCascade - change imported key
		 * to agree with parent key update importedKeySetNull - change imported key to
		 * NULL if its parent key has been updated importedKeySetDefault - change
		 * imported key to default values if its parent key has been updated
		 * importedKeyRestrict - same as importedKeyNoAction (for ODBC 2.x
		 * compatibility) DELETE_RULE short => What happens to the foreign key when
		 * parent key is deleted. importedKeyNoAction - do not allow delete of parent
		 * key if it has been imported importedKeyCascade - delete rows that import a
		 * deleted key importedKeySetNull - change imported key to NULL if its primary
		 * key has been deleted importedKeyRestrict - same as importedKeyNoAction (for
		 * ODBC 2.x compatibility) importedKeySetDefault - change imported key to
		 * default if its parent key has been deleted FK_NAME String => foreign key name
		 * (may be null) PK_NAME String => parent key name (may be null) DEFERRABILITY
		 * short => can the evaluation of foreign key constraints be deferred until
		 * commit importedKeyInitiallyDeferred - see SQL92 for definition
		 * importedKeyInitiallyImmediate - see SQL92 for definition
		 * importedKeyNotDeferrable - see SQL92 for definition
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("pktable_cat", 0);
		cols2Pos.put("pktable_schem", 1);
		cols2Pos.put("pktable_name", 2);
		cols2Pos.put("pkcolumn_name", 3);
		cols2Pos.put("fktable_cat", 4);
		cols2Pos.put("fktable_schem", 5);
		cols2Pos.put("fktable_name", 6);
		cols2Pos.put("fkcolumn_name", 7);
		cols2Pos.put("key_seq", 8);
		cols2Pos.put("update_rule", 9);
		cols2Pos.put("delete_rule", 10);
		cols2Pos.put("fk_name", 11);
		cols2Pos.put("pk_name", 12);
		cols2Pos.put("deferrability", 13);
		pos2Cols.put(0, "pktable_cat");
		pos2Cols.put(1, "pktable_schem");
		pos2Cols.put(2, "pktable_name");
		pos2Cols.put(3, "pkcolumn_name");
		pos2Cols.put(4, "fktable_cat");
		pos2Cols.put(5, "fktable_schem");
		pos2Cols.put(6, "fktable_name");
		pos2Cols.put(7, "fkcolumn_name");
		pos2Cols.put(8, "key_seq");
		pos2Cols.put(9, "update_rule");
		pos2Cols.put(10, "delete_rule");
		pos2Cols.put(11, "fk_name");
		pos2Cols.put(12, "pk_name");
		pos2Cols.put(13, "deferrability");
		cols2Types.put("pktable_cat", "CHAR");
		cols2Types.put("pktable_schem", "CHAR");
		cols2Types.put("pktable_name", "CHAR");
		cols2Types.put("pkcolumn_name", "CHAR");
		cols2Types.put("fktable_cat", "CHAR");
		cols2Types.put("fktable_schem", "CHAR");
		cols2Types.put("fktable_name", "CHAR");
		cols2Types.put("fkcolumn_name", "CHAR");
		cols2Types.put("key_seq", "SHORT");
		cols2Types.put("update_rule", "SHORT");
		cols2Types.put("delete_rule", "SHORT");
		cols2Types.put("fk_name", "CHAR");
		cols2Types.put("pk_name", "CHAR");
		cols2Types.put("deferrability", "SHORT");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public int getDatabaseMajorVersion() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getDatabaseMajorVersion()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		int retval;
		try {
			retval = stmt.fetchSystemMetadataInt(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_DATABASE_MAJOR_VERSION);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getDatabaseMajorVersion with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public int getDatabaseMinorVersion() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getDatabaseMinorVersion()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		int retval;
		try {
			retval = stmt.fetchSystemMetadataInt(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_DATABASE_MINOR_VERSION);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getDatabaseMinorVersion with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public String getDatabaseProductName() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getDatabaseProductName()");
		return "Ocient";
	}

	@Override
	public String getDatabaseProductVersion() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getDatabaseProductVersion()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		String retval;
		try {
			retval = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_DATABASE_PRODUCT_VERSION);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getDatabaseProductVersion with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public int getDefaultTransactionIsolation() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getDefaultTransactionIsolation()");
		return Connection.TRANSACTION_NONE;
	}

	@Override
	public int getDriverMajorVersion()
	{
		LOGGER.log(Level.INFO, "Called getDriverMajorVersion()");
		return ((XGConnection) conn).getMajorVersion();
	}

	@Override
	public int getDriverMinorVersion()
	{
		LOGGER.log(Level.INFO, "Called getDriverMinorVersion()");
		return ((XGConnection) conn).getMinorVersion();
	}

	@Override
	public String getDriverName() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getDriverName()");
		return "Ocient JDBC Driver";
	}

	@Override
	public String getDriverVersion() throws SQLException
	{
		// This is really the protocol version.
		LOGGER.log(Level.INFO, "Called getDriverVersion()");
		return ((XGConnection) conn).getVersion();
	}

	@Override
	public ResultSet getExportedKeys(final String catalog, final String schema, final String table) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getExportedKeys()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * PKTABLE_CAT String => primary key table catalog (may be null) PKTABLE_SCHEM
		 * String => primary key table schema (may be null) PKTABLE_NAME String =>
		 * primary key table name PKCOLUMN_NAME String => primary key column name
		 * FKTABLE_CAT String => foreign key table catalog (may be null) being exported
		 * (may be null) FKTABLE_SCHEM String => foreign key table schema (may be null)
		 * being exported (may be null) FKTABLE_NAME String => foreign key table name
		 * being exported FKCOLUMN_NAME String => foreign key column name being exported
		 * KEY_SEQ short => sequence number within foreign key( a value of 1 represents
		 * the first column of the foreign key, a value of 2 would represent the second
		 * column within the foreign key). UPDATE_RULE short => What happens to foreign
		 * key when primary is updated: importedNoAction - do not allow update of
		 * primary key if it has been imported importedKeyCascade - change imported key
		 * to agree with primary key update importedKeySetNull - change imported key to
		 * NULL if its primary key has been updated importedKeySetDefault - change
		 * imported key to default values if its primary key has been updated
		 * importedKeyRestrict - same as importedKeyNoAction (for ODBC 2.x
		 * compatibility) DELETE_RULE short => What happens to the foreign key when
		 * primary is deleted. importedKeyNoAction - do not allow delete of primary key
		 * if it has been imported importedKeyCascade - delete rows that import a
		 * deleted key importedKeySetNull - change imported key to NULL if its primary
		 * key has been deleted importedKeyRestrict - same as importedKeyNoAction (for
		 * ODBC 2.x compatibility) importedKeySetDefault - change imported key to
		 * default if its primary key has been deleted FK_NAME String => foreign key
		 * name (may be null) PK_NAME String => primary key name (may be null)
		 * DEFERRABILITY short => can the evaluation of foreign key constraints be
		 * deferred until commit importedKeyInitiallyDeferred - see SQL92 for definition
		 * importedKeyInitiallyImmediate - see SQL92 for definition
		 * importedKeyNotDeferrable - see SQL92 for definition
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("pktable_cat", 0);
		cols2Pos.put("pktable_schem", 1);
		cols2Pos.put("pktable_name", 2);
		cols2Pos.put("pkcolumn_name", 3);
		cols2Pos.put("fktable_cat", 4);
		cols2Pos.put("fktable_schem", 5);
		cols2Pos.put("fktable_name", 6);
		cols2Pos.put("fkcolumn_name", 7);
		cols2Pos.put("key_seq", 8);
		cols2Pos.put("update_rule", 9);
		cols2Pos.put("delete_rule", 10);
		cols2Pos.put("fk_name", 11);
		cols2Pos.put("pk_name", 12);
		cols2Pos.put("deferrability", 13);
		pos2Cols.put(0, "pktable_cat");
		pos2Cols.put(1, "pktable_schem");
		pos2Cols.put(2, "pktable_name");
		pos2Cols.put(3, "pkcolumn_name");
		pos2Cols.put(4, "fktable_cat");
		pos2Cols.put(5, "fktable_schem");
		pos2Cols.put(6, "fktable_name");
		pos2Cols.put(7, "fkcolumn_name");
		pos2Cols.put(8, "key_seq");
		pos2Cols.put(9, "update_rule");
		pos2Cols.put(10, "delete_rule");
		pos2Cols.put(11, "fk_name");
		pos2Cols.put(12, "pk_name");
		pos2Cols.put(13, "deferrability");
		cols2Types.put("pktable_cat", "CHAR");
		cols2Types.put("pktable_schem", "CHAR");
		cols2Types.put("pktable_name", "CHAR");
		cols2Types.put("pkcolumn_name", "CHAR");
		cols2Types.put("fktable_cat", "CHAR");
		cols2Types.put("fktable_schem", "CHAR");
		cols2Types.put("fktable_name", "CHAR");
		cols2Types.put("fkcolumn_name", "CHAR");
		cols2Types.put("key_seq", "SHORT");
		cols2Types.put("update_rule", "SHORT");
		cols2Types.put("delete_rule", "SHORT");
		cols2Types.put("fk_name", "CHAR");
		cols2Types.put("pk_name", "CHAR");
		cols2Types.put("deferrability", "SHORT");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public String getExtraNameCharacters() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getExtraNameCharacters()");
		return "";
	}

	@Override
	public ResultSet getFunctionColumns(final String catalog, final String schemaPattern, final String functionNamePattern, final String columnNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getFunctionColumns()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * FUNCTION_CAT String => function catalog (may be null) FUNCTION_SCHEM String
		 * => function schema (may be null) FUNCTION_NAME String => function name. This
		 * is the name used to invoke the function COLUMN_NAME String =>
		 * column/parameter name COLUMN_TYPE Short => kind of column/parameter:
		 * functionColumnUnknown - nobody knows functionColumnIn - IN parameter
		 * functionColumnInOut - INOUT parameter functionColumnOut - OUT parameter
		 * functionColumnReturn - function return value functionColumnResult - Indicates
		 * that the parameter or column is a column in the ResultSet DATA_TYPE int =>
		 * SQL type from java.sql.Types TYPE_NAME String => SQL type name, for a UDT
		 * type the type name is fully qualified PRECISION int => precision LENGTH int
		 * => length in bytes of data SCALE short => scale - null is returned for data
		 * types where SCALE is not applicable. RADIX short => radix NULLABLE short =>
		 * can it contain NULL. functionNoNulls - does not allow NULL values
		 * functionNullable - allows NULL values functionNullableUnknown - nullability
		 * unknown REMARKS String => comment describing column/parameter
		 * CHAR_OCTET_LENGTH int => the maximum length of binary and character based
		 * parameters or columns. For any other datatype the returned value is a NULL
		 * ORDINAL_POSITION int => the ordinal position, starting from 1, for the input
		 * and output parameters. A value of 0 is returned if this row describes the
		 * function's return value. For result set columns, it is the ordinal position
		 * of the column in the result set starting from 1. IS_NULLABLE String => ISO
		 * rules are used to determine the nullability for a parameter or column. YES
		 * --- if the parameter or column can include NULLs NO --- if the parameter or
		 * column cannot include NULLs empty string --- if the nullability for the
		 * parameter or column is unknown SPECIFIC_NAME String => the name which
		 * uniquely identifies this function within its schema. This is a user
		 * specified, or DBMS generated, name that may be different then the
		 * FUNCTION_NAME for example with overload functions
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("function_cat", 0);
		cols2Pos.put("function_schem", 1);
		cols2Pos.put("function_name", 2);
		cols2Pos.put("column_name", 3);
		cols2Pos.put("column_type", 4);
		cols2Pos.put("data_type", 5);
		cols2Pos.put("type_name", 6);
		cols2Pos.put("precision", 7);
		cols2Pos.put("length", 8);
		cols2Pos.put("scale", 9);
		cols2Pos.put("radix", 10);
		cols2Pos.put("nullable", 11);
		cols2Pos.put("remarks", 12);
		cols2Pos.put("char_octet_length", 13);
		cols2Pos.put("ordinal_position", 14);
		cols2Pos.put("is_nullable", 15);
		cols2Pos.put("specific_name", 16);

		pos2Cols.put(0, "function_cat");
		pos2Cols.put(1, "function_schem");
		pos2Cols.put(2, "function_name");
		pos2Cols.put(3, "column_name");
		pos2Cols.put(4, "column_type");
		pos2Cols.put(5, "data_type");
		pos2Cols.put(6, "type_name");
		pos2Cols.put(7, "precision");
		pos2Cols.put(8, "length");
		pos2Cols.put(9, "scale");
		pos2Cols.put(10, "radix");
		pos2Cols.put(11, "nullable");
		pos2Cols.put(12, "remarks");
		pos2Cols.put(13, "char_octet_length");
		pos2Cols.put(14, "ordinal_position");
		pos2Cols.put(15, "is_nullable");
		pos2Cols.put(16, "specific_name");

		cols2Types.put("function_cat", "CHAR");
		cols2Types.put("function_schem", "CHAR");
		cols2Types.put("function_name", "CHAR");
		cols2Types.put("column_name", "CHAR");
		cols2Types.put("column_type", "SHORT");
		cols2Types.put("data_type", "INT");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("precision", "INT");
		cols2Types.put("length", "INT");
		cols2Types.put("scale", "SHORT");
		cols2Types.put("radix", "SHORT");
		cols2Types.put("nullable", "SHORT");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("char_octet_length", "INT");
		cols2Types.put("ordinal_position", "INT");
		cols2Types.put("is_nullable", "CHAR");
		cols2Types.put("specific_name", "CHAR");

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getFunctions(final String catalog, final String schemaPattern, final String functionNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getFunctions()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * FUNCTION_CAT String => function catalog (may be null) FUNCTION_SCHEM String
		 * => function schema (may be null) FUNCTION_NAME String => function name. This
		 * is the name used to invoke the function REMARKS String => explanatory comment
		 * on the function FUNCTION_TYPE short => kind of function:
		 * functionResultUnknown - Cannot determine if a return value or table will be
		 * returned functionNoTable- Does not return a table functionReturnsTable -
		 * Returns a table SPECIFIC_NAME String => the name which uniquely identifies
		 * this function within its schema. This is a user specified, or DBMS generated,
		 * name that may be different then the FUNCTION_NAME for example with overload
		 * functions
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("function_cat", 0);
		cols2Pos.put("function_schem", 1);
		cols2Pos.put("function_name", 2);
		cols2Pos.put("remarks", 3);
		cols2Pos.put("function_type", 4);
		cols2Pos.put("specific_name", 5);

		pos2Cols.put(0, "function_cat");
		pos2Cols.put(1, "function_schem");
		pos2Cols.put(2, "function_name");
		pos2Cols.put(3, "remarks");
		pos2Cols.put(4, "function_type");
		pos2Cols.put(5, "specific_name");

		cols2Types.put("function_cat", "CHAR");
		cols2Types.put("function_schem", "CHAR");
		cols2Types.put("function_name", "CHAR");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("function_type", "SHORT");
		cols2Types.put("specific_name", "CHAR");

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public String getIdentifierQuoteString() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getIdentifierQuoteString()");
		return "\"";
	}

	@Override
	public ResultSet getImportedKeys(final String catalog, final String schema, final String table) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getImportedKeys()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * PKTABLE_CAT String => primary key table catalog being imported (may be null)
		 * PKTABLE_SCHEM String => primary key table schema being imported (may be null)
		 * PKTABLE_NAME String => primary key table name being imported PKCOLUMN_NAME
		 * String => primary key column name being imported FKTABLE_CAT String =>
		 * foreign key table catalog (may be null) FKTABLE_SCHEM String => foreign key
		 * table schema (may be null) FKTABLE_NAME String => foreign key table name
		 * FKCOLUMN_NAME String => foreign key column name KEY_SEQ short => sequence
		 * number within a foreign key( a value of 1 represents the first column of the
		 * foreign key, a value of 2 would represent the second column within the
		 * foreign key). UPDATE_RULE short => What happens to a foreign key when the
		 * primary key is updated: importedNoAction - do not allow update of primary key
		 * if it has been imported importedKeyCascade - change imported key to agree
		 * with primary key update importedKeySetNull - change imported key to NULL if
		 * its primary key has been updated importedKeySetDefault - change imported key
		 * to default values if its primary key has been updated importedKeyRestrict -
		 * same as importedKeyNoAction (for ODBC 2.x compatibility) DELETE_RULE short =>
		 * What happens to the foreign key when primary is deleted. importedKeyNoAction
		 * - do not allow delete of primary key if it has been imported
		 * importedKeyCascade - delete rows that import a deleted key importedKeySetNull
		 * - change imported key to NULL if its primary key has been deleted
		 * importedKeyRestrict - same as importedKeyNoAction (for ODBC 2.x
		 * compatibility) importedKeySetDefault - change imported key to default if its
		 * primary key has been deleted FK_NAME String => foreign key name (may be null)
		 * PK_NAME String => primary key name (may be null) DEFERRABILITY short => can
		 * the evaluation of foreign key constraints be deferred until commit
		 * importedKeyInitiallyDeferred - see SQL92 for definition
		 * importedKeyInitiallyImmediate - see SQL92 for definition
		 * importedKeyNotDeferrable - see SQL92 for definition
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("pktable_cat", 0);
		cols2Pos.put("pktable_schem", 1);
		cols2Pos.put("pktable_name", 2);
		cols2Pos.put("pkcolumn_name", 3);
		cols2Pos.put("fktable_cat", 4);
		cols2Pos.put("fktable_schem", 5);
		cols2Pos.put("fktable_name", 6);
		cols2Pos.put("fkcolumn_name", 7);
		cols2Pos.put("key_seq", 8);
		cols2Pos.put("update_rule", 9);
		cols2Pos.put("delete_rule", 10);
		cols2Pos.put("fk_name", 11);
		cols2Pos.put("pk_name", 12);
		cols2Pos.put("deferrability", 13);
		pos2Cols.put(0, "pktable_cat");
		pos2Cols.put(1, "pktable_schem");
		pos2Cols.put(2, "pktable_name");
		pos2Cols.put(3, "pkcolumn_name");
		pos2Cols.put(4, "fktable_cat");
		pos2Cols.put(5, "fktable_schem");
		pos2Cols.put(6, "fktable_name");
		pos2Cols.put(7, "fkcolumn_name");
		pos2Cols.put(8, "key_seq");
		pos2Cols.put(9, "update_rule");
		pos2Cols.put(10, "delete_rule");
		pos2Cols.put(11, "fk_name");
		pos2Cols.put(12, "pk_name");
		pos2Cols.put(13, "deferrability");
		cols2Types.put("pktable_cat", "CHAR");
		cols2Types.put("pktable_schem", "CHAR");
		cols2Types.put("pktable_name", "CHAR");
		cols2Types.put("pkcolumn_name", "CHAR");
		cols2Types.put("fktable_cat", "CHAR");
		cols2Types.put("fktable_schem", "CHAR");
		cols2Types.put("fktable_name", "CHAR");
		cols2Types.put("fkcolumn_name", "CHAR");
		cols2Types.put("key_seq", "SHORT");
		cols2Types.put("update_rule", "SHORT");
		cols2Types.put("delete_rule", "SHORT");
		cols2Types.put("fk_name", "CHAR");
		cols2Types.put("pk_name", "CHAR");
		cols2Types.put("deferrability", "SHORT");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getIndexInfo(final String catalog, final String schema, final String table, final boolean unique, final boolean approximate) throws SQLException
	{
		// we only have non-unique indices
		// and don't report index statistics so have no use for approximate
		LOGGER.log(Level.INFO, "Called getIndexInfo()");
		boolean test = false;
		String wireSchema = "";
		if (schema != null)
		{
			test = true;
			wireSchema = schema;
		}
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_INDEX_INFO, wireSchema, table, "", test);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getIndexInfo with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public int getJDBCMajorVersion() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getJDBCMajorVersion()");
		return majorJdbcVersion;
	}

	@Override
	public int getJDBCMinorVersion() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getJDBCMinorVersion()");
		return minorJdbcVersion;
	}

	@Override
	public int getMaxBinaryLiteralLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxBinaryLiteralLength()");
		return 124 * 1024;
	}

	@Override
	public int getMaxCatalogNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxCatalogNameLength()");
		return 0;
	}

	@Override
	public int getMaxCharLiteralLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxCharLiteralLength()");
		return 124 * 1024;
	}

	@Override
	public int getMaxColumnNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxColumnNameLength()");
		return 0;
	}

	@Override
	public int getMaxColumnsInGroupBy() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxColumnsInGroupBy()");
		return 0;
	}

	@Override
	public int getMaxColumnsInIndex() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxColumnsInIndex()");
		return 0;
	}

	@Override
	public int getMaxColumnsInOrderBy() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxColumnsInOrderBy()");
		return 0;
	}

	@Override
	public int getMaxColumnsInSelect() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxColumnsInSelect()");
		return 0;
	}

	@Override
	public int getMaxColumnsInTable() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxColumnsInTable()");
		return 0;
	}

	@Override
	public int getMaxConnections() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxConnections()");
		return 0;
	}

	@Override
	public int getMaxCursorNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxCursorNameLength()");
		return 0;
	}

	@Override
	public int getMaxIndexLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxIndexLength()");
		return 0;
	}

	@Override
	public int getMaxProcedureNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxProcedureNameLength()");
		return 0;
	}

	@Override
	public int getMaxRowSize() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxRowSize()");
		return 0;
	}

	@Override
	public int getMaxSchemaNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxSchemaNameLength()");
		return 0;
	}

	@Override
	public int getMaxStatementLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxStatementLength()");
		return 0;
	}

	@Override
	public int getMaxStatements() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxStatements()");
		return 0;
	}

	@Override
	public int getMaxTableNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxTableNameLength()");
		return 0;
	}

	@Override
	public int getMaxTablesInSelect() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxTablesInSelect()");
		return 0;
	}

	@Override
	public int getMaxUserNameLength() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMaxUserNameLength()");
		return 0;
	}

	@Override
	public String getNumericFunctions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getNumericFunctions()");
		XGStatement stmt = (XGStatement) conn.createStatement();
		String retval;
		try{
			retval = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_NUMERIC_FUNCTIONS);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getNumericFunctions with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getPrimaryKeys(final String catalog, final String schema, final String table) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getPrimaryKeys()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * TABLE_CAT String => table catalog (may be null) TABLE_SCHEM String => table
		 * schema (may be null) TABLE_NAME String => table name COLUMN_NAME String =>
		 * column name KEY_SEQ short => sequence number within primary key( a value of 1
		 * represents the first column of the primary key, a value of 2 would represent
		 * the second column within the primary key). PK_NAME String => primary key name
		 * (may be null)
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("table_cat", 0);
		cols2Pos.put("table_schem", 1);
		cols2Pos.put("table_name", 2);
		cols2Pos.put("column_name", 3);
		cols2Pos.put("key_seq", 4);
		cols2Pos.put("pk_name", 5);
		pos2Cols.put(0, "table_cat");
		pos2Cols.put(1, "table_schem");
		pos2Cols.put(2, "table_name");
		pos2Cols.put(3, "column_name");
		pos2Cols.put(4, "key_seq");
		pos2Cols.put(5, "pk_name");
		cols2Types.put("table_cat", "CHAR");
		cols2Types.put("table_schem", "CHAR");
		cols2Types.put("table_name", "CHAR");
		cols2Types.put("column_name", "CHAR");
		cols2Types.put("key_seq", "SHORT");
		cols2Types.put("pk_name", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getProcedureColumns(final String catalog, final String schemaPattern, final String procedureNamePattern, final String columnNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getProcedureColumns()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * PROCEDURE_CAT String => procedure catalog (may be null) PROCEDURE_SCHEM
		 * String => procedure schema (may be null) PROCEDURE_NAME String => procedure
		 * name COLUMN_NAME String => column/parameter name COLUMN_TYPE Short => kind of
		 * column/parameter: procedureColumnUnknown - nobody knows procedureColumnIn -
		 * IN parameter procedureColumnInOut - INOUT parameter procedureColumnOut - OUT
		 * parameter procedureColumnReturn - procedure return value
		 * procedureColumnResult - result column in ResultSet DATA_TYPE int => SQL type
		 * from java.sql.Types TYPE_NAME String => SQL type name, for a UDT type the
		 * type name is fully qualified PRECISION int => precision LENGTH int => length
		 * in bytes of data SCALE short => scale - null is returned for data types where
		 * SCALE is not applicable. RADIX short => radix NULLABLE short => can it
		 * contain NULL. procedureNoNulls - does not allow NULL values procedureNullable
		 * - allows NULL values procedureNullableUnknown - nullability unknown REMARKS
		 * String => comment describing parameter/column COLUMN_DEF String => default
		 * value for the column, which should be interpreted as a string when the value
		 * is enclosed in single quotes (may be null) The string NULL (not enclosed in
		 * quotes) - if NULL was specified as the default value TRUNCATE (not enclosed
		 * in quotes) - if the specified default value cannot be represented without
		 * truncation NULL - if a default value was not specified SQL_DATA_TYPE int =>
		 * reserved for future use SQL_DATETIME_SUB int => reserved for future use
		 * CHAR_OCTET_LENGTH int => the maximum length of binary and character based
		 * columns. For any other datatype the returned value is a NULL ORDINAL_POSITION
		 * int => the ordinal position, starting from 1, for the input and output
		 * parameters for a procedure. A value of 0 is returned if this row describes
		 * the procedure's return value. For result set columns, it is the ordinal
		 * position of the column in the result set starting from 1. If there are
		 * multiple result sets, the column ordinal positions are implementation
		 * defined. IS_NULLABLE String => ISO rules are used to determine the
		 * nullability for a column. YES --- if the column can include NULLs NO --- if
		 * the column cannot include NULLs empty string --- if the nullability for the
		 * column is unknown SPECIFIC_NAME String => the name which uniquely identifies
		 * this procedure within its schema.
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("procedure_cat", 0);
		cols2Pos.put("procedure_schem", 1);
		cols2Pos.put("procedure_name", 2);
		cols2Pos.put("column_name", 3);
		cols2Pos.put("column_type", 4);
		cols2Pos.put("data_type", 5);
		cols2Pos.put("type_name", 6);
		cols2Pos.put("precision", 7);
		cols2Pos.put("length", 8);
		cols2Pos.put("scale", 9);
		cols2Pos.put("radix", 10);
		cols2Pos.put("nullable", 11);
		cols2Pos.put("remarks", 12);
		cols2Pos.put("column_def", 13);
		cols2Pos.put("sql_data_type", 14);
		cols2Pos.put("sql_datetime_sub", 15);
		cols2Pos.put("char_octet_length", 16);
		cols2Pos.put("ordinal_position", 17);
		cols2Pos.put("is_nullable", 18);
		cols2Pos.put("specific_name", 19);

		pos2Cols.put(0, "procedure_cat");
		pos2Cols.put(1, "procedure_schem");
		pos2Cols.put(2, "procedure_name");
		pos2Cols.put(3, "column_name");
		pos2Cols.put(4, "column_type");
		pos2Cols.put(5, "data_type");
		pos2Cols.put(6, "type_name");
		pos2Cols.put(7, "precision");
		pos2Cols.put(8, "length");
		pos2Cols.put(9, "scale");
		pos2Cols.put(10, "radix");
		pos2Cols.put(11, "nullable");
		pos2Cols.put(12, "remarks");
		pos2Cols.put(13, "column_def");
		pos2Cols.put(14, "sql_data_type");
		pos2Cols.put(15, "sql_datetime_sub");
		pos2Cols.put(16, "char_octet_length");
		pos2Cols.put(17, "ordinal_position");
		pos2Cols.put(18, "is_nullable");
		pos2Cols.put(19, "specific_name");

		cols2Types.put("procedure_cat", "CHAR");
		cols2Types.put("procedure_schem", "CHAR");
		cols2Types.put("procedure_name", "CHAR");
		cols2Types.put("column_name", "CHAR");
		cols2Types.put("column_type", "SHORT");
		cols2Types.put("data_type", "INT");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("precision", "INT");
		cols2Types.put("length", "INT");
		cols2Types.put("scale", "SHORT");
		cols2Types.put("radix", "SHORT");
		cols2Types.put("nullable", "SHORT");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("column_def", "CHAR");
		cols2Types.put("sql_data_type", "INT");
		cols2Types.put("sql_datetime_sub", "INT");
		cols2Types.put("char_octet_length", "INT");
		cols2Types.put("ordinal_position", "INT");
		cols2Types.put("is_nullable", "CHAR");
		cols2Types.put("specific_name", "CHAR");

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getProcedures(final String catalog, final String schemaPattern, final String procedureNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getProcedures()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * PROCEDURE_CAT String => procedure catalog (may be null) PROCEDURE_SCHEM
		 * String => procedure schema (may be null) PROCEDURE_NAME String => procedure
		 * name reserved for future use reserved for future use reserved for future use
		 * REMARKS String => explanatory comment on the procedure PROCEDURE_TYPE short
		 * => kind of procedure: procedureResultUnknown - Cannot determine if a return
		 * value will be returned procedureNoResult - Does not return a return value
		 * procedureReturnsResult - Returns a return value SPECIFIC_NAME String => The
		 * name which uniquely identifies this procedure within its schema.
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("procedure_cat", 0);
		cols2Pos.put("procedure_schem", 1);
		cols2Pos.put("procedure_name", 2);
		cols2Pos.put("remarks", 3);
		cols2Pos.put("procedure_type", 4);
		cols2Pos.put("specific_name", 5);

		pos2Cols.put(0, "procedure_cat");
		pos2Cols.put(1, "procedure_schem");
		pos2Cols.put(2, "procedure_name");
		pos2Cols.put(3, "remarks");
		pos2Cols.put(4, "procedure_type");
		pos2Cols.put(5, "specific_name");

		cols2Types.put("procedure_cat", "CHAR");
		cols2Types.put("procedure_schem", "CHAR");
		cols2Types.put("procedure_name", "CHAR");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("procedure_type", "SHORT");
		cols2Types.put("specific_name", "CHAR");

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public String getProcedureTerm() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getProcedureTerm()");
		return "stored procedure";
	}

	@Override
	public ResultSet getPseudoColumns(final String catalog, final String schemaPattern, final String tableNamePattern, final String columnNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getPseudoColumns()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * TABLE_CAT String => table catalog (may be null) TABLE_SCHEM String => table
		 * schema (may be null) TABLE_NAME String => table name COLUMN_NAME String =>
		 * column name DATA_TYPE int => SQL type from java.sql.Types COLUMN_SIZE int =>
		 * column size. DECIMAL_DIGITS int => the number of fractional digits. Null is
		 * returned for data types where DECIMAL_DIGITS is not applicable.
		 * NUM_PREC_RADIX int => Radix (typically either 10 or 2) COLUMN_USAGE String =>
		 * The allowed usage for the column. The value returned will correspond to the
		 * enum name returned by PseudoColumnUsage.name() REMARKS String => comment
		 * describing column (may be null) CHAR_OCTET_LENGTH int => for char types the
		 * maximum number of bytes in the column IS_NULLABLE String => ISO rules are
		 * used to determine the nullability for a column. YES --- if the column can
		 * include NULLs NO --- if the column cannot include NULLs empty string --- if
		 * the nullability for the column is unknown
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("table_cat", 0);
		cols2Pos.put("table_schem", 1);
		cols2Pos.put("table_name", 2);
		cols2Pos.put("column_name", 3);
		cols2Pos.put("data_type", 4);
		cols2Pos.put("column_size", 5);
		cols2Pos.put("decimal_digits", 6);
		cols2Pos.put("num_prec_radix", 7);
		cols2Pos.put("column_usage", 8);
		cols2Pos.put("remarks", 9);
		cols2Pos.put("char_octet_length", 10);
		cols2Pos.put("is_nullable", 11);

		pos2Cols.put(0, "table_cat");
		pos2Cols.put(1, "table_schem");
		pos2Cols.put(2, "table_name");
		pos2Cols.put(3, "column_name");
		pos2Cols.put(4, "data_type");
		pos2Cols.put(5, "column_size");
		pos2Cols.put(6, "decimal_digits");
		pos2Cols.put(7, "num_prec_radix");
		pos2Cols.put(8, "column_usage");
		pos2Cols.put(9, "remarks");
		pos2Cols.put(10, "char_octet_length");
		pos2Cols.put(11, "is_nullable");

		cols2Types.put("table_cat", "CHAR");
		cols2Types.put("table_schem", "CHAR");
		cols2Types.put("table_name", "CHAR");
		cols2Types.put("column_name", "CHAR");
		cols2Types.put("data_type", "INT");
		cols2Types.put("column_size", "INT");
		cols2Types.put("decimal_digits", "INT");
		cols2Types.put("num_prec_radix", "INT");
		cols2Types.put("column_usage", "CHAR");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("char_octet_length", "INT");
		cols2Types.put("is_nullable", "CHAR");

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public int getResultSetHoldability() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getResultSetHoldability()");
		return ResultSet.CLOSE_CURSORS_AT_COMMIT;
	}

	@Override
	public RowIdLifetime getRowIdLifetime() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getRowIdLifetime()");
		return RowIdLifetime.ROWID_UNSUPPORTED;
	}

	@Override
	public ResultSet getSchemas() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSchemas()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_SCHEMAS, "", "", "", false);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getSchemas with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getSchemas(final String catalog, final String schemaPattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSchemas()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_SCHEMAS, schemaPattern, "", "", true);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getSchemas with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public String getSchemaTerm() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSchemaTerm()");
		return "schema";
	}

	@Override
	public String getSearchStringEscape() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSearchStringEscape()");
		return "\\";
	}

	@Override
	public String getSQLKeywords() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSQLKeywords()");
		XGStatement stmt = (XGStatement) conn.createStatement();
		String retval;
		try{
			retval = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_SQL_KEYWORDS);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getSQLKeywords with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public int getSQLStateType() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSQLStateType()");
		return DatabaseMetaData.sqlStateSQL;
	}

	@Override
	public String getStringFunctions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getStringFunctions()");
		XGStatement stmt = (XGStatement) conn.createStatement();
		String retval;
		try{
			retval = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_STRING_FUNCTIONS);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getStringFunctions with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getSuperTables(final String catalog, final String schemaPattern, final String tableNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSuperTables()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * TABLE_CAT String => the type's catalog (may be null) TABLE_SCHEM String =>
		 * type's schema (may be null) TABLE_NAME String => type name SUPERTABLE_NAME
		 * String => the direct super type's name
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("table_cat", 0);
		cols2Pos.put("table_schem", 1);
		cols2Pos.put("table_name", 2);
		cols2Pos.put("supertable_name", 3);
		pos2Cols.put(0, "table_cat");
		pos2Cols.put(1, "table_schem");
		pos2Cols.put(2, "table_name");
		pos2Cols.put(3, "supertable_name");
		cols2Types.put("table_cat", "CHAR");
		cols2Types.put("table_schem", "CHAR");
		cols2Types.put("table_name", "CHAR");
		cols2Types.put("supertable_name", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getSuperTypes(final String catalog, final String schemaPattern, final String typeNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSuperTypes()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * TYPE_CAT String => the UDT's catalog (may be null) TYPE_SCHEM String => UDT's
		 * schema (may be null) TYPE_NAME String => type name of the UDT SUPERTYPE_CAT
		 * String => the direct super type's catalog (may be null) SUPERTYPE_SCHEM
		 * String => the direct super type's schema (may be null) SUPERTYPE_NAME String
		 * => the direct super type's name
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("type_cat", 0);
		cols2Pos.put("type_schem", 1);
		cols2Pos.put("type_name", 2);
		cols2Pos.put("supertype_cat", 3);
		cols2Pos.put("supertype_schem", 4);
		cols2Pos.put("supertype_name", 5);
		pos2Cols.put(0, "type_cat");
		pos2Cols.put(1, "type_schem");
		pos2Cols.put(2, "type_name");
		pos2Cols.put(3, "supertype_cat");
		pos2Cols.put(4, "supertype_schem");
		pos2Cols.put(5, "supertype_name");
		cols2Types.put("type_cat", "CHAR");
		cols2Types.put("type_schem", "CHAR");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("supertype_cat", "CHAR");
		cols2Types.put("supertype_schem", "CHAR");
		cols2Types.put("supertype_name", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);

		return retval;
	}

	@Override
	public String getSystemFunctions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSystemFunctions()");
		XGStatement stmt = (XGStatement) conn.createStatement();
		String retval;
		try{
			retval = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_SYSTEM_FUNCTIONS);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getSystemFunctions with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	public ResultSet getSystemTables(final String catalog, final String schemaPattern, final String tableNamePattern, final String[] types) throws SQLException
	{
		// we only have one table type
		LOGGER.log(Level.INFO, "Called getSystemTables()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_SYSTEM_TABLES, schemaPattern, tableNamePattern, "",
			true);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getSystemTables with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getTablePrivileges(final String catalog, final String schemaPattern, final String tableNamePattern) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getTablePrivileges()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_TABLE_PRIVILEGES, schemaPattern, tableNamePattern, "",
			true);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getTablePrivileges with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getTables(final String catalog, final String schemaPattern, final String tableNamePattern, final String[] types) throws SQLException
	{
		// we only have one table type
		LOGGER.log(Level.INFO, "Called getTables()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_TABLES, schemaPattern, tableNamePattern, "", true);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getTables with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getTableTypes() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getTableTypes()");
		final ArrayList<Object> rs = new ArrayList<>();
		ArrayList<Object> row = new ArrayList<>();
		row.add("SYSTEM TABLE");
		rs.add(row);
		row = new ArrayList<>();
		row.add("TABLE");
		rs.add(row);
		row = new ArrayList<>();
		row.add("VIEW");
		rs.add(row);
		final XGResultSet retval = new XGResultSet((XGConnection) conn, rs, (XGStatement) conn.createStatement());
		final HashMap<String, Integer> cols2Pos = new HashMap<>();
		cols2Pos.put("table_type", 0);
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		pos2Cols.put(0, "table_type");
		final HashMap<String, String> cols2Types = new HashMap<>();
		cols2Types.put("table_type", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public String getTimeDateFunctions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getTimeDateFunctions()");
		XGStatement stmt = (XGStatement) conn.createStatement();
		String retval;
		try{
			retval = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_TIME_DATE_FUNCTIONS);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getTimeDateFunctions with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getTypeInfo() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getTypeInfo()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_TYPE_INFO, "", "", "", true);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getTypeInfo with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public ResultSet getUDTs(final String catalog, final String schemaPattern, final String typeNamePattern, final int[] types) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getUDTs()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * TYPE_CAT String => the type's catalog (may be null) TYPE_SCHEM String =>
		 * type's schema (may be null) TYPE_NAME String => type name CLASS_NAME String
		 * => Java class name DATA_TYPE int => type value defined in java.sql.Types. One
		 * of JAVA_OBJECT, STRUCT, or DISTINCT REMARKS String => explanatory comment on
		 * the type BASE_TYPE short => type code of the source type of a DISTINCT type
		 * or the type that implements the user-generated reference type of the
		 * SELF_REFERENCING_COLUMN of a structured type as defined in java.sql.Types
		 * (null if DATA_TYPE is not DISTINCT or not STRUCT with REFERENCE_GENERATION =
		 * USER_DEFINED)
		 */

		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("type_cat", 0);
		cols2Pos.put("type_schem", 1);
		cols2Pos.put("type_name", 2);
		cols2Pos.put("data_type", 3);
		cols2Pos.put("remarks", 4);
		cols2Pos.put("base_type", 5);
		pos2Cols.put(0, "type_cat");
		pos2Cols.put(1, "type_schem");
		pos2Cols.put(2, "type_name");
		pos2Cols.put(3, "data_type");
		pos2Cols.put(4, "remarks");
		pos2Cols.put(5, "base_type");
		cols2Types.put("type_cat", "CHAR");
		cols2Types.put("type_schem", "CHAR");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("data_type", "CHAR");
		cols2Types.put("remarks", "CHAR");
		cols2Types.put("base_type", "CHAR");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public String getURL() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getURL()");
		return ((XGConnection) conn).getURL();
	}

	@Override
	public String getUserName() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getUserName()");
		return ((XGConnection) conn).getUser();
	}

	@Override
	public ResultSet getVersionColumns(final String catalog, final String schema, final String table) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getVersionColumns()");
		final XGResultSet retval = new XGResultSet((XGConnection) conn, new ArrayList<>(), (XGStatement) conn.createStatement());

		/*
		 * SCOPE short => is not used COLUMN_NAME String => column name DATA_TYPE int =>
		 * SQL data type from java.sql.Types TYPE_NAME String => Data source-dependent
		 * type name COLUMN_SIZE int => precision BUFFER_LENGTH int => length of column
		 * value in bytes DECIMAL_DIGITS short => scale - Null is returned for data
		 * types where DECIMAL_DIGITS is not applicable. PSEUDO_COLUMN short => whether
		 * this is pseudo column like an Oracle ROWID versionColumnUnknown - may or may
		 * not be pseudo column versionColumnNotPseudo - is NOT a pseudo column
		 * versionColumnPseudo - is a pseudo column
		 */

		final HashMap<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final HashMap<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("scope", 0);
		cols2Pos.put("column_name", 1);
		cols2Pos.put("data_type", 2);
		cols2Pos.put("type_name", 3);
		cols2Pos.put("column_size", 4);
		cols2Pos.put("buffer_length", 5);
		cols2Pos.put("decimal_digits", 6);
		cols2Pos.put("pseudo_column", 7);
		pos2Cols.put(0, "scope");
		pos2Cols.put(1, "column_name");
		pos2Cols.put(2, "data_type");
		pos2Cols.put(3, "type_name");
		pos2Cols.put(4, "column_size");
		pos2Cols.put(5, "buffer_length");
		pos2Cols.put(6, "decimal_digits");
		pos2Cols.put(7, "pseudo_column");
		cols2Types.put("scope", "SHORT");
		cols2Types.put("column_name", "CHAR");
		cols2Types.put("data_type", "INT");
		cols2Types.put("type_name", "CHAR");
		cols2Types.put("column_size", "INT");
		cols2Types.put("buffer_length", "INT");
		cols2Types.put("decimal_digits", "SHORT");
		cols2Types.put("pseudo_column", "SHORT");
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);

		return retval;
	}

	public ResultSet getViews(final String catalog, final String schemaPattern, final String viewNamePattern, final String[] types) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getViews()");
		XGStatement stmt = (XGStatement)conn.createStatement();
		ResultSet retval;
		try{
			retval = stmt.fetchSystemMetadataResultSet(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_VIEWS, schemaPattern, viewNamePattern, "", true);
		}
		catch(final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getViews with message %s", e.toString(), e.getMessage()));
			stmt.close();
			throw e;
		}
		return retval;
	}

	@Override
	public boolean insertsAreDetected(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called insertsAreDetected()");
		return false;
	}

	@Override
	public boolean isCatalogAtStart() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isCatalogAtStart()");
		return true;
	}

	@Override
	public boolean isReadOnly() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isReadOnly()");
		return false;
	}

	@Override
	public boolean isWrapperFor(final Class<?> iface) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isWrapperFor()");
		return false;
	}

	@Override
	public boolean locatorsUpdateCopy() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called locatorsUpdateCopy()");
		return false;
	}

	@Override
	public boolean nullPlusNonNullIsNull() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called nullPlusNonNullIsNull()");
		return true;
	}

	@Override
	public boolean nullsAreSortedAtEnd() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called nullsAreSortedAtEnd()");
		return true;
	}

	@Override
	public boolean nullsAreSortedAtStart() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called nullsAreSortedAtStart()");
		return false;
	}

	@Override
	public boolean nullsAreSortedHigh() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called nullsAreSortedHigh()");
		return false;
	}

	@Override
	public boolean nullsAreSortedLow() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called nullsAreSortedLow()");
		return false;
	}

	@Override
	public boolean othersDeletesAreVisible(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called othersDeletesAreVisible()");
		return false;
	}

	@Override
	public boolean othersInsertsAreVisible(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called othersInsertsAreVisible()");
		return false;
	}

	@Override
	public boolean othersUpdatesAreVisible(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called othersUpdatesAreVisible()");
		return false;
	}

	@Override
	public boolean ownDeletesAreVisible(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called ownDeletesAreVisible()");
		return true;
	}

	@Override
	public boolean ownInsertsAreVisible(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called ownInsertsAreVisible()");
		return true;
	}

	@Override
	public boolean ownUpdatesAreVisible(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called ownUpdatesAreVisible()");
		return true;
	}

	@Override
	public boolean storesLowerCaseIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called storesLowerCaseIdentifiers()");
		return true;
	}

	@Override
	public boolean storesLowerCaseQuotedIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called storesLowerCaseQuotedIdentifiers()");
		return false;
	}

	@Override
	public boolean storesMixedCaseIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called storesMixedCaseIdentifiers()");
		return false;
	}

	@Override
	public boolean storesMixedCaseQuotedIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called storesMixedCaseQuotedIdentifiers()");
		return true;
	}

	@Override
	public boolean storesUpperCaseIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called storesUpperCaseIdentifiers()");
		return false;
	}

	@Override
	public boolean storesUpperCaseQuotedIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called storesUpperCaseQuotedIdentifiers()");
		return false;
	}

	@Override
	public boolean supportsAlterTableWithAddColumn() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsAlterTableWithAddColumn()");
		return true;
	}

	@Override
	public boolean supportsAlterTableWithDropColumn() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsAlterTableWithDropColumn()");
		return true;
	}

	@Override
	public boolean supportsANSI92EntryLevelSQL() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsANSI92EntryLevelSQL()");
		return false;
	}

	@Override
	public boolean supportsANSI92FullSQL() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsANSI92FullSQL()");
		return false;
	}

	@Override
	public boolean supportsANSI92IntermediateSQL() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsANSI92IntermediateSQL()");
		return false;
	}

	@Override
	public boolean supportsBatchUpdates() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsBatchUpdates()");
		return false;
	}

	@Override
	public boolean supportsCatalogsInDataManipulation() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCatalogsInDataManipulation()");
		return false;
	}

	@Override
	public boolean supportsCatalogsInIndexDefinitions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCatalogsInIndexDefinitions()");
		return false;
	}

	@Override
	public boolean supportsCatalogsInPrivilegeDefinitions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCatalogsInPrivilegeDefinitions()");
		return false;
	}

	@Override
	public boolean supportsCatalogsInProcedureCalls() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCatalogsInProcedureCalls()");
		return false;
	}

	@Override
	public boolean supportsCatalogsInTableDefinitions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCatalogsInTableDefinitions()");
		return false;
	}

	@Override
	public boolean supportsColumnAliasing() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsColumnAliasing()");
		return true;
	}

	@Override
	public boolean supportsConvert() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsConvert()");
		return false;
	}

	@Override
	public boolean supportsConvert(final int fromType, final int toType) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsConvert()");
		return false;
	}

	@Override
	public boolean supportsCoreSQLGrammar() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCoreSQLGrammar()");
		return false;
	}

	@Override
	public boolean supportsCorrelatedSubqueries() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsCorrelatedSubqueries()");
		return true;
	}

	@Override
	public boolean supportsDataDefinitionAndDataManipulationTransactions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsDataDefinitionAndDataManipulationTransactions()");
		return false;
	}

	@Override
	public boolean supportsDataManipulationTransactionsOnly() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsDataManipulationTransactionsOnly()");
		return false;
	}

	@Override
	public boolean supportsDifferentTableCorrelationNames() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsDifferentTableCorrelationNames()");
		return true;
	}

	@Override
	public boolean supportsExpressionsInOrderBy() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsExpressionsInOrderBy()");
		return true;
	}

	@Override
	public boolean supportsExtendedSQLGrammar() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsExtendedSQLGrammar()");
		return false;
	}

	@Override
	public boolean supportsFullOuterJoins() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsFullOuterJoins()");
		return true;
	}

	@Override
	public boolean supportsGetGeneratedKeys() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsGetGeneratedKeys()");
		return false;
	}

	@Override
	public boolean supportsGroupBy() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsGroupBy()");
		return true;
	}

	@Override
	public boolean supportsGroupByBeyondSelect() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsGroupByBeyondSelect()");
		return true;
	}

	@Override
	public boolean supportsGroupByUnrelated() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsGroupByUnrelated()");
		return true;
	}

	@Override
	public boolean supportsIntegrityEnhancementFacility() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsIntegrityEnhancementFacility()");
		return false;
	}

	@Override
	public boolean supportsLikeEscapeClause() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsLikeEscapeClause()");
		return true;
	}

	@Override
	public boolean supportsLimitedOuterJoins() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsLikeEscapeClause()");
		return true;
	}

	@Override
	public boolean supportsMinimumSQLGrammar() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsMinimumSQLGrammar()");
		return false;
	}

	@Override
	public boolean supportsMixedCaseIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsMixedCaseIdentifiers()");
		return false;
	}

	@Override
	public boolean supportsMixedCaseQuotedIdentifiers() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsMixedCaseQuotedIdentifiers()");
		return true;
	}

	@Override
	public boolean supportsMultipleOpenResults() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsMultipleOpenResults()");
		return false;
	}

	@Override
	public boolean supportsMultipleResultSets() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsMultipleResultSets()");
		return false;
	}

	@Override
	public boolean supportsMultipleTransactions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsMultipleTransactions()");
		return true;
	}

	@Override
	public boolean supportsNamedParameters() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsNamedParameters()");
		return false;
	}

	@Override
	public boolean supportsNonNullableColumns() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsNonNullableColumns()");
		return true;
	}

	@Override
	public boolean supportsOpenCursorsAcrossCommit() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsOpenCursorsAcrossCommit()");
		return false;
	}

	@Override
	public boolean supportsOpenCursorsAcrossRollback() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsOpenCursorsAcrossRollback()");
		return false;
	}

	@Override
	public boolean supportsOpenStatementsAcrossCommit() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsOpenStatementsAcrossCommit()");
		return false;
	}

	@Override
	public boolean supportsOpenStatementsAcrossRollback() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsOpenStatementsAcrossRollback()");
		return false;
	}

	@Override
	public boolean supportsOrderByUnrelated() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsOrderByUnrelated()");
		return true;
	}

	@Override
	public boolean supportsOuterJoins() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsOuterJoins()");
		return true;
	}

	@Override
	public boolean supportsPositionedDelete() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsPositionedDelete()");
		return false;
	}

	@Override
	public boolean supportsPositionedUpdate() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsPositionedUpdate()");
		return false;
	}

	@Override
	public boolean supportsResultSetConcurrency(final int type, final int concurrency) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsResultSetConcurrency()");
		if (type == ResultSet.TYPE_FORWARD_ONLY && concurrency == ResultSet.CONCUR_READ_ONLY)
		{
			return true;
		}

		return false;
	}

	@Override
	public boolean supportsResultSetHoldability(final int holdability) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsResultSetHoldability()");
		if (holdability == ResultSet.CLOSE_CURSORS_AT_COMMIT)
		{
			return true;
		}

		return false;
	}

	@Override
	public boolean supportsResultSetType(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsResultSetType()");
		if (type == ResultSet.TYPE_FORWARD_ONLY)
		{
			return true;
		}

		return false;
	}

	@Override
	public boolean supportsSavepoints() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSavepoints()");
		return false;
	}

	@Override
	public boolean supportsSchemasInDataManipulation() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSchemasInDataManipulation()");
		return true;
	}

	@Override
	public boolean supportsSchemasInIndexDefinitions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSchemasInIndexDefinitions()");
		return true;
	}

	@Override
	public boolean supportsSchemasInPrivilegeDefinitions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSchemasInPrivilegeDefinitions()");
		return true;
	}

	@Override
	public boolean supportsSchemasInProcedureCalls() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSchemasInProcedureCalls()");
		return true;
	}

	@Override
	public boolean supportsSchemasInTableDefinitions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSchemasInTableDefinitions()");
		return true;
	}

	@Override
	public boolean supportsSelectForUpdate() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSelectForUpdate()");
		return false;
	}

	@Override
	public boolean supportsStatementPooling() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsStatementPooling()");
		return true;
	}

	@Override
	public boolean supportsStoredFunctionsUsingCallSyntax() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsStoredFunctionsUsingCallSyntax()");
		return false;
	}

	@Override
	public boolean supportsStoredProcedures() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsStoredProcedures()");
		return false;
	}

	@Override
	public boolean supportsSubqueriesInComparisons() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSubqueriesInComparisons()");
		return true;
	}

	@Override
	public boolean supportsSubqueriesInExists() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSubqueriesInExists()");
		return true;
	}

	@Override
	public boolean supportsSubqueriesInIns() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSubqueriesInIns()");
		return true;
	}

	@Override
	public boolean supportsSubqueriesInQuantifieds() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsSubqueriesInQuantifieds()");
		return true;
	}

	@Override
	public boolean supportsTableCorrelationNames() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsTableCorrelationNames()");
		return true;
	}

	@Override
	public boolean supportsTransactionIsolationLevel(final int level) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsTransactionIsolationLevel()");
		if (level == Connection.TRANSACTION_NONE)
		{
			return true;
		}

		return false;
	}

	@Override
	public boolean supportsTransactions() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsTransactions()");
		return false;
	}

	@Override
	public boolean supportsUnion() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsUnion()");
		return true;
	}

	@Override
	public boolean supportsUnionAll() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called supportsUnionAll()");
		return true;
	}

	@Override
	public <T> T unwrap(final Class<T> iface) throws SQLException
	{
		LOGGER.log(Level.WARNING, "unwrap() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean updatesAreDetected(final int type) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called updatesAreDetected()");
		return false;
	}

	@Override
	public boolean usesLocalFilePerTable() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called usesLocalFilePerTable()");
		return false;
	}

	@Override
	public boolean usesLocalFiles() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called usesLocalFiles()");
		return false;
	}
}
