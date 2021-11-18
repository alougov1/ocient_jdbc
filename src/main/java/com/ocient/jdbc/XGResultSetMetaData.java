package com.ocient.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class XGResultSetMetaData implements ResultSetMetaData
{
	private static final Logger LOGGER = Logger.getLogger("com.ocient.jdbc");

	public final Map<String, Integer> cols2Pos;
	private Map<String, Integer> caseInsensitiveCols2Pos;
	public final TreeMap<Integer, String> pos2Cols;
	public final Map<String, String> cols2Types;

	public XGResultSetMetaData(final Map<String, Integer> cols2Pos2, final TreeMap<Integer, String> pos2Cols, final Map<String, String> cols2Types2)
	{
		cols2Pos = cols2Pos2;
		this.pos2Cols = pos2Cols;
		cols2Types = cols2Types2;
		setCaseInsensitiveCols2Pos();
	}

	public Map<String, Integer> getCols2Pos(){
		return cols2Pos;
	}

	public TreeMap<Integer, String> getPos2Cols(){
		return pos2Cols;
	} 

	public Map<String, String> getCols2Types(){
		return cols2Types;
	}

	@Override
	public String getCatalogName(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getCatalogName()");
		return "";
	}

	@Override
	public String getColumnClassName(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnClassName()");
		final String name = pos2Cols.get(column - 1);
		final String type = cols2Types.get(name);

		if (type.equals("CHAR"))
		{
			return "java.lang.String";
		}
		else if (type.equals("BYTE"))
		{
			return "java.lang.Byte";
		}
		else if (type.equals("SHORT"))
		{
			return "java.lang.Short";
		}
		else if (type.equals("INT"))
		{
			return "java.lang.Integer";
		}
		else if (type.equals("FLOAT"))
		{
			return "java.lang.Float";
		}
		else if (type.equals("DOUBLE"))
		{
			return "java.lang.Double";
		}
		else if (type.equals("LONG"))
		{
			return "java.lang.Long";
		}
		else if (type.equals("TIMESTAMP"))
		{
			return "com.ocient.jdbc.XGTimestamp";
		}
		else if (type.equals("TIME"))
		{
			return "com.ocient.jdbc.XGTime";
		}
		else if (type.equals("DATE"))
		{
			return "com.ocient.jdbc.XGDate";
		}
		else if (type.equals("BOOLEAN"))
		{
			return "java.lang.Boolean";
		}
		else if (type.equals("DECIMAL"))
		{
			return "java.math.BigDecimal";
		}
		else if (type.equals("BINARY"))
		{
			return "[B";
		}
		else if (type.equals("ARRAY"))
		{
			return "com.ocient.jdbc.XGArray";
		}
		else if (type.equals("TUPLE"))
		{
			return "com.ocient.jdbc.XGTuple";
		}
		else if (type.equals("UUID"))
		{
			return "java.util.UUID";
		}
		else if (type.equals("ST_POINT"))
		{
			return "com.ocient.jdbc.StPoint";
		}
		else if (type.equals("ST_LINESTRING"))
		{
			return "com.ocient.jdbc.StLinestring";
		}
		else if (type.equals("ST_POLYGON"))
		{
			return "com.ocient.jdbc.StPolygon";
		}
		else if (type.equals("IP") || type.equals("IPV4"))
		{
			return "java.net.InetAddress";
		}
		else
		{
			LOGGER.log(Level.WARNING, "getColumnClassName() is throwing UNKNOWN_DATA_TYPE");
			throw SQLStates.UNKNOWN_DATA_TYPE.clone();
		}
	}

	@Override
	public int getColumnCount() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnCount()");
		return cols2Pos.size();
	}

	@Override
	public int getColumnDisplaySize(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnDisplaySize()");
		final String name = pos2Cols.get(column - 1);
		final String type = cols2Types.get(name);
		int retval = 0;

		if (type.equals("BYTE"))
		{
			retval = 4;
		}
		else if (type.equals("SHORT"))
		{
			retval = 6;
		}
		else if (type.equals("INT"))
		{
			retval = 11;
		}
		else if (type.equals("LONG"))
		{
			retval = 20;
		}
		else if (type.equals("FLOAT"))
		{
			retval = 14;
		}
		else if (type.equals("DOUBLE"))
		{
			retval = 22;
		}
		else if (type.equals("TIMESTAMP"))
		{
			retval = 29;
		}
		else if (type.equals("TIME"))
		{
			retval = 13; // HH:MM:SS.mmm
		}
		else if (type.equals("DATE"))
		{
			retval = 11;
		}
		else if (type.equals("CHAR"))
		{
			retval = 45;
		}
		else if (type.equals("BOOLEAN"))
		{
			retval = 6;
		}
		else if (type.equals("BINARY"))
		{
			retval = 33;
		}
		else if (type.equals("DECIMAL"))
		{
			retval = 33; // max precision + '.' + "-"
		}
		else if (type.equals("ARRAY"))
		{
			retval = 80;
		}
		else if (type.equals("UUID"))
		{
			return 37;
		}
		else if (type.equals("ST_POINT"))
		{
			return 47;
		}
		else if (type.equals("ST_LINESTRING"))
		{
			return 47;
		}
		else if (type.equals("ST_POLYGON"))
		{
			return 47;
		}
		else if (type.equals("IP"))
		{
			return 47;
		}
		else if (type.equals("IPV4"))
		{
			return 17;
		}
		else if(type.equals("TUPLE"))
		{
			retval = 80;
		}
		else
		{
			LOGGER.log(Level.WARNING, "getColumnDisplaySize() is throwing UNKNOWN_DATA_TYPE");
			throw SQLStates.UNKNOWN_DATA_TYPE.clone();
		}

		if (retval < name.length())
		{
			retval = name.length();
		}

		return retval;
	}

	@Override
	public String getColumnLabel(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnLabel()");
		return pos2Cols.get(column - 1);
	}

	@Override
	public String getColumnName(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnName()");
		return pos2Cols.get(column - 1);
	}

	@Override
	public int getColumnType(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnType()");
		final String name = pos2Cols.get(column - 1);
		final String type = cols2Types.get(name);

		if (type.equals("CHAR"))
		{
			return java.sql.Types.VARCHAR;
		}
		else if (type.equals("BYTE"))
		{
			return java.sql.Types.TINYINT;
		}
		else if (type.equals("SHORT"))
		{
			return java.sql.Types.SMALLINT;
		}
		else if (type.equals("INT"))
		{
			return java.sql.Types.INTEGER;
		}
		else if (type.equals("FLOAT"))
		{
			return java.sql.Types.FLOAT;
		}
		else if (type.equals("DOUBLE"))
		{
			return java.sql.Types.DOUBLE;
		}
		else if (type.equals("LONG"))
		{
			return java.sql.Types.BIGINT;
		}
		else if (type.equals("TIMESTAMP"))
		{
			return java.sql.Types.TIMESTAMP;
		}
		else if (type.equals("TIME"))
		{
			return java.sql.Types.TIME;
		}
		else if (type.equals("DATE"))
		{
			return java.sql.Types.DATE;
		}
		else if (type.equals("BOOLEAN"))
		{
			return java.sql.Types.BOOLEAN;
		}
		else if (type.equals("BINARY"))
		{
			return java.sql.Types.BINARY;
		}
		else if (type.equals("DECIMAL"))
		{
			return java.sql.Types.DECIMAL;
		}
		else if (type.equals("ARRAY"))
		{
			return java.sql.Types.ARRAY;
		}
		else if (type.equals("UUID"))
		{
			return java.sql.Types.OTHER;
		}
		else if (type.equals("ST_POINT"))
		{
			return java.sql.Types.OTHER;
		}
		else if (type.equals("ST_LINESTRING"))
		{
			return java.sql.Types.OTHER;
		}
		else if (type.equals("ST_POLYGON"))
		{
			return java.sql.Types.OTHER;
		}
		else if (type.equals("IP") || type.equals("IPV4"))
		{
			return java.sql.Types.OTHER;
		}
		else if(type.equals("TUPLE"))
		{
			return java.sql.Types.STRUCT;
		}
		else
		{
			LOGGER.log(Level.WARNING, "getColumnType() is throwing UNKNOWN_DATA_TYPE");
			throw SQLStates.UNKNOWN_DATA_TYPE.clone();
		}
	}

	@Override
	public String getColumnTypeName(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getColumnTypeName()");
		return cols2Types.get(pos2Cols.get(column - 1));
	}

	public int getPosition(final String name) throws Exception
	{
		LOGGER.log(Level.INFO, "Called getPosition()");
		Integer retval = cols2Pos.get(name);
		if (retval == null)
		{
			retval = caseInsensitiveCols2Pos.get(name.toLowerCase());
		}

		return retval;
	}

	@Override
	public int getPrecision(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getPrecision()");
		final String name = pos2Cols.get(column - 1);
		final String type = cols2Types.get(name);

		if (type.equals("CHAR"))
		{
			return 128 * 1024;
		}
		else if (type.equals("BYTE"))
		{
			return 3;
		}
		else if (type.equals("SHORT"))
		{
			return 5;
		}
		else if (type.equals("INT"))
		{
			return 10;
		}
		else if (type.equals("FLOAT"))
		{
			return 7;
		}
		else if (type.equals("DOUBLE"))
		{
			return 16;
		}
		else if (type.equals("LONG"))
		{
			return 20;
		}
		else if (type.equals("TIMESTAMP"))
		{
			return 23;
		}
		else if (type.equals("TIME"))
		{
			return 12;
		}
		else if (type.equals("DATE"))
		{
			return 10;
		}
		else if (type.equals("BOOLEAN"))
		{
			return 0;
		}
		else if (type.equals("BINARY"))
		{
			return 128 * 1024;
		}
		else if (type.equals("DECIMAL"))
		{
			return 31;
		}
		else if (type.equals("ARRAY"))
		{
			return 128 * 1024;
		}
		else if (type.equals("TUPLE"))
		{
			return 128 * 1024;
		}
		else if (type.equals("UUID"))
		{
			return 16;
		}
		else if (type.equals("ST_POINT"))
		{
			return 32;
		}
		else if (type.equals("ST_LINESTRING"))
		{
			return 32;
		}
		else if (type.equals("ST_POLYGON"))
		{
			return 32;
		}
		else if (type.equals("IP"))
		{
			return 16;
		}
		else if (type.equals("IPV4"))
		{
			return 12;
		}
		else
		{
			LOGGER.log(Level.WARNING, "getPrecision() is throwing UNKNOWN_DATA_TYPE");
			throw SQLStates.UNKNOWN_DATA_TYPE.clone();
		}
	}

	@Override
	public int getScale(final int column) throws SQLException
	{
		LOGGER.log(Level.WARNING, "Called getScale()");
		return 0;
	}

	@Override
	public String getSchemaName(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSchemaName()");
		return "";
	}

	@Override
	public String getTableName(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getTableName()");
		return "";
	}

	@Override
	public boolean isAutoIncrement(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isAutoIncrement()");
		return false;
	}

	@Override
	public boolean isCaseSensitive(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isCaseSensitive()");
		return true;
	}

	@Override
	public boolean isCurrency(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isCurrency()");
		return false;
	}

	@Override
	public boolean isDefinitelyWritable(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isDefinitelyWritable()");
		return false;
	}

	@Override
	public int isNullable(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isNullable()");
		return ResultSetMetaData.columnNullableUnknown;
	}

	@Override
	public boolean isReadOnly(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isReadOnly()");
		return true;
	}

	@Override
	public boolean isSearchable(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isSearchable()");
		return true;
	}

	@Override
	public boolean isSigned(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isSigned()");
		return true;
	}

	@Override
	public boolean isWrapperFor(final Class<?> iface) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isWrapperFor()");
		return false;
	}

	@Override
	public boolean isWritable(final int column) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isWritable()");
		return false;
	}

	private void setCaseInsensitiveCols2Pos()
	{
		caseInsensitiveCols2Pos = new HashMap<>();

		for (final Map.Entry<String, Integer> entry : cols2Pos.entrySet())
		{
			caseInsensitiveCols2Pos.put(entry.getKey().toLowerCase(), entry.getValue());
		}
	}

	@Override
	public String toString()
	{
		LOGGER.log(Level.INFO, "Called toString()");
		return "Position -> column = " + pos2Cols + "\nColumn -> type = " + cols2Types;
	}

	@Override
	public <T> T unwrap(final Class<T> iface) throws SQLException
	{
		LOGGER.log(Level.WARNING, "unwrap() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	static String type2Name(byte type) throws SQLException
	{
		switch (type)
		{
			case 1:
				return "INTEGER";
			case 2:
				return "BIGINT";
			case 3:
				return "FLOAT";
			case 4:
				return "DOUBLE";
			case 5:
				return "VARCHAR";
			case 6:
				return "TIMESTAMP";
			case 7:
				return "NULL";
			case 8:
				return "BOOLEAN";
			case 9:
				return "VARBINARY";
			case 10:
				return "BYTE";
			case 11:
				return "SMALLINT";
			case 12:
				return "TIME";
			case 13:
				return "DECIMAL";
			case 14:
				return "ARRAY";
			case 15:
				return "UUID";
			case 16:
				return "ST_POINT";
			case 17:
				return "IP";
			case 18:
				return "IPV4";
			case 19:
				return "DATE";
			case 20:
				return "TIMESTAMP";
			case 21:
				return "TIME";
			case 22:
				return "TUPLE";
			case 23:
				return "ST_LINESTRING";
			case 24:
				return "ST_POLYGON";
			default:
				throw SQLStates.INVALID_COLUMN_TYPE.clone();
		}
	}
}
