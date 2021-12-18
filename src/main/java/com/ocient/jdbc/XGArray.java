package com.ocient.jdbc;

import com.ocient.jdbc.XGByteArrayHelper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class XGArray implements java.sql.Array
{

	private final byte type;
	private Object[] array;

	private final XGConnection conn;

	private final XGStatement stmt;

	public XGArray(final int numElements, final byte type, final XGConnection conn, final XGStatement stmt)
	{
		this.type = type;
		this.conn = conn;
		this.stmt = stmt;
		array = new Object[numElements];
	}

	public void add(final Object obj, final int pos)
	{
		array[pos] = obj;
	}

	@Override
	public void free() throws SQLException
	{
		array = new Object[0];
	}

	@Override
	public Object getArray() throws SQLException
	{
		Object arrayCopy = array;
		return arrayCopy;
	}

	@Override
	public Object getArray(final long index, final int count) throws SQLException
	{
		try
		{
			return Arrays.copyOfRange(array, (int) index - 1, (int) index + count - 1);
		}
		catch (final Exception e)
		{
			throw SQLStates.newGenericException(e);
		}
	}

	@Override
	public Object getArray(final long index, final int count, final Map<String, Class<?>> map) throws SQLException
	{
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Object getArray(final Map<String, Class<?>> map) throws SQLException
	{
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public int getBaseType() throws SQLException
	{
		switch (type)
		{
			case 1:
				return Types.INTEGER;
			case 2:
				return Types.BIGINT;
			case 3:
				return Types.FLOAT;
			case 4:
				return Types.DOUBLE;
			case 5:
				return Types.VARCHAR;
			case 6:
				return Types.TIMESTAMP;
			case 7:
				return Types.NULL;
			case 8:
				return Types.BOOLEAN;
			case 9:
				return Types.VARBINARY;
			case 10:
				return Types.TINYINT;
			case 11:
				return Types.SMALLINT;
			case 12:
				return Types.TIME;
			case 13:
				return Types.DECIMAL;
			case 14:
				return Types.ARRAY;
			case 15:
			case 16:
			case 17:
			case 18:
				return Types.OTHER;
			case 19:
				return Types.DATE;
			case 20:
				return Types.TIMESTAMP;
			case 21:
				return Types.TIME;
			case 22:
				return Types.STRUCT;
			case 23:
			case 24:
				return Types.OTHER;
			default:
				throw SQLStates.INVALID_COLUMN_TYPE.clone();
		}
	}

	@Override
	public String getBaseTypeName() throws SQLException
	{
		return XGResultSetMetaData.type2Name(type);
	}

	@Override
	public ResultSet getResultSet() throws SQLException
	{
		final ArrayList<Object> alo = new ArrayList<>();
		int i = 1;
		for (final Object o : array)
		{
			final ArrayList<Object> row = new ArrayList<>();
			row.add(i++);
			row.add(o);
			alo.add(row);
		}

		final XGResultSet retval = new XGResultSet(conn, alo, stmt);
		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("index", 0);
		cols2Pos.put("array_value", 1);
		pos2Cols.put(0, "index");
		pos2Cols.put(1, "array_value");
		cols2Types.put("index", "INT");

		cols2Types.put("array_value", XGResultSetMetaData.type2Name(type));
		
		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getResultSet(final long index, final int count) throws SQLException
	{
		final ArrayList<Object> alo = new ArrayList<>();
		for (int i = (int) index; i < index + count; i++)
		{
			final ArrayList<Object> row = new ArrayList<>();
			row.add(i);
			row.add(array[i]);
			alo.add(row);
		}

		final XGResultSet retval = new XGResultSet(conn, alo, stmt);
		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
		cols2Pos.put("index", 0);
		cols2Pos.put("array_value", 1);
		pos2Cols.put(0, "index");
		pos2Cols.put(1, "array_value");
		cols2Types.put("index", "INT");

		cols2Types.put("array_value", XGResultSetMetaData.type2Name(type));

		retval.setCols2Pos(cols2Pos);
		retval.setPos2Cols(pos2Cols);
		retval.setCols2Types(cols2Types);
		return retval;
	}

	@Override
	public ResultSet getResultSet(final long index, final int count, final Map<String, Class<?>> map) throws SQLException
	{
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public ResultSet getResultSet(final Map<String, Class<?>> map) throws SQLException
	{
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public String toString()
	{
		try
		{
			final StringBuilder str = new StringBuilder();
			str.append("[");

			if (array.length > 0)
			{
				final Object o = array[0];
				if (o == null)
				{
					str.append("NULL");
				}
				else if (getBaseType() == java.sql.Types.ARRAY)
				{
					str.append(((XGArray) o).toString());
				}
				else if (getBaseType() == java.sql.Types.BINARY || getBaseType() == java.sql.Types.VARBINARY)
				{
					str.append("0x" + XGByteArrayHelper.bytesToHex((byte[]) o));
				}
				else
				{
					str.append(o);
				}
			}

			for (int i = 1; i < array.length; i++)
			{
				str.append(", ");
				final Object o = array[i];
				if (o == null)
				{
					str.append("NULL");
				}
				else if (getBaseType() == java.sql.Types.ARRAY)
				{
					str.append(((XGArray) o).toString());
				}
				else if (getBaseType() == java.sql.Types.BINARY || getBaseType() == java.sql.Types.VARBINARY)
				{
					str.append("0x" + XGByteArrayHelper.bytesToHex((byte[]) o));
				}
				else
				{
					str.append(o);
				}
			}

			str.append("]");
			return str.toString();
		}
		catch (final Exception e)
		{
			return "Exception occurred accessing Array";
		}
	}
}
