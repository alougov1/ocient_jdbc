package com.ocient.jdbc;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.InetAddress;
import java.net.URL;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.common.base.Charsets;
import com.google.protobuf.ByteString;
import com.ocient.jdbc.proto.ClientWireProtocol;
import com.ocient.jdbc.proto.ClientWireProtocol.AttachToQuery;
import com.ocient.jdbc.proto.ClientWireProtocol.CloseResultSet;
import com.ocient.jdbc.proto.ClientWireProtocol.ConfirmationResponse;
import com.ocient.jdbc.proto.ClientWireProtocol.ConfirmationResponse.ResponseType;
import com.ocient.jdbc.proto.ClientWireProtocol.FetchData;
import com.ocient.jdbc.proto.ClientWireProtocol.FetchMetadata;
import com.ocient.jdbc.proto.ClientWireProtocol.Request;

public final class XGResultSet implements ResultSet
{

	public class SecondaryResultSetThread implements Runnable
	{
		@Override
		public void run()
		{
			XGConnection newConn = null;
			try
			{
				LOGGER.log(Level.INFO, "Started secondary result set thread");
				newConn = conn.copy(false, true);
				final String queryId = getQueryId().get();
				attachToQuery(newConn, queryId);

				// First fetch has to come from main thread
				while (!didFirstFetch.get() && !cacheLimitBreak.get())
				{
					Thread.sleep(1);
				}

				LOGGER.log(Level.INFO, "Calling getMoreData() on secondary result set thread");
				getMoreData(newConn);
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred in SecondaryResultSetThread with message %s", e.toString(), e.getMessage()));
			}

			try
			{
				if (newConn != null)
				{
					newConn.close();
					LOGGER.log(Level.INFO, "Closed connection for secondary result set thread");
				}

			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, "Secondary fetch thread failed to close");
			}
		}
	}

	/*
	* The main result set thread is responsible for handling the case of the special cache limit warning.
	* First all the secondary threads are cleaned up.
	* We will fetch a statement from the statement cache. Then, we will swap the connections
	* of the statement retrieved from the cache and that of the user statement. Then this thread
	* will continue to fetch until we receive a DEM or an error. The purpose of this continued fetching 
	* is to occupy the connection so that the driver does not use it, because the corresponding
	* connection on the server side is still running a query.
	*/
	public class XGResultSetThread implements Runnable
	{
		@Override
		public void run()
		{
			getMoreData();

			// Check for the special cache time limit hit.
			if(cacheLimitBreak.get()){

				// First, collect all the secondary fetch threads. Which should have returned by now.
				LOGGER.log(Level.INFO, String.format("Now cleaning up secondary threads of size: %d", fetchThreads.size() - 1));
				try
				{
					for (final Thread t : fetchThreads)
					{
						if (!t.equals(Thread.currentThread()))
						{
							t.join();
						}
					}
				} catch(final Exception e){
					LOGGER.log(Level.WARNING, "ERROR: Failed to join secondary fetch threads");
				}

				LOGGER.log(Level.INFO, "First cache timeout limit hit. Asynchrnously finishing fetch on main resultSetThread.");
				try
				{
					XGStatement cachedOrNewStatement = XGStatement.newXGStatement(conn, false);

					// Take the old connection. It will be used to finish the fetch.
					XGConnection oldConn = conn;
					// Give the userstatement the new connection.
					stmt.conn = cachedOrNewStatement.conn;

					cachedOrNewStatement.conn = null;
					cachedOrNewStatement.result = null;

					// Very important step. So that if resultSet.close() gets called, it won't close the old connection.
					conn = stmt.conn;
					// It must be at this point, after we've replaced the statement exception, do we fill the result set with the cacheLimitException.
					final ArrayList<Object> alo = new ArrayList<>();
					alo.add(cacheLimitException);
					rsQueue.put(alo);

					// The daemon thread will finish the fetch and return the statement to the cache.
					Thread daemonThread = new Thread(new daemonFinishFetchThread(cachedOrNewStatement, oldConn));
					daemonThread.setDaemon(true);
					daemonThread.start();
				}
				catch(RuntimeException e)
				{
					LOGGER.log(Level.WARNING, "Unable to create new statement in order to finish fetching result set due to cache time limit hit");
				}
				catch(final Exception e)
				{
					LOGGER.log(Level.WARNING, "Unable to create new statement in order to finish fetching result set due to cache time limit hit");
				}
			}
		}
	}

	private static final Logger LOGGER = Logger.getLogger("com.ocient.jdbc");

	private static int bytesToInt(final byte[] val)
	{
		final int ret = java.nio.ByteBuffer.wrap(val).getInt();
		return ret;
	}

	private static byte[] intToBytes(final int val)
	{
		final byte[] buff = new byte[4];
		buff[0] = (byte) (val >> 24);
		buff[1] = (byte) ((val & 0x00FF0000) >> 16);
		buff[2] = (byte) ((val & 0x0000FF00) >> 8);
		buff[3] = (byte) (val & 0x000000FF);
		return buff;
	}

	// It is assumed the vendor codes never change. At this time, the code is 1 for special cache warning.
	private static int CACHE_LIMIT_WARNING_CODE = 1;
	private ArrayList<Object> rs = null;
	private long firstRowIs = 0;
	private long position = -1;
	private boolean closed = false;
	private XGConnection conn;
	private int fetchSize;
	private boolean wasNull = false;
	private Map<String, Integer> cols2Pos;
	private Map<String, Integer> caseInsensitiveCols2Pos;
	private TreeMap<Integer, String> pos2Cols;
	private Map<String, String> cols2Types;

	// tell whether the resultset was constructed with a pre-defined dataset.
	private boolean immutable = false;

	private final XGStatement stmt;

	private final ArrayList<SQLWarning> warnings = new ArrayList<>();

	private final LinkedBlockingQueue<ArrayList<Object>> rsQueue = new LinkedBlockingQueue<>(64);

	private final ArrayList<Thread> fetchThreads = new ArrayList<>();

	private final AtomicBoolean didFirstFetch = new AtomicBoolean(false);
	private final AtomicBoolean demReceived = new AtomicBoolean(false);

	// Whether we hit the first cache break and need to do an asynchronous fetch until resultSet is finished.
	private final AtomicBoolean cacheLimitBreak = new AtomicBoolean(false);
	private SQLException cacheLimitException;

	public XGResultSet(final XGConnection conn, final ArrayList<Object> rs, final XGStatement stmt)
	{
		this.conn = conn;
		this.rs = rs;
		this.stmt = stmt;
		this.rs.add(new DataEndMarker());
		immutable = true;
	}

	public XGResultSet(final XGConnection conn, final int fetchSize, final XGStatement stmt) throws Exception
	{
		this.conn = conn;
		this.fetchSize = fetchSize;
		this.stmt = stmt;
		requestMetaData();
		final Thread t = new Thread(new XGResultSetThread());
		fetchThreads.add(t);
		t.start();
	}

	public XGResultSet(final XGConnection conn, final int fetchSize, final XGStatement stmt, final ClientWireProtocol.ResultSet re) throws Exception
	{
		this.conn = conn;
		this.fetchSize = fetchSize;
		this.stmt = stmt;
		requestMetaData();
		mergeData(re);
	}

	public XGResultSet(final XGConnection conn, final int fetchSize, final XGStatement stmt, final int numClientThreads) throws Exception
	{
		this.conn = conn;
		this.fetchSize = fetchSize;
		this.stmt = stmt;
		requestMetaData();
		Thread t = new Thread(new XGResultSetThread());
		fetchThreads.add(t);
		// Add the threads first.
		for (int i = 1; i < numClientThreads; i++)
		{
			t = new Thread(new SecondaryResultSetThread());
			fetchThreads.add(t);
		}
		// Then start them
		for (final Thread thr : fetchThreads)
		{
			thr.start();
		}
	}

	@Override
	public boolean absolute(final int row) throws SQLException
	{
		LOGGER.log(Level.WARNING, "absolute() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	public void addWarnings(final ArrayList<SQLWarning> ws)
	{
		warnings.addAll(ws);
	}

	public void addWarnings(final SQLWarning w)
	{
		warnings.add(w);
	}

	@Override
	public void afterLast() throws SQLException
	{
		LOGGER.log(Level.WARNING, "afterLast() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	/*
	 * Attach a secondary result set fetch thread to a query
	 */
	private void attachToQuery(final XGConnection newConn, final String queryId) throws Exception
	{
		stmt.passUpCancel(false);

		final ClientWireProtocol.AttachToQuery.Builder builder = ClientWireProtocol.AttachToQuery.newBuilder();
		builder.setQueryId(queryId);
		final AttachToQuery msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.ATTACH_TO_QUERY);
		b2.setAttachToQuery(msg);
		final Request wrapper = b2.build();

		newConn.out.write(intToBytes(wrapper.getSerializedSize()));
		wrapper.writeTo(newConn.out);
		newConn.out.flush();
		getStandardResponse(newConn);
	}

	private int bcdLength(final int precision)
	{
		// translated from C++
		int bytesNeeded = (precision + 1) / 2;
		if (precision % 2 == 0)
		{
			bytesNeeded += 1;
		}
		return bytesNeeded;
	}

	@Override
	public void beforeFirst() throws SQLException
	{
		LOGGER.log(Level.WARNING, "beforeFirst() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void cancelRowUpdates() throws SQLException
	{
		LOGGER.log(Level.WARNING, "cancelRowUpdates() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void clearWarnings() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called clearWarnings()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "clearWarnings() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		warnings.clear();
	}

	@Override
	public void close() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called close()");
		if (closed)
		{
			return;
		}

		stmt.cancel();

		/* If we got the special break, we CANNOT allow these threads to be interrupted.
		 * If the user calls resultSet.close(), and we allow these threads to be interrupted,
		 * the the socket on the main thread will be closed. The asynchronous fetch query
		 * is still being finished on the server side. We must take great care to make sure
		 * these threads are cleaned in the case of asynchronous finish fetch.
		 */
		
		if(!cacheLimitBreak.get()){
			for (final Thread t : fetchThreads)
			{
				t.interrupt();
			}
	
			for (final Thread t : fetchThreads)
			{
				while (true)
				{
					try
					{
						t.join();
						break;
					}
					catch (final Exception e)
					{
					}
				}
			}
		}

		try
		{
			closed = true;
			sendCloseRS();
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during close() with message %s", e.toString(), e.getMessage()));
			throw SQLStates.newGenericException(e);
		}

		stmt.setQueryCancelled(false);
	}

	@Override
	public void deleteRow() throws SQLException
	{
		LOGGER.log(Level.WARNING, "cancelRowUpdates() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public int findColumn(final String columnLabel) throws SQLException
	{
		if (closed)
		{
			LOGGER.log(Level.WARNING, "findColumn() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("findColumn() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return pos + 1;
	}

	@Override
	public boolean first() throws SQLException
	{
		LOGGER.log(Level.WARNING, "first() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Array getArray(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getArray() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getArray() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getArray() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (!(col instanceof XGArray))
		{
			LOGGER.log(Level.WARNING, "getArray() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return (XGArray) col;
	}

	@Override
	public Array getArray(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getArray() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getArray(pos + 1);
	}

	private XGArray getArrayFromBuffer(final ByteBuffer bb, final int[] offset) throws SQLException
	{
		// Get the rest of the type info
		int nestedLevel = 0;
		byte type = 0;

		do
		{
			nestedLevel++;
			type = bb.get(offset[0]);
			offset[0]++;
		}
		while (type == 14);

		try
		{
			return getArrayInternals(bb, offset, nestedLevel, type);
		}
		catch (final java.net.UnknownHostException e)
		{
			throw SQLStates.newGenericException(e);
		}
	}

	private XGArray getArrayInternals(final ByteBuffer bb, final int[] offset, int nestedLevel, final byte type) throws SQLException, java.net.UnknownHostException
	{
		// Get number of elements in the array
		final int numElements = bb.getInt(offset[0]);

		offset[0] += 4;
		nestedLevel--;

		final byte nullByte = bb.get(offset[0]);
		offset[0]++;

		final boolean isEntirelyNull = nullByte != 0;
		if (isEntirelyNull)
		{
			assert numElements == 0;
			return null;
		}

		// Make return value
		XGArray retval = null;

		// Recurse if needed
		if (nestedLevel > 0)
		{
			retval = new XGArray(numElements, (byte) 14, conn, stmt);
			for (int i = 0; i < numElements; i++)
			{
				retval.add(getArrayInternals(bb, offset, nestedLevel, type), i);
			}
		}
		else
		{
			retval = new XGArray(numElements, type, conn, stmt);
			for (int i = 0; i < numElements; i++)
			{
				final byte t = bb.get(offset[0]);
				offset[0]++;
				assert t == type || t == 7; // Array type or NULL
				Boolean allowArrays = false;
				retval.add(getValueFromBuffer(bb, t, offset, allowArrays), i);
			}
		}

		return retval;
	}

	@Override
	public InputStream getAsciiStream(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public InputStream getAsciiStream(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public BigDecimal getBigDecimal(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getBigDecimal() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getBigDecimal() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getBigDecimal() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (!(col instanceof Byte || col instanceof Integer || col instanceof Short || col instanceof Long || col instanceof Float || col instanceof Double || col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getBigDecimal() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		final BigDecimal retval = new BigDecimal(num.doubleValue());
		return retval;
	}

	@Override
	public BigDecimal getBigDecimal(final int columnIndex, final int scale) throws SQLException
	{
		BigDecimal retval = getBigDecimal(columnIndex);
		retval = retval.setScale(scale, RoundingMode.HALF_UP);
		return retval;
	}

	@Override
	public BigDecimal getBigDecimal(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getBigDecimal() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getBigDecimal(pos + 1);
	}

	@Override
	public BigDecimal getBigDecimal(final String columnLabel, final int scale) throws SQLException
	{
		BigDecimal retval = getBigDecimal(columnLabel);
		retval = retval.setScale(scale, RoundingMode.HALF_UP);
		return retval;
	}

	@Override
	public InputStream getBinaryStream(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public InputStream getBinaryStream(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Blob getBlob(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Blob getBlob(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean getBoolean(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getBoolean() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getBoolean() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getBoolean() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return false;
		}

		if (!(col instanceof Boolean))
		{
			LOGGER.log(Level.WARNING, "getBoolean() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return (Boolean) col;
	}

	@Override
	public boolean getBoolean(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getBoolean() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getBoolean(pos + 1);
	}

	@Override
	public byte getByte(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getByte() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getByte() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getByte() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return 0;
		}

		if (!(col instanceof Byte) && !(col instanceof Short) && !(col instanceof Integer) && !(col instanceof Long) && !(col instanceof Float) && !(col instanceof Double)
			&& !(col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getByte() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		return num.byteValue();
	}

	@Override
	public byte getByte(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getByte() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getByte(pos + 1);
	}

	@Override
	public byte[] getBytes(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getBytes() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getBytes() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getBytes() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (!(col instanceof byte[]))
		{
			LOGGER.log(Level.WARNING, "getBytes() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return (byte[]) col;
	}

	@Override
	public byte[] getBytes(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getBytes() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getBytes(pos + 1);
	}

	@Override
	public Reader getCharacterStream(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Reader getCharacterStream(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Clob getClob(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Clob getClob(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public int getConcurrency() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getConcurrency()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getConcurrency() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return ResultSet.CONCUR_READ_ONLY;
	}

	@Override
	public String getCursorName() throws SQLException
	{
		LOGGER.log(Level.WARNING, "getCursorName() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Date getDate(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (col instanceof XGTimestamp)
		{
			return new XGDate((XGTimestamp) col);
		}

		if (!(col instanceof XGDate))
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return (XGDate) col;
	}

	@Override
	public Date getDate(final int columnIndex, final Calendar cal) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (col instanceof XGTimestamp)
		{
			return new XGDate((XGTimestamp) col);
		}

		if (!(col instanceof XGDate))
		{
			LOGGER.log(Level.WARNING, "getDate() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return (XGDate) col;
	}

	@Override
	public Date getDate(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getDate() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getDate(pos + 1);
	}

	@Override
	public Date getDate(final String columnLabel, final Calendar cal) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getDate() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getDate(pos + 1, cal);
	}

	private BigDecimal getDecimalFromBuffer(final ByteBuffer bb, int offset)
	{
		// translated from C++

		// read off parameters
		final int precision = bb.get(offset);
		offset += 1;
		final int scale = bb.get(offset);
		offset += 1;

		// read raw data
		final int bytesNeeded = bcdLength(precision);
		final byte[] rawPackedBcdData = new byte[bytesNeeded];
		((Buffer) bb).position(offset);
		bb.get(rawPackedBcdData);

		// translate BCD -> character array of numerals
		// leave room for the sign character, but don't bother dealing with scale and
		// decimal point here
		final char[] formedDecimalString = new char[precision + 1];

		// sign character
		final boolean isPositive = (rawPackedBcdData[bytesNeeded - 1] & 0x0f) == 0x0c;
		formedDecimalString[0] = isPositive ? '+' : '-';

		// set up starting indices for reading digits out
		int theByte = 0;
		boolean highOrder = precision % 2 != 0; // first high-order nibble might be filler

		// read digits from nibbles
		for (int i = 0; i < precision; i++)
		{
			char digit = '0';
			final int byteVal = rawPackedBcdData[theByte] & 0xFF;
			if (highOrder)
			{
				digit += byteVal >> 4;
			}
			else
			{
				digit += byteVal & 0x0f;
			}
			formedDecimalString[1 + i] = digit;

			// increment reading indices
			if (highOrder)
			{
				highOrder = false;
			}
			else
			{
				theByte++;
				highOrder = true;
			}
		}

		// set scale now, right at the end
		return new BigDecimal(formedDecimalString).movePointLeft(scale);
	}

	@Override
	public double getDouble(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getDouble() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getDouble() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getDouble() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return 0;
		}
		if (!(col instanceof Byte || col instanceof Integer || col instanceof Short || col instanceof Long || col instanceof Float || col instanceof Double || col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getDouble() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		return num.doubleValue();
	}

	@Override
	public double getDouble(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getDouble() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getDouble(pos + 1);
	}

	public ArrayList<Object> getEntireRow() throws SQLException
	{
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getEntireRow() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getEntireRow() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		return (ArrayList<Object>) row;
	}

	@Override
	public int getFetchDirection() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getFetchDirection()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getFetchDirection() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return ResultSet.FETCH_FORWARD;
	}

	@Override
	public int getFetchSize() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getFetchSize()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getFetchSize() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return fetchSize;
	}

	@Override
	public float getFloat(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getFloat() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getFloat() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getFloat() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return 0;
		}

		if (!(col instanceof Byte || col instanceof Integer || col instanceof Short || col instanceof Long || col instanceof Float || col instanceof Double || col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getFloat() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		return num.floatValue();
	}

	@Override
	public float getFloat(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getFloat() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getFloat(pos + 1);
	}

	@Override
	public int getHoldability() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getHoldability()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getHoldability() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return ResultSet.CLOSE_CURSORS_AT_COMMIT;
	}

	@Override
	public int getInt(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getInt() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getInt() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getInt() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return 0;
		}
		if (!(col instanceof Byte || col instanceof Integer || col instanceof Short || col instanceof Long || col instanceof Float || col instanceof Double || col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getInt() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		return num.intValue();
	}

	@Override
	public int getInt(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getInt() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getInt(pos + 1);
	}

	private int getLength() throws Exception
	{
		return getLength(conn);
	}

	private int getLength(final XGConnection newConn) throws Exception
	{
		final byte[] inMsg = new byte[4];

		int count = 0;
		while (count < 4)
		{
			try
			{
				final int temp = newConn.in.read(inMsg, count, 4 - count);
				if (temp == -1)
				{
					throw SQLStates.UNEXPECTED_EOF.clone();
				}

				count += temp;
			} catch(RuntimeException e)
			{
				throw e;
			}
			catch (final Exception e)
			{
				throw SQLStates.NETWORK_COMMS_ERROR.clone();
			}
		}

		return bytesToInt(inMsg);
	}

	@Override
	public long getLong(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getLong() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getLong() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getLong() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return 0;
		}

		if (!(col instanceof Byte || col instanceof Integer || col instanceof Short || col instanceof Long || col instanceof Float || col instanceof Double || col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getLong() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		return num.longValue();
	}

	@Override
	public long getLong(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getLong() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getLong(pos + 1);
	}

	@Override
	public ResultSetMetaData getMetaData() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMetaData()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getMetaData() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		try
		{
			return new XGResultSetMetaData(cols2Pos, pos2Cols, cols2Types);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getMetaData() with message %s", e.toString(), e.getMessage()));

			throw SQLStates.newGenericException(e);
		}
		finally
		{
			stmt.passUpCancel(true);
		}
	}

	private void getMoreData()
	{
		getMoreData(conn);
	}

	/*
	 * Fetch data from server, parse result sets, place on queue
	 */
	private void getMoreData(final XGConnection newConn)
	{
		if (immutable)
		{
			// no data to get as the resultset was prepopulate at construction time.
			return;
		}

		try
		{
			final Optional<String> queryId = getQueryId();
			stmt.passUpCancel(false);
			// send FetchData request with fetchSize parameter
			final ClientWireProtocol.FetchData.Builder builder = ClientWireProtocol.FetchData.newBuilder();
			builder.setFetchSize(fetchSize);
			final FetchData msg = builder.build();
			final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.FETCH_DATA);
			b2.setFetchData(msg);
			final Request wrapper = b2.build();

			stmt.startTask(() ->
			{
				while(true){
					if (demReceived.get())
					{
						return;
					} else if(cacheLimitBreak.get()){
						LOGGER.log(Level.WARNING, "Thread saw cacheLimitBreak. Exiting getMoreData");
						return;
					}
					newConn.out.write(intToBytes(wrapper.getSerializedSize()));
					wrapper.writeTo(newConn.out);
					newConn.out.flush();
	
					// Kind of ugly, but doesn't violate JMM (startTask() is synchronous)
					final ClientWireProtocol.FetchDataResponse.Builder fdr = ClientWireProtocol.FetchDataResponse.newBuilder();
	
					// get confirmation and data (fetchSize rows or zero size result set or
					// terminated early with a DataEndMarker)
					final int length = getLength(newConn);
					final byte[] data = new byte[length];
					readBytes(data, newConn);
					fdr.mergeFrom(data);
	
					final ConfirmationResponse response = fdr.getResponse();
					final ResponseType rType = response.getType();
					if(processResponseType(rType, response)){
						LOGGER.log(Level.INFO, "Got special cache limit warning.");
						// Flip the necessary flags to exit.
						cacheLimitBreak.compareAndSet(false,true);
						return;
					} 
					if (!mergeData(fdr.getResultSet()))
					{
						return;
					}
				}
			}, queryId, getTimeoutMillis());
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred while fetching data with message %s", e.toString(), e.getMessage()));
			if (e instanceof SQLException)
			{
				final ArrayList<Object> alo = new ArrayList<>();
				alo.add(e);
				try
				{
					rsQueue.put(alo);
				}
				catch (final InterruptedException f)
				{
					final ArrayList<Object> alo2 = new ArrayList<>();
					alo2.add(SQLStates.newGenericException(f));
					rsQueue.offer(alo2);
					return;
				}

				return;
			}

			if (e instanceof InterruptedException)
			{
				final ArrayList<Object> alo = new ArrayList<>();
				alo.add(SQLStates.newGenericException(e));
				rsQueue.offer(alo);
				return;
			}

			final ArrayList<Object> alo = new ArrayList<>();
			alo.add(SQLStates.newGenericException(e));
			try
			{
				rsQueue.put(alo);
			}
			catch (final InterruptedException f)
			{
				final ArrayList<Object> alo2 = new ArrayList<>();
				alo2.add(SQLStates.newGenericException(f));
				rsQueue.offer(alo2);
				return;
			}

			return;
		}
	}

	@Override
	public Reader getNCharacterStream(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getNCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Reader getNCharacterStream(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getNCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public NClob getNClob(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public NClob getNClob(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public String getNString(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getNString() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public String getNString(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getNString() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Object getObject(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);
		if (col == null)
		{
			wasNull = true;
			return col;
		}

		// Check type map
		final Class<?> clazz = conn.getTypeMap().get(cols2Types.get(pos2Cols.get(columnIndex - 1)));

		if (clazz == null)
		{
			return col;
		}

		if (clazz.getCanonicalName().equals("java.lang.String"))
		{
			return col.toString();
		}

		try
		{
			final Constructor<?> c = clazz.getConstructor(col.getClass());
			return c.newInstance(col);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getObject() with message %s", e.toString(), e.getMessage()));
			throw SQLStates.newGenericException(e);
		}
	}

	@Override
	public <T> T getObject(final int columnIndex, final Class<T> clazz) throws SQLException
	{
		wasNull = false;

		if (clazz == null)
		{
			throw new SQLException();
		}

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);
		if (col == null)
		{
			wasNull = true;
			return (T) col;
		}

		if (clazz.getCanonicalName().equals("java.lang.String"))
		{
			return (T) col.toString();
		}

		try
		{
			final Constructor<?> c = clazz.getConstructor(col.getClass());
			return (T) c.newInstance(col);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getObject() with message %s", e.toString(), e.getMessage()));
			throw SQLStates.newGenericException(e);
		}
	}

	@Override
	public Object getObject(final int columnIndex, final Map<String, Class<?>> map) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getObject() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);
		if (col == null)
		{
			wasNull = true;
			return col;
		}

		// Check type map
		final Class<?> clazz = map.get(cols2Types.get(pos2Cols.get(columnIndex - 1)));

		if (clazz == null)
		{
			return col;
		}

		if (clazz.getCanonicalName().equals("java.lang.String"))
		{
			return col.toString();
		}

		try
		{
			final Constructor<?> c = clazz.getConstructor(col.getClass());
			return c.newInstance(col);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getObject() with message %s", e.toString(), e.getMessage()));
			throw SQLStates.newGenericException(e);
		}
	}

	@Override
	public Object getObject(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getObject() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getObject(pos + 1);
	}

	@Override
	public <T> T getObject(final String columnLabel, final Class<T> type) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getObject() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getObject(pos + 1, type);
	}

	@Override
	public Object getObject(final String columnLabel, final Map<String, Class<?>> map) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getObject() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getObject(pos + 1, map);
	}

	private Optional<String> getQueryId()
	{
		// TODO The query id should be known when the result set is created (on
		// executeQuery())
		// but this would require some additional server side work, so we'll do this
		// hack
		// for now
		return stmt.getQueryId();
	}

	@Override
	public Ref getRef(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getRef() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Ref getRef(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getRef() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public int getRow() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getRow()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getRow() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (position == -1)
		{
			return 0;
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			return 0;
		}

		return (int) (position + 1);
	}

	@Override
	public RowId getRowId(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getRowId() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public RowId getRowId(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getRowId() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public short getShort(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getShort() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getShort() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getShort() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return 0;
		}

		if (!(col instanceof Byte) && !(col instanceof Short) && !(col instanceof Integer) && !(col instanceof Long) && !(col instanceof Float) && !(col instanceof Double)
			&& !(col instanceof BigDecimal))
		{
			LOGGER.log(Level.WARNING, "getShort() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		final Number num = (Number) col;
		return num.shortValue();
	}

	@Override
	public short getShort(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getShort() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getShort(pos + 1);
	}

	@Override
	public SQLXML getSQLXML(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getSQLXML() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public SQLXML getSQLXML(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getSQLXML() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	private void getStandardResponse() throws Exception
	{
		getStandardResponse(conn);
	}

	private void getStandardResponse(final XGConnection newConn) throws Exception
	{
		final int length = getLength(newConn);
		final byte[] data = new byte[length];
		readBytes(data, newConn);
		final ConfirmationResponse.Builder rBuild = ConfirmationResponse.newBuilder();
		rBuild.mergeFrom(data);
		final ResponseType rType = rBuild.getType();
		processResponseType(rType, rBuild.build());
	}

	@Override
	public Statement getStatement() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return stmt;
	}

	@Override
	public String getString(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getString() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getString() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getString() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (!(col instanceof String))
		{
			col = col.toString();
		}

		return (String) col;
	}

	@Override
	public String getString(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getString() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getString(pos + 1);
	}

	@Override
	public Time getTime(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (!(col instanceof XGTime))
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return (XGTime) col;
	}

	@Override
	public Time getTime(final int columnIndex, final Calendar cal) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (!(col instanceof XGTime))
		{
			LOGGER.log(Level.WARNING, "getTime() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return ((XGTime) col).addMs(cal.getTimeZone().getRawOffset());
	}

	@Override
	public Time getTime(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getTime() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getTime(pos + 1);
	}

	@Override
	public Time getTime(final String columnLabel, final Calendar cal) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getTime() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getTime(pos + 1, cal);
	}

	private long getTimeoutMillis()
	{
		return stmt.getQueryTimeoutMillis();
	}

	@Override
	public Timestamp getTimestamp(final int columnIndex) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (col instanceof XGTimestamp)
		{
			return (XGTimestamp) col;
		}

		if (!(col instanceof XGDate))
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return new XGTimestamp((XGDate) col);
	}

	@Override
	public Timestamp getTimestamp(final int columnIndex, final Calendar cal) throws SQLException
	{
		wasNull = false;

		if (closed)
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing CURSOR_NOT_ON_ROW");
			throw SQLStates.CURSOR_NOT_ON_ROW.clone();
		}

		final ArrayList<Object> alo = (ArrayList<Object>) row;

		if (columnIndex < 1 || columnIndex > alo.size())
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing COLUMN_NOT_FOUND");
			throw SQLStates.COLUMN_NOT_FOUND.clone();
		}

		final Object col = alo.get(columnIndex - 1);

		if (col == null)
		{
			wasNull = true;
			return null;
		}

		if (col instanceof XGTimestamp)
		{
			return ((XGTimestamp) col).addMs(cal.getTimeZone().getOffset(((XGTimestamp) col).getTime()));
		}

		if (!(col instanceof XGDate))
		{
			LOGGER.log(Level.WARNING, "getTimestamp() is throwing INVALID_DATA_TYPE_CONVERSION");
			throw SQLStates.INVALID_DATA_TYPE_CONVERSION.clone();
		}

		return new XGTimestamp((XGDate) col).addMs(cal.getTimeZone().getOffset(((XGDate) col).getTime()));
	}

	@Override
	public Timestamp getTimestamp(final String columnLabel) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getTimestamp() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getTimestamp(pos + 1);
	}

	@Override
	public Timestamp getTimestamp(final String columnLabel, final Calendar cal) throws SQLException
	{
		Integer pos = cols2Pos.get(columnLabel);
		if (pos == null)
		{
			pos = caseInsensitiveCols2Pos.get(columnLabel.toLowerCase());
			if (pos == null)
			{
				LOGGER.log(Level.WARNING, String.format("getTimestamp() is throwing COLUMN_NOT_FOUND, looking for %s", columnLabel));
				throw SQLStates.COLUMN_NOT_FOUND.clone();
			}
		}

		return getTimestamp(pos + 1, cal);
	}

	@Override
	public int getType() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getType()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getType() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return ResultSet.TYPE_FORWARD_ONLY;
	}

	@Override
	public InputStream getUnicodeStream(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getUnicodeStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public InputStream getUnicodeStream(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getUnicodeStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public URL getURL(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getURL() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public URL getURL(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "getURL() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public SQLWarning getWarnings() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getWarnings()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getWarnings() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (warnings.size() == 0)
		{
			return null;
		}

		final SQLWarning retval = warnings.get(0);
		SQLWarning current = retval;
		int i = 1;
		while (i < warnings.size())
		{
			current.setNextWarning(warnings.get(i));
			current = warnings.get(i);
			i++;
		}

		return retval;
	}

	@Override
	public void insertRow() throws SQLException
	{
		LOGGER.log(Level.WARNING, "insertRow() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean isAfterLast() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isAfterLast()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "isAfterLast() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (position == -1 && rs == null)
		{
			try
			{
				// handle possible interrupt and get a result set from the queue
				stmt.passUpCancel(false);
				stmt.setRunningQueryThread(Thread.currentThread());
				rs = rsQueue.take();

				if (rs.get(0) instanceof SQLException)
				{
					throw (SQLException) rs.get(0);
				}
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred while fetching data with message %s", e.toString(), e.getMessage()));
				if (e instanceof SQLException)
				{
					throw (SQLException) e;
				}

				throw SQLStates.newGenericException(e);
			}
			finally
			{
				stmt.setRunningQueryThread(null);
				stmt.passUpCancel(true);
			}
		}

		final Object row = rs.get(rs.size() - 1);
		if (!(row instanceof DataEndMarker))
		{
			return false;
		}

		if (position < firstRowIs + rs.size() - 1)
		{
			return false;
		}

		if (position > 0)
		{
			return true;
		}

		return false;
	}

	@Override
	public boolean isBeforeFirst() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isBeforeFirst()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "isBeforeFirst() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (position != -1)
		{
			return false;
		}

		if (rs == null)
		{
			try
			{
				// handle possible interrupt and get a result set from the queue
				stmt.passUpCancel(false);
				stmt.setRunningQueryThread(Thread.currentThread());
				rs = rsQueue.take();

				if (rs.get(0) instanceof SQLException)
				{
					throw (SQLException) rs.get(0);
				}
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred while fetching data with message %s", e.toString(), e.getMessage()));
				if (e instanceof SQLException)
				{
					throw (SQLException) e;
				}

				throw SQLStates.newGenericException(e);
			}
			finally
			{
				stmt.setRunningQueryThread(null);
				stmt.passUpCancel(true);
			}
		}

		final Object row = rs.get(0);
		if (row instanceof DataEndMarker)
		{
			return false;
		}

		return true;
	}

	private boolean isBufferDem(final ByteBuffer bb)
	{
		return bb.limit() > 8 && bb.get(8) == 0;
	}

	@Override
	public boolean isClosed() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isClosed()");
		if (closed)
		{
			LOGGER.log(Level.INFO, "Returning true from isClosed()");
		}
		else
		{
			LOGGER.log(Level.INFO, "Returning false from isClosed()");
		}

		return closed;
	}

	@Override
	public boolean isFirst() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isFirst()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "isFirst() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (position != 0)
		{
			return false;
		}

		if (rs == null)
		{
			try
			{
				// handle possible interrupt and get a result set from the queue
				stmt.passUpCancel(false);
				stmt.setRunningQueryThread(Thread.currentThread());
				rs = rsQueue.take();

				if (rs.get(0) instanceof SQLException)
				{
					throw (SQLException) rs.get(0);
				}
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred while fetching data with message %s", e.toString(), e.getMessage()));
				if (e instanceof SQLException)
				{
					throw (SQLException) e;
				}

				throw SQLStates.newGenericException(e);
			}
			finally
			{
				stmt.setRunningQueryThread(null);
				stmt.passUpCancel(true);
			}
		}

		final Object row = rs.get(0);
		if (row instanceof DataEndMarker)
		{
			return false;
		}

		return true;
	}

	@Override
	public boolean isLast() throws SQLException
	{
		LOGGER.log(Level.WARNING, "isLast() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean isWrapperFor(final Class<?> iface) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isWrapperFor()");
		return false;
	}

	@Override
	public boolean last() throws SQLException
	{
		LOGGER.log(Level.WARNING, "last() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	private XGTuple getTupleFromBuffer(final ByteBuffer bb, int[] mutableOffset) throws SQLException, java.net.UnknownHostException
	{
		final int numElements = bb.getInt(mutableOffset[0]);
		mutableOffset[0] += 4;

		ArrayList<Object> components = new ArrayList<Object>();
		ArrayList<String> innerTypeNames = new ArrayList<String>();
		assert(numElements > 0);
		for(int i = 0; i < numElements ; i++)
		{
			final byte type = bb.get(mutableOffset[0]);
			mutableOffset[0]++;
			boolean allowArrays = true;
			components.add(getValueFromBuffer(bb, type, mutableOffset, allowArrays));
			innerTypeNames.add(XGResultSetMetaData.type2Name(type));
		}

		return new XGTuple(components, innerTypeNames, conn, stmt);
	}

	private Object getValueFromBuffer(final ByteBuffer bb, final byte type, int[] mutableOffset, Boolean allowArrays) throws SQLException, java.net.UnknownHostException
	{
		int offset = mutableOffset[0];
		Object retval = null;
		if (type == 1) // INT
		{
			retval = bb.getInt(offset);
			offset += 4;
		}
		else if (type == 2) // LONG
		{
			retval = bb.getLong(offset);
			offset += 8;
		}
		else if (type == 3) // FLOAT
		{
			retval = Float.intBitsToFloat(bb.getInt(offset));
			offset += 4;
		}
		else if (type == 4) // DOUBLE
		{
			retval = Double.longBitsToDouble(bb.getLong(offset));
			offset += 8;
		}
		else if (type == 5) // STRING
		{
			final int stringLength = bb.getInt(offset);
			offset += 4;
			final byte[] dst = new byte[stringLength];
			((Buffer) bb).position(offset);
			bb.get(dst);
			retval = new String(dst, Charsets.UTF_8);
			offset += stringLength;
		}
		else if (type == 6) // Timestamp
		{
			retval = new XGTimestamp(bb.getLong(offset));
			offset += 8;
		}
		else if (type == 7) // Null
		{
			retval = null;
		}
		else if (type == 8) // BOOL
		{
			retval = bb.get(offset) != 0;
			offset++;
		}
		else if (type == 9) // BINARY
		{
			final int stringLength = bb.getInt(offset);
			offset += 4;
			final byte[] dst = new byte[stringLength];
			((Buffer) bb).position(offset);
			bb.get(dst);
			retval = dst;
			offset += stringLength;
		}
		else if (type == 10) // BYTE
		{
			retval = bb.get(offset);
			offset++;
		}
		else if (type == 11) // SHORT
		{
			retval = bb.getShort(offset);
			offset += 2;
		}
		else if (type == 12) // TIME
		{
			retval = new XGTime(bb.getLong(offset));
			offset += 8;
		}
		else if (type == 13) // DECIMAL
		{
			final int precision = bb.get(offset);
			retval = getDecimalFromBuffer(bb, offset);
			offset += 2 + bcdLength(precision);
		}
		else if (type == 14 && allowArrays) // ARRAY
		{
			// Need to use int[] so we can pass an integer by reference.
			// Cannot use 'new Integer'. It goes by value.
			final int[] off = new int[1];
			off[0] = offset;
			final XGArray array = getArrayFromBuffer(bb, off);
			offset = off[0];
			retval = array;
		}
		else if (type == 15) // UUID
		{
			final long high = bb.getLong(offset);
			offset += 8;
			final long low = bb.getLong(offset);
			offset += 8;
			retval = new UUID(high, low);
		}
		else if (type == 16) // ST_POINT
		{
			final double lon = Double.longBitsToDouble(bb.getLong(offset));
			offset += 8;
			final double lat = Double.longBitsToDouble(bb.getLong(offset));
			offset += 8;
			retval = new StPoint(lon, lat);
		}
		else if (type == 17) // IP
		{
			final byte[] bytes = new byte[16];
			((Buffer) bb).position(offset);
			bb.get(bytes);
			offset += 16;
			retval = InetAddress.getByAddress(bytes);
		}
		else if (type == 18) // IPV4
		{
			final byte[] bytes = new byte[4];
			((Buffer) bb).position(offset);
			bb.get(bytes);
			offset += 4;
			retval = InetAddress.getByAddress(bytes);
		}
		else if (type == 19) // Date
		{
			retval = new XGDate(bb.getLong(offset));
			offset += 8;
		}
		else if (type == 20) // Timestamp w/ nanos
		{
			final long nanos = bb.getLong(offset);
			long seconds = nanos / 1000000000;
			long nanosPortion = nanos - seconds * 1000000000;
			if(nanosPortion < 0){
				seconds = seconds - 1;
				nanosPortion = 1000000000 + nanosPortion;
			}
			final XGTimestamp ts = new XGTimestamp(seconds * 1000);
			ts.setNanos((int) (nanosPortion));
			retval = ts;
			offset += 8;
		}
		else if (type == 21) // Time w/ nanos
		{
			final long nanos = bb.getLong(offset);
			long seconds = nanos / 1000000000;
			long nanosPortion = nanos - seconds * 1000000000;
			if(nanosPortion < 0){
				seconds = seconds - 1;
				nanosPortion = 1000000000 + nanosPortion;
			}
			final XGTime time = new XGTime(seconds * 1000);
			time.setNanos((int) nanosPortion);
			retval = time;
			offset += 8;
		}
		else if (type == 22) //tuple
		{
			//use int[] as a mutable int to pass by reference
			final int[] off = new int[1];
			off[0] = offset;
			final XGTuple tuple = getTupleFromBuffer(bb, off);
			offset = off[0];
			retval = tuple;
		}
		else if (type == 23) // ST_LINESTRING
		{
			final int length = bb.getInt(offset);
			offset += 4;
			final List<StPoint> points = new ArrayList<StPoint>();
			for(int j = 0; j < length; j++) {
				final double lon = Double.longBitsToDouble(bb.getLong(offset));
				offset += 8;
				final double lat = Double.longBitsToDouble(bb.getLong(offset));
				offset += 8;
				points.add(new StPoint(lon, lat));
			}
			retval = new StLinestring(points);
		}
		else if (type == 24) // ST_POLYGON
		{
			final int length = bb.getInt(offset);
			offset += 4;
			final List<StPoint> exterior = new ArrayList<StPoint>();
			for(int j = 0; j < length; j++) {
				final double lon = Double.longBitsToDouble(bb.getLong(offset));
				offset += 8;
				final double lat = Double.longBitsToDouble(bb.getLong(offset));
				offset += 8;
				exterior.add(new StPoint(lon, lat));
			}
			final int numRings = bb.getInt(offset);
			offset += 4;
			List<List<StPoint>> holes = new ArrayList<List<StPoint>>();
			for(int j = 0; j < numRings; j++) {
				int numPointsInRing = bb.getInt(offset);
				offset += 4;
				List<StPoint> ring = new ArrayList<StPoint>();
				for(int k = 0; k < numPointsInRing; k++) {
					final double lon = Double.longBitsToDouble(bb.getLong(offset));
					offset += 8;
					final double lat = Double.longBitsToDouble(bb.getLong(offset));
					offset += 8;
					ring.add(new StPoint(lon, lat));
				}
				holes.add(ring);
			}
			retval = new StPolygon(exterior, holes);
		}
		else
		{
			throw SQLStates.INVALID_COLUMN_TYPE.clone();
		}

		mutableOffset[0] = offset;
		return retval;
	}

	/*
	 * Returns true if we actually received data, false if there was no data to
	 * merge
	 */
	private boolean mergeData(final ClientWireProtocol.ResultSet re) throws Exception
	{
		boolean done = false;
		boolean didProcessRows = false;
		final List<ByteString> buffers = re.getBlobsList();
		final ArrayList<Object> newRs = new ArrayList<>();
		for (final ByteString buffer : buffers)
		{
			final ByteBuffer bb = buffer.asReadOnlyByteBuffer();
			if (isBufferDem(bb))
			{
				newRs.add(new DataEndMarker());
				demReceived.set(true);
				done = true;
			}
			else
			{
				final int numRows = bb.getInt(0);
				int offset = 4;
				for (int i = 0; i < numRows; i++)
				{
					didProcessRows = true;
					// Process this row
					final ArrayList<Object> alo = new ArrayList<>();
					final int rowLength = bb.getInt(offset);
					final int end = offset + rowLength;
					offset += 4;

					while (offset < end)
					{
						// Get type tag
						final byte type = bb.get(offset);
						offset++;
						int[] mutableOffset = new int[] {offset};
						Boolean allowArrays = true;
						alo.add(getValueFromBuffer(bb, type, mutableOffset, allowArrays));
						offset = mutableOffset[0];
					}

					newRs.add(alo);
				}
			}
		}

		if (didProcessRows)
		{
			didFirstFetch.set(true);
		}

		// Need to not join threads here if we got the special break. The main thread cannot
		// cannot return yet. It needs to finish the fetch.
		if (done && didFirstFetch.get() && !cacheLimitBreak.get())
		{
			// Spin and wait for other threads
			for (final Thread t : fetchThreads)
			{
				if (!t.equals(Thread.currentThread()))
				{
					t.join();
				}
			}
		}

		if (!newRs.isEmpty())
		{
			rsQueue.put(newRs);
		}
		return !done;
	}

	@Override
	public void moveToCurrentRow() throws SQLException
	{
		LOGGER.log(Level.WARNING, "moveToCurrentRow() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void moveToInsertRow() throws SQLException
	{
		LOGGER.log(Level.WARNING, "moveToInsertRow() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean next() throws SQLException
	{
		if (closed)
		{
			LOGGER.log(Level.WARNING, "next() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		position++;

		if (rs == null || firstRowIs - 1 + rs.size() < position)
		{
			if (rs != null)
			{
				final Object row = rs.get(rs.size() - 1);
				if (row instanceof DataEndMarker)
				{
					return false;
				}
			}

			try
			{
				// handle possible interrupt and get a result set from the queue
				stmt.passUpCancel(false);
				stmt.setRunningQueryThread(Thread.currentThread());
				rs = rsQueue.take();

				if (rs.get(0) instanceof SQLException)
				{
					throw (SQLException) rs.get(0);
				}
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred while fetching data with message %s", e.toString(), e.getMessage()));
				if (e instanceof SQLException)
				{
					throw (SQLException) e;
				}

				throw SQLStates.newGenericException(e);
			}
			finally
			{
				stmt.setRunningQueryThread(null);
				stmt.passUpCancel(true);
			}

			firstRowIs = position;
		}

		final Object row = rs.get((int) (position - firstRowIs));
		if (row instanceof DataEndMarker)
		{
			return false;
		}
		else
		{
			return true;
		}
	}

	@Override
	public boolean previous() throws SQLException
	{
		LOGGER.log(Level.WARNING, "previous() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	/*!
	 * Returns true if the special cache limit warning is received. This signals the result set fetching
	 * to break and finish via an asynchronous fetch.
	 */

	private boolean processResponseType(final ResponseType rType, final ConfirmationResponse response) throws SQLException
	{
		if (rType.equals(ResponseType.INVALID))
		{
			LOGGER.log(Level.WARNING, "Received an invalid response from the server");
			throw SQLStates.INVALID_RESPONSE_TYPE.clone();
		}
		else if (rType.equals(ResponseType.RESPONSE_ERROR))
		{
			final String reason = response.getReason();
			final String sqlState = response.getSqlState();
			final int code = response.getVendorCode();
			LOGGER.log(Level.WARNING, String.format("Server returned an error response [%s] %s. Code: %d", sqlState, reason, code));
			throw new SQLException(reason, sqlState, code);
		}
		else if (rType.equals(ResponseType.RESPONSE_WARN))
		{
			final String reason = response.getReason();
			final String sqlState = response.getSqlState();
			final int code = response.getVendorCode();
			if(code == CACHE_LIMIT_WARNING_CODE){
				cacheLimitException = new SQLException(reason, sqlState, code);
				return true;
			}
			LOGGER.log(Level.WARNING, String.format("Server returned a warning response [%s] %s. Code: %d", sqlState, reason, code));
			warnings.add(new SQLWarning(reason, sqlState, code));
		}
		return false;
	}

	private void readBytes(final byte[] bytes) throws Exception
	{
		readBytes(bytes, conn);
	}

	private void readBytes(final byte[] bytes, final XGConnection newConn) throws Exception
	{
		int count = 0;
		final int size = bytes.length;
		while (count < size)
		{
			final int temp = newConn.in.read(bytes, count, bytes.length - count);
			if (temp == -1)
			{
				throw SQLStates.UNEXPECTED_EOF.clone();
			}
			else
			{
				count += temp;
			}
		}
	}

	@Override
	public void refreshRow() throws SQLException
	{
		LOGGER.log(Level.WARNING, "refreshRow() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean relative(final int rows) throws SQLException
	{
		LOGGER.log(Level.WARNING, "relative() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	private void requestMetaData() throws Exception
	{
		LOGGER.log(Level.INFO, "Called requestMetaData()");
		stmt.passUpCancel(false);
		try
		{
			// send fetch metadata request
			final ClientWireProtocol.FetchMetadata.Builder builder = ClientWireProtocol.FetchMetadata.newBuilder();
			final FetchMetadata msg = builder.build();
			final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.FETCH_METADATA);
			b2.setFetchMetadata(msg);
			final Request wrapper = b2.build();
			conn.out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(conn.out);
			conn.out.flush();

			// receive response
			final ClientWireProtocol.FetchMetadataResponse.Builder fmdr = ClientWireProtocol.FetchMetadataResponse.newBuilder();
			final int length = getLength();
			final byte[] data = new byte[length];
			readBytes(data);
			fmdr.mergeFrom(data);
			final ConfirmationResponse response = fmdr.getResponse();
			final ResponseType rType = response.getType();
			processResponseType(rType, response);
			cols2Pos = fmdr.getCols2PosMap();
			setCaseInsensitiveCols2Pos();
			cols2Types = fmdr.getCols2TypesMap();
			pos2Cols = new TreeMap<>();
			for (final Map.Entry<String, Integer> entry : cols2Pos.entrySet())
			{
				pos2Cols.put(entry.getValue(), entry.getKey());
			}
		}
		finally
		{
			stmt.passUpCancel(false);
		}
	}

	@Override
	public boolean rowDeleted() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called rowDeleted()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "rowDeleted() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return false;
	}

	@Override
	public boolean rowInserted() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called rowInserted()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "rowInserted() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return false;
	}

	@Override
	public boolean rowUpdated() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called rowUpdated()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "rowUpdated() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return false;
	}

	private void sendCloseRS() throws Exception
	{
		// send CloseResultSet request
		final ClientWireProtocol.CloseResultSet.Builder builder = ClientWireProtocol.CloseResultSet.newBuilder();
		final CloseResultSet msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.CLOSE_RESULT_SET);
		b2.setCloseResultSet(msg);
		final Request wrapper = b2.build();

		try
		{
			conn.out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(conn.out);
			conn.out.flush();
			getStandardResponse();
		}
		catch (final IOException e)
		{
			// Doesn't matter...
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during sendCloseRs() with message %s", e.toString(), e.getMessage()));
		}
	}

	private void setCaseInsensitiveCols2Pos()
	{
		caseInsensitiveCols2Pos = new HashMap<>();
		for (final Map.Entry<String, Integer> entry : cols2Pos.entrySet())
		{
			caseInsensitiveCols2Pos.put(entry.getKey().toLowerCase(), entry.getValue());
		}
	}

	public void setCols2Pos(final Map<String, Integer> cols2Pos)
	{
		this.cols2Pos = cols2Pos;
		setCaseInsensitiveCols2Pos();
	}

	public void setCols2Types(final Map<String, String> cols2Types)
	{
		this.cols2Types = cols2Types;
	}

	@Override
	public void setFetchDirection(final int direction) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called setFetchDirection()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "setFetchDirection() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (direction != ResultSet.FETCH_FORWARD)
		{
			throw new SQLFeatureNotSupportedException();
		}
	}

	@Override
	public void setFetchSize(final int rows) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called setFetchSize()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "setFetchSize() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (rows <= 0)
		{
			throw SQLStates.INVALID_ARGUMENT.clone();
		}

		fetchSize = rows;
	}

	public void setPos2Cols(final TreeMap<Integer, String> pos2Cols)
	{
		this.pos2Cols = pos2Cols;
	}

	@Override
	public <T> T unwrap(final Class<T> iface) throws SQLException
	{
		LOGGER.log(Level.WARNING, "unwrap() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateArray(final int columnIndex, final Array x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateArray() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateArray(final String columnLabel, final Array x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateArray() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateAsciiStream(final int columnIndex, final InputStream x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateAsciiStream(final int columnIndex, final InputStream x, final int length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateAsciiStream(final int columnIndex, final InputStream x, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateAsciiStream(final String columnLabel, final InputStream x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateAsciiStream(final String columnLabel, final InputStream x, final int length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateAsciiStream(final String columnLabel, final InputStream x, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateAsciiStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBigDecimal(final int columnIndex, final BigDecimal x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBigDecimal() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBigDecimal(final String columnLabel, final BigDecimal x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBigDecimal() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBinaryStream(final int columnIndex, final InputStream x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBinaryStream(final int columnIndex, final InputStream x, final int length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBinaryStream(final int columnIndex, final InputStream x, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBinaryStream(final String columnLabel, final InputStream x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBinaryStream(final String columnLabel, final InputStream x, final int length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBinaryStream(final String columnLabel, final InputStream x, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBinaryStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBlob(final int columnIndex, final Blob x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBlob(final int columnIndex, final InputStream inputStream) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBlob(final int columnIndex, final InputStream inputStream, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBlob(final String columnLabel, final Blob x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBlob(final String columnLabel, final InputStream inputStream) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBlob(final String columnLabel, final InputStream inputStream, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBoolean(final int columnIndex, final boolean x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBoolean() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBoolean(final String columnLabel, final boolean x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBoolean() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateByte(final int columnIndex, final byte x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateByte() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateByte(final String columnLabel, final byte x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateByte() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBytes(final int columnIndex, final byte[] x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBytes() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateBytes(final String columnLabel, final byte[] x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateBytes() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateCharacterStream(final int columnIndex, final Reader x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateCharacterStream(final int columnIndex, final Reader x, final int length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateCharacterStream(final int columnIndex, final Reader x, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateCharacterStream(final String columnLabel, final Reader reader) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateCharacterStream(final String columnLabel, final Reader reader, final int length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateCharacterStream(final String columnLabel, final Reader reader, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateClob(final int columnIndex, final Clob x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateClob(final int columnIndex, final Reader reader) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateClob(final int columnIndex, final Reader reader, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateClob(final String columnLabel, final Clob x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateClob(final String columnLabel, final Reader reader) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateClob(final String columnLabel, final Reader reader, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateDate(final int columnIndex, final Date x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateDate() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateDate(final String columnLabel, final Date x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateDate() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateDouble(final int columnIndex, final double x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateDouble() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateDouble(final String columnLabel, final double x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateDouble() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateFloat(final int columnIndex, final float x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateFloat() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateFloat(final String columnLabel, final float x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateFloat() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateInt(final int columnIndex, final int x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateInt() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateInt(final String columnLabel, final int x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateInt() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateLong(final int columnIndex, final long x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateLong() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateLong(final String columnLabel, final long x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateLong() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNCharacterStream(final int columnIndex, final Reader x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNCharacterStream(final int columnIndex, final Reader x, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNCharacterStream(final String columnLabel, final Reader reader) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNCharacterStream(final String columnLabel, final Reader reader, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNCharacterStream() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNClob(final int columnIndex, final NClob nClob) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNClob(final int columnIndex, final Reader reader) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNClob(final int columnIndex, final Reader reader, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNClob(final String columnLabel, final NClob nClob) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNClob(final String columnLabel, final Reader reader) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNClob(final String columnLabel, final Reader reader, final long length) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNString(final int columnIndex, final String nString) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNString() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNString(final String columnLabel, final String nString) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNString() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNull(final int columnIndex) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNull() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateNull(final String columnLabel) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateNull() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateObject(final int columnIndex, final Object x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateObject() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateObject(final int columnIndex, final Object x, final int scaleOrLength) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateObject() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateObject(final String columnLabel, final Object x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateObject() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateObject(final String columnLabel, final Object x, final int scaleOrLength) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateObject() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateRef(final int columnIndex, final Ref x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateRef() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateRef(final String columnLabel, final Ref x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateRef() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateRow() throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateRow() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateRowId(final int columnIndex, final RowId x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateRowId() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateRowId(final String columnLabel, final RowId x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateRowId() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateShort(final int columnIndex, final short x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateShort() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateShort(final String columnLabel, final short x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateShort() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateSQLXML(final int columnIndex, final SQLXML xmlObject) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateSQLXML() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateSQLXML(final String columnLabel, final SQLXML xmlObject) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateSQLXML() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateString(final int columnIndex, final String x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateString() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateString(final String columnLabel, final String x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateString() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateTime(final int columnIndex, final Time x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateTime() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateTime(final String columnLabel, final Time x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateTime() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateTimestamp(final int columnIndex, final Timestamp x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateTimestamp() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void updateTimestamp(final String columnLabel, final Timestamp x) throws SQLException
	{
		LOGGER.log(Level.WARNING, "updateTimestamp() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean wasNull() throws SQLException
	{
		if (closed)
		{
			LOGGER.log(Level.WARNING, "wasNull() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return wasNull;
	}

	/*!
	 * Asynchronously finishes fetching. Occupies a connection so it will not be
	 * used for another query.
	 */
	public void asyncFinishFetch(final XGConnection newConn)
	{
		LOGGER.log(Level.INFO, "asyncFinishFetch called");
		try
		{
			final Optional<String> queryId = getQueryId();
			stmt.passUpCancel(false);
			final ClientWireProtocol.FetchData.Builder builder = ClientWireProtocol.FetchData.newBuilder();
			builder.setFetchSize(fetchSize);
			final FetchData msg = builder.build();
			final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.FETCH_DATA);
			b2.setFetchData(msg);
			final Request wrapper = b2.build();
			while(true)
			{
				if (demReceived.get() || Thread.currentThread().interrupted())
				{
					return;
				}
				newConn.out.write(intToBytes(wrapper.getSerializedSize()));
				wrapper.writeTo(newConn.out);
				newConn.out.flush();
				// Kind of ugly, but doesn't violate JMM (startTask() is synchronous)
				final ClientWireProtocol.FetchDataResponse.Builder fdr = ClientWireProtocol.FetchDataResponse.newBuilder();
				stmt.startTask(() ->
				{
					// get confirmation and data (fetchSize rows or zero size result set or
					// terminated early with a DataEndMarker)
					final int length = getLength(newConn);
					final byte[] data = new byte[length];
					readBytes(data, newConn);
					fdr.mergeFrom(data);
				}, queryId, getTimeoutMillis());
				final ConfirmationResponse response = fdr.getResponse();
				final ResponseType rType = response.getType();
				processResponseType(rType, response);
				if (searchDem(fdr.getResultSet()))
				{
					return;
				}
			}
		}
		catch (final Exception e)
		{
			// The asynchronous result set fetch failed with an error. That is fine, we don't need this result set anymore. Log and return.
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred while finishing asynchronous fetching of result set with message %s. This is an error.", e.toString(), e.getMessage()));
			return;
		}
	}

	/*!
	 * Helper function for asynchronously finishing the result set fetch. Not much is
	 * being done here. We are just looking for the DEM so we know the query is complete server side.
	 */
	private boolean searchDem(final ClientWireProtocol.ResultSet re)
	{
		final List<ByteString> buffers = re.getBlobsList();
		for (final ByteString buffer : buffers)
		{
			final ByteBuffer bb = buffer.asReadOnlyByteBuffer();
			if (isBufferDem(bb))
			{
				LOGGER.log(Level.INFO, "searchDEM found dem");
				demReceived.set(true);
				return true;
			}
		}
		LOGGER.log(Level.INFO, "searchDEM did not find DEM");
		return false;
	}

	/*!
	 * A daemon thread will fetch the rest the result thread after a cacheLimit break. We want 
	 * this to be done on a daemon thread because we want the program to be able to exit
	 * despite this thread still running.
	 */
	private class daemonFinishFetchThread implements Runnable{

		public daemonFinishFetchThread(XGStatement stmtToCache, XGConnection connToFinish){
			m_stmtToCache = stmtToCache;
			m_connToFinish = connToFinish;
		}

		public void run(){
			asyncFinishFetch(m_connToFinish);
			m_stmtToCache.conn = m_connToFinish;
			m_stmtToCache.returnStatementToCache();
		}
		private XGStatement m_stmtToCache;
		private XGConnection m_connToFinish;
	}
}
