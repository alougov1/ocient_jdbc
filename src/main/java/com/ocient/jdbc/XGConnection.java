package com.ocient.jdbc;

import java.awt.Desktop;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import com.google.protobuf.ByteString;
import com.ocient.jdbc.proto.ClientWireProtocol;
import com.ocient.jdbc.proto.ClientWireProtocol.ClientConnection;
import com.ocient.jdbc.proto.ClientWireProtocol.ClientConnectionGCM;
import com.ocient.jdbc.proto.ClientWireProtocol.ClientConnectionSSO;
import com.ocient.jdbc.proto.ClientWireProtocol.ClientConnectionSecurityToken;
import com.ocient.jdbc.proto.ClientWireProtocol.CloseConnection;
import com.ocient.jdbc.proto.ClientWireProtocol.ConfirmationResponse;
import com.ocient.jdbc.proto.ClientWireProtocol.ConfirmationResponse.ResponseType;
import com.ocient.jdbc.proto.ClientWireProtocol.ForceExternal;
import com.ocient.jdbc.proto.ClientWireProtocol.GetSchema;
import com.ocient.jdbc.proto.ClientWireProtocol.Request;
import com.ocient.jdbc.proto.ClientWireProtocol.SessionInfo;
import com.ocient.jdbc.proto.ClientWireProtocol.SecurityToken;
import com.ocient.jdbc.proto.ClientWireProtocol.SetParameter;
import com.ocient.jdbc.proto.ClientWireProtocol.SetSchema;
import com.ocient.jdbc.proto.ClientWireProtocol.TestConnection;
import com.ocient.jdbc.proto.ClientWireProtocol.ClientConnectionSSO2Response.ResponseOneofCase;

public class XGConnection implements Connection
{
	private class TestConnectionThread extends Thread
	{
		Exception e = null;

		@Override
		public void run()
		{
			try
			{
				LOGGER.log(Level.INFO, "Testing connection");

				// send request
				final ClientWireProtocol.TestConnection.Builder builder = ClientWireProtocol.TestConnection.newBuilder();
				final TestConnection msg = builder.build();
				final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
				b2.setType(ClientWireProtocol.Request.RequestType.TEST_CONNECTION);
				b2.setTestConnection(msg);
				final Request wrapper = b2.build();

				try
				{
					out.write(intToBytes(wrapper.getSerializedSize()));
					wrapper.writeTo(out);
					out.flush();
					getStandardResponse();
				}
				catch (SQLException | IOException e)
				{
					LOGGER.log(Level.WARNING, String.format("Connection test failed with exception %s with message %s", e.toString(), e.getMessage()));
					if (e instanceof SQLException && !SQLStates.UNEXPECTED_EOF.equals((SQLException) e))
					{
						throw e;
					}

					reconnect();
					run();
					return;
				}
			}
			catch (final Exception e)
			{
				this.e = e;
			}
		}
	}

	public enum Tls
	{
		OFF, // No TLS
		UNVERIFIED, // Don't verify certificates
		ON, // TLS but no server identity verification
		VERIFY, // TLS with server identity verification
	}
	public enum HandshakeType
	{
		CBC, // Original handshake method
		GCM, // New handshake method. Now default.
		SSO, // SSO handshake. needs to be explicitly used.
	}

	private class XGTrustManager extends X509ExtendedTrustManager
	{
		X509TrustManager defaultTm;
		Tls tls;

		public XGTrustManager(final Tls t) throws Exception
		{
			tls = t;

			final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

			tmf.init((java.security.KeyStore) null);

			for (final TrustManager tm : tmf.getTrustManagers())
			{
				if (tm instanceof X509TrustManager)
				{
					defaultTm = (X509TrustManager) tm;
					break;
				}
			}
		}

		@Override
		public void checkClientTrusted(final X509Certificate certificates[], final String s, final javax.net.ssl.SSLEngine sslEngine) throws CertificateException
		{
			LOGGER.log(Level.INFO, "x509ExtendedTrustManager: checkClientTrusted " + s + "with sslEngine");
			checkClientTrusted(certificates, s);
		}

		@Override
		public void checkClientTrusted(final X509Certificate[] certificates, final String s) throws CertificateException
		{

			LOGGER.log(Level.INFO, "x509ExtendedTrustManager: checkClientTrusted " + s);
			try
			{
				defaultTm.checkClientTrusted(certificates, s);
			}
			catch (final CertificateException e)
			{
				LOGGER.log(Level.WARNING, "checkClientTrusted caught " + e.getMessage());

				// Rethrow the exception if we are not using level ON
				if (tls != Tls.UNVERIFIED)
				{
					throw e;
				}
				else
				{
					LOGGER.log(Level.WARNING, "Ignoring certificate exception: " + e.getMessage());
				}
			}
		}

		@Override
		public void checkClientTrusted(final X509Certificate[] certificates, final String s, final java.net.Socket socket) throws CertificateException
		{
			LOGGER.log(Level.INFO, "x509ExtendedTrustManager: checkClientTrusted " + s + "with socket");
			checkClientTrusted(certificates, s);
		}

		@Override
		public void checkServerTrusted(final X509Certificate certificates[], final String s, final javax.net.ssl.SSLEngine sslEngine) throws CertificateException
		{
			LOGGER.log(Level.INFO, "x509ExtendedTrustManager: checkServerTrusted " + s + "with sslEngine");
			checkServerTrusted(certificates, s);
		}

		@Override
		public void checkServerTrusted(final X509Certificate[] certificates, final String s) throws CertificateException
		{
			LOGGER.log(Level.INFO, "x509ExtendedTrustManager: checkServerTrusted " + s);
			try
			{
				defaultTm.checkServerTrusted(certificates, s);
			}
			catch (final CertificateException e)
			{

				// Rethrow the exception if we are not using level ON
				if (tls != Tls.UNVERIFIED)
				{
					throw e;
				}
				else
				{
					LOGGER.log(Level.WARNING, "Ignoring certificate exception: " + e.getMessage());
				}
			}
		}

		@Override
		public void checkServerTrusted(final X509Certificate[] certificates, final String s, final java.net.Socket socket) throws CertificateException
		{
			LOGGER.log(Level.INFO, "x509ExtendedTrustManager: checkServerTrusted " + s + "with socket");
			checkServerTrusted(certificates, s);

			// Do host name verification
			if (tls == Tls.VERIFY)
			{
				throw new UnsupportedOperationException("TLS Verify mode not supported");
			}
		}

		@Override
		public X509Certificate[] getAcceptedIssuers()
		{
			return defaultTm.getAcceptedIssuers();
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

	protected BufferedInputStream in;
	protected BufferedOutputStream out;
	private boolean closed = false;
	private boolean connected = true;
	private Socket sock;
	protected XGResultSet rs;
	protected int portNum;
	protected ArrayList<SQLWarning> warnings = new ArrayList<>();
	protected final String url;
	protected String ip;
	protected String originalIp;
	protected String connectedIp;
	protected int originalPort;
	protected int connectedPort;
	protected String user;
	protected String database;
	protected String client = "jdbc";
	// protocolVersion does not change since switching to maven. clientVersion is the true driver version.
	protected String protocolVersion;
	protected String clientVersion = "0.00";
	protected String serverVersion = "";
	protected String defaultSchema = "";

	protected boolean oneShotForce = false;
	protected ArrayList<String> cmdcomps = new ArrayList<>();
	protected ArrayList<ArrayList<String>> secondaryInterfaces = new ArrayList<>();
	protected int secondaryIndex = -1;
	protected int networkTimeout = 10000;
	protected Tls tls;

	// The timer is initially null, created when the first query timeout is set and
	// destroyed on close()
	private final AtomicReference<Timer> timer = new AtomicReference<>();
	private static final String sessionID = UUID.randomUUID().toString();

	protected String pwd;

	private static class Session {

		static class SecurityToken {
			final String tokenData;
			final String tokenSignature;
			final String issuerFingerprint;
	
			SecurityToken(final String tokenData, final String tokenSignature, final String issuerFingerprint) {
				this.tokenData = tokenData;
				this.tokenSignature = tokenSignature;
				this.issuerFingerprint = issuerFingerprint;
			}
		}
		static class UserAndPassword{
			final String user;
			final String password;
			
			UserAndPassword(final String user, final String password){
				this.user = user;
				this.password = password;
			}
		}
		static class State {

			public Optional<SecurityToken> securityToken = Optional.empty();
			public Optional<UserAndPassword> userAndPassword = Optional.empty();
			
			// Constructor for state with securityToken
			State(SecurityToken securityToken){
				this.securityToken = Optional.of(securityToken);
			}
			// Constructor for state with user name and password
			State(UserAndPassword userAndPassword){
				this.userAndPassword = Optional.of(userAndPassword);
			}
		}		

		Session(final String tokenData, final String tokenSignature, final String issuerFingerprint) {
			currentState = new State(new SecurityToken(tokenData, tokenSignature, issuerFingerprint));
		}

		Session(final String user, final String password){
			currentState = new State(new UserAndPassword(user, password));
		}
		
		// volatile provides thread safety within single producer, multi consumer contexts
		private volatile State currentState;
		// provides mutual exclusion 
		private ReentrantLock refreshMutex = new ReentrantLock();
		// Copyable when >= 1
		final AtomicInteger refCount = new AtomicInteger(1);	
		
		// Retains a reference to this session iff its ref count is greater than 0 (implies the 
		// session has not been destroyed). Returns EMPTY if the ref count was 0 session has been 
		// destroyed.
		public Optional<State> retain() {
			// Retain a reference to this session by CAS
			int curr;
			do {
				curr = refCount.get();
				if (curr == 0) {
					// The session was destroyed
					return Optional.empty();
				}

				assert curr > 0;
			} while (!refCount.compareAndSet(curr, curr + 1));

			// Success
			// 
			// Return a reference to the current session state. Would be nice 
			// to return an opaque handle that decrements on desctrution, but
			// we can't do this with JAVA because garbage collectors can't 
			// guarantee is called Object.finalize() happens exactly once. 
			// Technically, they don't even guarantee at-least-once semantics
			// (no RAII sigh...)
			return Optional.of(currentState);
		}

		// Decrements the ref count by 1 and returns true iff the session is safe
		// to destroy. The caller is responsible for signaling to the server the
		// session is safe to terminate.
		public boolean release() {
			// Release a reference to this session by CAS
			int curr;
			do {
				curr = refCount.get();
				assert curr > 0;
			} while (!refCount.compareAndSet(curr, curr - 1));

			return curr == 1;
		}		

		// Multiple threads may attempt to refresh a security token, an operation
		// that requires at most once semantics. A lock is used to provide mutual 
		// exclusion within the critical section which compares the manager's token
		// with the thread's expectation. If the comparison fails, this indicates
		// another thread has already performed the refresh. The calling thread's
		// state simply needs to be updated.
		public State refresh(final State expectedState, XGConnection conn) throws SQLException{
			LOGGER.log(Level.INFO, "Attempting to refresh session");
			// Acquire the refresh mutex
			refreshMutex.lock();
			try {
				// when you get the lock, check the manager's current state
				// NOTE: this is an intentional reference comparison, we essentially are comparing a mem address, 
				// not object equality (though in this particular case, equality would actually work too)
				if (currentState != expectedState) {
					// we interleaved with a sibling connection thread that performed a refresh
					LOGGER.log(Level.INFO, "Interweaved refresh attempt. Returning");
					return currentState;
				}
				// else
				// we are responsible for updating the state
				// Importantly, we are the only thread in this critical section
				boolean ignoreSecurityToken = expectedState.userAndPassword.isPresent();
				State newState = conn.sendRefresh(ignoreSecurityToken);
				LOGGER.log(Level.INFO, "Successfully refreshed session");
				currentState = newState;
				return newState;
			} finally {
				refreshMutex.unlock();
			}
		}
	}

	// Refresh the session.
	public void refreshSession() throws SQLException{
		this.sessionState = this.session.refresh(this.sessionState, this);
	}


	// TODO Introduce an Either<L, R> data structure to hold either SSOToken OR PasswordToken
	// TODO New connector versions should use signed security tokens instead of storing the 
	// raw password in memory
	// 
	protected Session session = null;
	// Presence implies the connection was established successfully
	protected String serverSessionId = "";
	// We keep our own copy of what we believe is the security token for purposes of synchronization.
	protected Session.State sessionState = null;
	private int retryCounter;

	protected Map<String, Class<?>> typeMap;

	private final Properties properties;

	/*!
	 * Connection level settings need to be added to the hash code so that connections with different settings get mapped to different hash codes.
	 */
	protected String setSchema = "";
	protected long setPso = 0;
	public Integer maxRows = null;
	private Integer maxTime = null;
	private Integer maxTempDisk = null;
	private Integer parallelism = null;
	private Double priority = null;
	protected boolean force = false;
	private volatile long timeoutMillis = 0L; // 0L means no timeout set	

	private XGConnection(final String user, final String pwd, final int portNum, final String url, final String database, final String protocolVersion, String clientVersion, final boolean force, final Tls tls,
		final Properties properties)
	{
		// Note that this constructor is only used by internally by connection copy(). Thus we do not need to call validateDefaultProperties(properties)
		this.properties = properties;
		resetLocalVars();
		this.force = force;
		this.url = url;
		this.user = user;
		this.pwd = pwd;
		sock = null;
		this.portNum = portNum;
		this.database = database;
		this.protocolVersion = protocolVersion;
		if(clientVersion != null){
			this.clientVersion = clientVersion;
		} else {
			LOGGER.log(Level.WARNING, "Null clientVersion passed to the connection constructor. Something is probably wrong with manifest.");
		}
		retryCounter = 0;
		this.tls = tls;
		typeMap = new HashMap<>();
		in = null;
		out = null;
	}

	public XGConnection(final String user, final String pwd, final String ip, final int portNum, final String url, final String database, final String protocolVersion, String clientVersion, final String force, final Tls tls,
		final Properties properties) throws Exception
	{
		validateDefaultProperties(properties);
		this.properties = properties;
		resetLocalVars();
		originalIp = ip;
		originalPort = portNum;

		LOGGER.log(Level.INFO, String.format("Connection constructor is setting IP = %s and PORT = %d", ip, portNum));

		if (force.equals("true"))
		{
			this.force = true;
		}

		this.url = url;
		this.user = user;
		this.pwd = pwd;
		this.ip = ip;
		this.portNum = portNum;
		this.database = database;
		this.protocolVersion = protocolVersion;
		if(clientVersion != null){
			this.clientVersion = clientVersion;
		} else {
			LOGGER.log(Level.WARNING, "Null clientVersion passed to the connection constructor. Something is probably wrong with manifest.");
		}
		retryCounter = 0;
		this.tls = tls;
		typeMap = new HashMap<>();
	}

	@Override
	public void abort(final Executor executor) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called abort()");
		if (executor == null)
		{
			LOGGER.log(Level.WARNING, "abort() is throwing INVALID_ARGUMENT");
			throw SQLStates.INVALID_ARGUMENT.clone();
		}

		if (closed)
		{
			return;
		}

		close();
	}

	/**
	 * Schedules the task to run after the specified delay
	 *
	 * @param task    the task to run
	 * @param timeout delay in milliseconds
	 */
	protected void addTimeout(final TimerTask task, final long timeout)
	{
		getTimer().schedule(task, timeout);
	}

	public void clearOneShotForce()
	{
		oneShotForce = false;
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

	/**
	 * Saves the secondary interfaces being used and marks the secondaryIndex
	 * according to the one we are connected to. Necessary after every completed
	 * connection.
	 */
	private void saveSecondaryInterfaces(final List<String> newCmdComps, final List<com.ocient.jdbc.proto.ClientWireProtocol.SecondaryInterfaceList> newSecondaryInterfaces) throws Exception {
		LOGGER.log(Level.INFO, "called saveSecondaryInterfaces()");
		// TODO: Check if this cmdComps member is even used anymore. I think its deprecated by secondaryInterfaces.
		this.cmdcomps.clear();
		for(int i = 0; i < newCmdComps.size(); i++){
			this.cmdcomps.add(newCmdComps.get(i));
		}
		LOGGER.log(Level.INFO, "Clearing and adding new secondary interfaces");
		this.secondaryInterfaces.clear();
		for(int i = 0; i < newSecondaryInterfaces.size(); i++){
			this.secondaryInterfaces.add(new ArrayList<String>());
			for(int j = 0; j < newSecondaryInterfaces.get(i).getAddressCount(); j++){
				// Do hostname / IP translation here
				String connInfo = newSecondaryInterfaces.get(i).getAddress(j);
				final StringTokenizer tokens = new StringTokenizer(connInfo, ":", false);
				final String connHost = tokens.nextToken();
				final int connPort = Integer.parseInt(tokens.nextToken());
				final InetAddress[] addrs = InetAddress.getAllByName(connHost);
				for(final InetAddress addr : addrs){
					connInfo = addr.toString().substring(addr.toString().indexOf('/') + 1) + ":" + connPort;
					this.secondaryInterfaces.get(i).add(connInfo);
				}
			}
		}
		// Figure out what secondary index it is
		final String combined = ip + ":" + portNum;
		for (final ArrayList<String> list : secondaryInterfaces)
		{
			int index = 0;
			for (final String address : list)
			{
				if (address.equals(combined))
				{
					secondaryIndex = index;
					break;
				}

				index++;
			}
		}
		LOGGER.log(Level.INFO, String.format("Using secondary index %d", this.secondaryIndex));
		for (final ArrayList<String> list : this.secondaryInterfaces)
		{
			LOGGER.log(Level.INFO, "New SQL node");
			for (final String address : list)
			{
				LOGGER.log(Level.INFO, String.format("Interface %s", address));
			}
		}		
	}

	private void clientHandshake(final String userid, final String pwd, final String db, final boolean shouldRequestVersion) throws Exception
	{
		final String handshakeStr = properties.getProperty("handshake", "GCM").toUpperCase();
		final XGConnection.HandshakeType handshake = XGConnection.HandshakeType.valueOf(handshakeStr);
		if(handshake == HandshakeType.CBC){
			// CBC
			clientHandshakeCBC(userid, pwd, db, shouldRequestVersion);
		} else if(handshake == HandshakeType.SSO){
			// SSO
			if(!userid.toLowerCase().equals("") || !pwd.toLowerCase().equals("")){
				// SSO handshake desired but non empty password or username.
				clientHandshakeGCM(userid, pwd, db, shouldRequestVersion, true);
			} else {
				// SSO but may or may not have a securitty token yet.
				if(this.session == null){
					// No token yet.
					clientHandshakeSSO(db, shouldRequestVersion);
				} else {
					// Already have a token.
					clientHandshakeSecurityToken(db, shouldRequestVersion);
				}				
			}
		} else {
			// GCM
			clientHandshakeGCM(userid, pwd, db, shouldRequestVersion, false);
		}
	}
	// DB-15559 make this and clientHandshakeCBC share code. Didn't have time to do this right now.
	private void clientHandshakeGCM(final String userid, final String pwd, final String db, final boolean shouldRequestVersion, final boolean isExplicitSSO) throws Exception
	{
		try
		{
			LOGGER.log(Level.INFO, "Beginning GCM handshake");
			// send first part of handshake - contains userid
			final ClientWireProtocol.ClientConnectionGCM.Builder builder = ClientWireProtocol.ClientConnectionGCM.newBuilder();
			builder.setUserid(userid);
			builder.setDatabase(database);
			builder.setClientid(client);
			builder.setVersion(protocolVersion);
			String[] majorMinorVersion = clientVersion.split("\\.");
			int majorClientVersion = Integer.parseInt(majorMinorVersion[0]);
			int minorClientVersion = Integer.parseInt(majorMinorVersion[1]);
			builder.setMajorClientVersion(majorClientVersion);
			builder.setMinorClientVersion(minorClientVersion);
			builder.setSessionID(sessionID);
			builder.setExplicitSSO(isExplicitSSO);

			final ClientConnectionGCM msg = builder.build();
			ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION_GCM);
			b2.setClientConnectionGcm(msg);
			Request wrapper = b2.build();
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();

			// get response
			final ClientWireProtocol.ClientConnectionGCMResponse.Builder ccr = ClientWireProtocol.ClientConnectionGCMResponse.newBuilder();
			int length = getLength();
			byte[] data = new byte[length];
			readBytes(data);
			ccr.mergeFrom(data);
			ConfirmationResponse response = ccr.getResponse();
			ResponseType rType = response.getType();
			processResponseType(rType, response);
			final ByteString ivString = ccr.getIv();
			byte[] key;
			byte[] macKey;
			String myPubKey;

			try
			{
				String keySpec = ccr.getPubKey();
				keySpec = keySpec.replace("-----BEGIN PUBLIC KEY-----\n", "");
				keySpec = keySpec.replace("-----END PUBLIC KEY-----\n", "");
				final byte[] keyBytes = Base64.getMimeDecoder().decode(keySpec.getBytes(StandardCharsets.UTF_8));
				final X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(keyBytes);
				final KeyFactory keyFact = KeyFactory.getInstance("DH");
				final DHPublicKey pubKey = (DHPublicKey) keyFact.generatePublic(x509keySpec);
				final DHParameterSpec params = pubKey.getParams();

				final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
				keyGen.initialize(params);
				final KeyPair kp = keyGen.generateKeyPair();

				final KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
				ka.init(kp.getPrivate());
				ka.doPhase(pubKey, true);
				final byte[] secret = ka.generateSecret();

				final byte[] buffer = new byte[5 + secret.length];
				buffer[0] = (byte) ((secret.length & 0xff000000) >> 24);
				buffer[1] = (byte) ((secret.length & 0xff0000) >> 16);
				buffer[2] = (byte) ((secret.length & 0xff00) >> 8);
				buffer[3] = (byte) (secret.length & 0xff);
				System.arraycopy(secret, 0, buffer, 5, secret.length);

				buffer[4] = 0x00;
				MessageDigest sha = MessageDigest.getInstance("SHA-256");
				key = sha.digest(buffer);

				buffer[4] = 0x01;
				sha = MessageDigest.getInstance("SHA-256");
				macKey = sha.digest(buffer);

				final PublicKey clientPub = kp.getPublic();
				myPubKey = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(clientPub.getEncoded()) + "\n-----END PUBLIC KEY-----\n";
			}
			catch(RuntimeException e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
				throw e;
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
				throw e;
			}

			final byte[] iv = ivString.toByteArray();
			// We are using a 16 byte authentication tag on the server side. 16 * 8 = 128.
			final GCMParameterSpec gps = new GCMParameterSpec(128, iv);

			// Create a key specification first, based on our key input.
			final SecretKey aesKey = new SecretKeySpec(key, "AES");
			final SecretKey hmacKey = new SecretKeySpec(macKey, "AES");

			// Create a Cipher for encrypting the data using the key we created.
			Cipher encryptCipher;

			encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
			// Initialize the Cipher with key and parameters
			encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, gps);

			// Our cleartext
			final byte[] cleartext = pwd.getBytes(StandardCharsets.UTF_8);

			// Encrypt the cleartext
			final byte[] ciphertext = encryptCipher.doFinal(cleartext);

			final Mac hmac = Mac.getInstance("HmacSha256");
			hmac.init(hmacKey);
			final byte[] calculatedMac = hmac.doFinal(ciphertext);

			// send handshake part2
			LOGGER.log(Level.INFO, "Beginning handshake part 2");
			final ClientWireProtocol.ClientConnectionGCM2.Builder hand2 = ClientWireProtocol.ClientConnectionGCM2.newBuilder();
			hand2.setCipher(ByteString.copyFrom(ciphertext));
			hand2.setPubKey(myPubKey);
			hand2.setHmac(ByteString.copyFrom(calculatedMac));
			if (force)
			{
				hand2.setForce(true);
			}
			else if (oneShotForce)
			{
				oneShotForce = false;
				hand2.setForce(true);
			}
			else
			{
				hand2.setForce(false);
			}
			// Set whether this is an explicit SSO handshake.
			hand2.setExplicitSSO(isExplicitSSO);
			final ClientWireProtocol.ClientConnectionGCM2 msg2 = hand2.build();
			b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION_GCM2);
			b2.setClientConnectionGcm2(msg2);
			wrapper = b2.build();
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();

			// getResponse
			final ClientWireProtocol.ClientConnectionGCM2Response.Builder ccr2 = ClientWireProtocol.ClientConnectionGCM2Response.newBuilder();
			length = getLength();
			data = new byte[length];
			readBytes(data);
			ccr2.mergeFrom(data);
			response = ccr2.getResponse();
			rType = response.getType();

			LOGGER.log(Level.INFO, "Handshake response received");
			final SQLException state = new SQLException(response.getReason(), response.getSqlState(), response.getVendorCode());
			// if we had a failed handshake, then something went wrong with verification on
			// the server, just try again(up to 5 times)
			if (SQLStates.FAILED_HANDSHAKE.equals(state) && retryCounter++ < 5)
			{
				LOGGER.log(Level.INFO, "Handshake failed, retrying");
				clientHandshake(userid, pwd, db, shouldRequestVersion);
				return;
			}
			retryCounter = 0;
			processResponseType(rType, response);
			// Set the server session id
			LOGGER.log(Level.INFO, String.format("Connected to session id: %s", ccr2.getServerSessionId()));
			serverSessionId = ccr2.getServerSessionId();
			this.session = new Session(user, pwd);
			this.sessionState = this.session.currentState; // record the current state.
			// Save the secondary interface for reconnecting and recirecting.
			saveSecondaryInterfaces(ccr2.getCmdcompsList(), ccr2.getSecondaryList());
			// Handle redirect
			if (ccr2.getRedirect())
			{
				LOGGER.log(Level.INFO, "Redirect command in ClientConnectionGCM2Response from server");
				final String host = ccr2.getRedirectHost();
				final int port = ccr2.getRedirectPort();
				redirect(host, port, shouldRequestVersion);
				// We have a lot of dangerous circular function calls.
				// If we were redirected, then we already have the server version. We need to
				// return here.
				if (!getVersion().equals(""))
				{
					LOGGER.log(Level.INFO, "Returning in handshake redirect. Already have protocol version.");
					return;
				}
			}
		}
		catch(RuntimeException e)
		{
			LOGGER.log(Level.WARNING, String.format("Runtime Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
			throw e;
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));

			try
			{
				sock.close();
			}
			catch (final Exception f)
			{
				LOGGER.log(Level.WARNING, "Failed to close socket in clientHandshakeGCM");
			}

			throw e;
		}

		if (shouldRequestVersion)
		{
			if (serverVersion.equals(""))
			{
				fetchServerVersion();
			}
		}
		LOGGER.log(Level.INFO, "Handshake GCM Finished");
	}

	// I don't like that this is copy and pasted of the above. But really, this function does too many things with
	// the ccr and ccr2 to separate the GCM and CBC cases into if/switch statements.
	private void clientHandshakeCBC(final String userid, final String pwd, final String db, final boolean shouldRequestVersion) throws Exception
	{
		try
		{
			LOGGER.log(Level.INFO, "Beginning CBC handshake");
			// send first part of handshake - contains userid
			final ClientWireProtocol.ClientConnection.Builder builder = ClientWireProtocol.ClientConnection.newBuilder();
			builder.setUserid(userid);
			builder.setDatabase(database);
			builder.setClientid(client);
			builder.setVersion(protocolVersion);
			String[] majorMinorVersion = clientVersion.split("\\.");
			int majorClientVersion = Integer.parseInt(majorMinorVersion[0]);
			int minorClientVersion = Integer.parseInt(majorMinorVersion[1]);
			builder.setMajorClientVersion(majorClientVersion);
			builder.setMinorClientVersion(minorClientVersion);
			builder.setSessionID(sessionID);
			final ClientConnection msg = builder.build();
			ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION);
			b2.setClientConnection(msg);
			Request wrapper = b2.build();
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();

			// get response
			final ClientWireProtocol.ClientConnectionResponse.Builder ccr = ClientWireProtocol.ClientConnectionResponse.newBuilder();
			int length = getLength();
			byte[] data = new byte[length];
			readBytes(data);
			ccr.mergeFrom(data);
			ConfirmationResponse response = ccr.getResponse();
			ResponseType rType = response.getType();
			processResponseType(rType, response);
			final ByteString ivString = ccr.getIv();
			byte[] key;
			byte[] macKey;
			String myPubKey;

			try
			{
				String keySpec = ccr.getPubKey();
				keySpec = keySpec.replace("-----BEGIN PUBLIC KEY-----\n", "");
				keySpec = keySpec.replace("-----END PUBLIC KEY-----\n", "");
				final byte[] keyBytes = Base64.getMimeDecoder().decode(keySpec.getBytes(StandardCharsets.UTF_8));
				final X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(keyBytes);
				final KeyFactory keyFact = KeyFactory.getInstance("DH");
				final DHPublicKey pubKey = (DHPublicKey) keyFact.generatePublic(x509keySpec);
				final DHParameterSpec params = pubKey.getParams();

				final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
				keyGen.initialize(params);
				final KeyPair kp = keyGen.generateKeyPair();

				final KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
				ka.init(kp.getPrivate());
				ka.doPhase(pubKey, true);
				final byte[] secret = ka.generateSecret();

				final byte[] buffer = new byte[5 + secret.length];
				buffer[0] = (byte) ((secret.length & 0xff000000) >> 24);
				buffer[1] = (byte) ((secret.length & 0xff0000) >> 16);
				buffer[2] = (byte) ((secret.length & 0xff00) >> 8);
				buffer[3] = (byte) (secret.length & 0xff);
				System.arraycopy(secret, 0, buffer, 5, secret.length);

				buffer[4] = 0x00;
				MessageDigest sha = MessageDigest.getInstance("SHA-256");
				key = sha.digest(buffer);

				buffer[4] = 0x01;
				sha = MessageDigest.getInstance("SHA-256");
				macKey = sha.digest(buffer);

				final PublicKey clientPub = kp.getPublic();
				myPubKey = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(clientPub.getEncoded()) + "\n-----END PUBLIC KEY-----\n";
			}
			catch(RuntimeException e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
				throw e;
			}
			catch (final Exception e)
			{
				LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
				throw e;
			}

			final byte[] iv = ivString.toByteArray();
			final IvParameterSpec ips = new IvParameterSpec(iv);

			// Create a key specification first, based on our key input.
			final SecretKey aesKey = new SecretKeySpec(key, "AES");
			final SecretKey hmacKey = new SecretKeySpec(macKey, "AES");

			// Create a Cipher for encrypting the data using the key we created.
			Cipher encryptCipher;

			encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// Initialize the Cipher with key and parameters
			encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, ips);

			// Our cleartext
			final byte[] cleartext = pwd.getBytes(StandardCharsets.UTF_8);

			// Encrypt the cleartext
			final byte[] ciphertext = encryptCipher.doFinal(cleartext);

			final Mac hmac = Mac.getInstance("HmacSha256");
			hmac.init(hmacKey);
			final byte[] calculatedMac = hmac.doFinal(ciphertext);

			// send handshake part2
			LOGGER.log(Level.INFO, "Beginning handshake part 2");
			final ClientWireProtocol.ClientConnection2.Builder hand2 = ClientWireProtocol.ClientConnection2.newBuilder();
			hand2.setCipher(ByteString.copyFrom(ciphertext));
			hand2.setPubKey(myPubKey);
			hand2.setHmac(ByteString.copyFrom(calculatedMac));
			if (force)
			{
				hand2.setForce(true);
			}
			else if (oneShotForce)
			{
				oneShotForce = false;
				hand2.setForce(true);
			}
			else
			{
				hand2.setForce(false);
			}
			final ClientWireProtocol.ClientConnection2 msg2 = hand2.build();
			b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION2);
			b2.setClientConnection2(msg2);
			wrapper = b2.build();
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();

			// getResponse
			final ClientWireProtocol.ClientConnection2Response.Builder ccr2 = ClientWireProtocol.ClientConnection2Response.newBuilder();
			length = getLength();
			data = new byte[length];
			readBytes(data);
			ccr2.mergeFrom(data);
			response = ccr2.getResponse();
			rType = response.getType();

			LOGGER.log(Level.INFO, "Handshake response received");
			final SQLException state = new SQLException(response.getReason(), response.getSqlState(), response.getVendorCode());
			// if we had a failed handshake, then something went wrong with verification on
			// the server, just try again(up to 5 times)
			if (SQLStates.FAILED_HANDSHAKE.equals(state) && retryCounter++ < 5)
			{
				LOGGER.log(Level.INFO, "Handshake failed, retrying");
				clientHandshake(userid, pwd, db, shouldRequestVersion);
				return;
			}
			retryCounter = 0;
			processResponseType(rType, response);
			// Save the server session id.
			LOGGER.log(Level.INFO, String.format("Connected to session id: %s", ccr2.getServerSessionId()));
			serverSessionId = ccr2.getServerSessionId();
			this.session = new Session(user, pwd);
			this.sessionState = this.session.currentState; // record the current state.
			// Save the secondary interface for reconnecting and recirecting.
			saveSecondaryInterfaces(ccr2.getCmdcompsList(), ccr2.getSecondaryList());
			// Handle redirect			
			if (ccr2.getRedirect())
			{
				LOGGER.log(Level.INFO, "Redirect command in ClientConnection2Response from server");
				final String host = ccr2.getRedirectHost();
				final int port = ccr2.getRedirectPort();
				redirect(host, port, shouldRequestVersion);
				// We have a lot of dangerous circular function calls.
				// If we were redirected, then we already have the server version. We need to
				// return here.
				if (!getVersion().equals(""))
				{
					LOGGER.log(Level.INFO, "Returning in handshake redirect. Already have protocol version.");
					return;
				}
			}
		}
		catch(RuntimeException e)
		{
			LOGGER.log(Level.WARNING, String.format("Runtime Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
			throw e;
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));

			try
			{
				sock.close();
			}
			catch (final Exception f)
			{
				LOGGER.log(Level.WARNING, "Failed to close socket in clientHandshakeCBC");
			}

			throw e;
		}

		if (shouldRequestVersion)
		{
			if (serverVersion.equals(""))
			{
				fetchServerVersion();
			}
		}
		LOGGER.log(Level.INFO, "Handshake CBC Finished");
	}

	private void clientHandshakeSecurityToken(final String db, final boolean shouldRequestVersion) throws Exception
	{
		try
		{
			LOGGER.log(Level.INFO, "Beginning security token handshake");
			final ClientWireProtocol.ClientConnectionSecurityToken.Builder builder = ClientWireProtocol.ClientConnectionSecurityToken.newBuilder();
			builder.setDatabase(database);
			builder.setClientid(client);
			builder.setVersion(protocolVersion);
			String[] majorMinorVersion = clientVersion.split("\\.");
			int majorClientVersion = Integer.parseInt(majorMinorVersion[0]);
			int minorClientVersion = Integer.parseInt(majorMinorVersion[1]);
			builder.setMajorClientVersion(majorClientVersion);
			builder.setMinorClientVersion(minorClientVersion);
			builder.setSessionID(sessionID);
			// Set the security token.
			Session.SecurityToken securityToken = sessionState.securityToken.get();
			builder.setSecurityToken(securityToken.tokenData);
			builder.setTokenSignature(securityToken.tokenSignature);
			builder.setIssuerFingerprint(securityToken.issuerFingerprint);
			builder.setForce((force || oneShotForce) ? true : false);
			oneShotForce = false;
			final ClientConnectionSecurityToken msg = builder.build();
			ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION_SECURITY_TOKEN);
			b2.setClientConnectionSecurityToken(msg);
			// Write message to server
			Request wrapper = b2.build();
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			
			// get response
			final ClientWireProtocol.ClientConnectionSecurityTokenResponse.Builder tokenHandshakeResp = ClientWireProtocol.ClientConnectionSecurityTokenResponse.newBuilder();
			int length = getLength();
			byte[] data = new byte[length];
			readBytes(data);
			tokenHandshakeResp.mergeFrom(data);
			ConfirmationResponse response = tokenHandshakeResp.getResponse();
			ResponseType rType = response.getType();
			processResponseType(rType, response);
			// Log the server session ID we are connected to.
			LOGGER.log(Level.INFO, String.format("Connected to server session ID: %s", tokenHandshakeResp.getServerSessionId()));
			serverSessionId = tokenHandshakeResp.getServerSessionId();
			// Save the secondary interface for reconnecting and recirecting.
			saveSecondaryInterfaces(tokenHandshakeResp.getCmdcompsList(), tokenHandshakeResp.getSecondaryList());
			// This can only be called after a connection was copied. So it should have already had its state set.
			// Handle redirect
			if (tokenHandshakeResp.getRedirect())
			{
				LOGGER.log(Level.INFO, "Redirect command in ClientConnection2Response from server");
				final String host = tokenHandshakeResp.getRedirectHost();
				final int port = tokenHandshakeResp.getRedirectPort();
				redirect(host, port, shouldRequestVersion);
				// We have a lot of dangerous circular function calls.
				// If we were redirected, then we already have the server version. We need to
				// return here.
				if (!getVersion().equals(""))
				{
					LOGGER.log(Level.INFO, "Returning in handshake redirect. Already have protocol version.");
					return;
				}
			}			
		}
		catch(RuntimeException e)
		{
			LOGGER.log(Level.WARNING, String.format("Runtime Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
			throw e;
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));

			try
			{
				sock.close();
			}
			catch (final Exception f)
			{
				LOGGER.log(Level.WARNING, "Failed to close socket in clientHandshakeSSOToken");
			}

			throw e;
		}

		if (shouldRequestVersion)
		{
			if (serverVersion.equals(""))
			{
				fetchServerVersion();
			}
		}
		LOGGER.log(Level.INFO, "Handshake SSO with token finished");		
	}

	private void clientHandshakeSSO(final String db, final boolean shouldRequestVersion) throws Exception
	{
		try
		{
			LOGGER.log(Level.INFO, "Beginning SSO handshake without token");
			final ClientWireProtocol.ClientConnectionSSO.Builder builder = ClientWireProtocol.ClientConnectionSSO.newBuilder();
			builder.setDatabase(database);
			builder.setClientid(client);
			builder.setVersion(protocolVersion);
			String[] majorMinorVersion = clientVersion.split("\\.");
			int majorClientVersion = Integer.parseInt(majorMinorVersion[0]);
			int minorClientVersion = Integer.parseInt(majorMinorVersion[1]);
			builder.setMajorClientVersion(majorClientVersion);
			builder.setMinorClientVersion(minorClientVersion);
			builder.setSessionID(sessionID);
			final ClientConnectionSSO msg = builder.build();
			ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
			b2.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION_SSO);
			b2.setClientConnectionSso(msg);
			// Write to the server
			Request wrapper = b2.build();
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();

			// get response
			final ClientWireProtocol.ClientConnectionSSOResponse.Builder ccr = ClientWireProtocol.ClientConnectionSSOResponse.newBuilder();
			int length = getLength();
			byte[] data = new byte[length];
			readBytes(data);
			ccr.mergeFrom(data);
			ConfirmationResponse response = ccr.getResponse();
			ResponseType rType = response.getType();
			processResponseType(rType, response);
			
			final String requestID = ccr.getRequestId();
			final String authUrl = ccr.getAuthUrl();

			// Do desktop stuff with authURL.
			openAuthUrl(authUrl);
			// Poll the database.
			LOGGER.log(Level.INFO, "SSO handshake part 2, polling database");
			pollDatabase(requestID, shouldRequestVersion);
		}
		catch(RuntimeException e)
		{
			LOGGER.log(Level.WARNING, String.format("Runtime Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));
			throw e;
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during handshake with message %s", e.toString(), e.getMessage()));

			try
			{
				sock.close();
			}
			catch (final Exception f)
			{
				LOGGER.log(Level.WARNING, "Failed to close socket in clientHandshakeSSO");
			}

			throw e;
		}

		if (shouldRequestVersion)
		{
			if (serverVersion.equals(""))
			{
				fetchServerVersion();
			}
		}
		LOGGER.log(Level.INFO, "Handshake SSO without token finished");
	}

	/**
	 * Opens the authentication URL in the users default browser.
	 * Solution based on: https://stackoverflow.com/a/18509384/14315585
	 * 
	 */

	private void openAuthUrl(String authUrl) throws Exception{
		LOGGER.log(Level.INFO, String.format("Opening authUrl: %s", authUrl));

		if(Desktop.isDesktopSupported()){
			Desktop desktop = Desktop.getDesktop();
			try{
				desktop.browse(new URI(authUrl));
			} catch (Exception e) {
				LOGGER.log(Level.WARNING, String.format("Failed to open browser for URI: %s with Desktop", authUrl));
				throw e;
            }
		} else {
			String reason = String.format("Could not open default browser with Desktop library. Please proceed to the following url on a browser: %s", authUrl);
			LOGGER.log(Level.WARNING, reason);
			System.out.println(reason);
			warnings.add(new SQLWarning(reason, SQLStates.FAILED_HANDSHAKE.getSqlState(), SQLStates.FAILED_HANDSHAKE.getSqlCode()));
			// We cannot throw here as it would end the handshake.
		}
	}

	private void pollDatabase(String requestId, boolean shouldRequestVersion) throws Exception{
		LOGGER.log(Level.INFO, "Called pollDatabase()");
		final ClientWireProtocol.ClientConnectionSSO2.Builder sso2MsgBuilder = ClientWireProtocol.ClientConnectionSSO2.newBuilder();
		sso2MsgBuilder.setRequestId(requestId);
		sso2MsgBuilder.setForce((force || oneShotForce) ? true : false);
		oneShotForce = false;
		final ClientWireProtocol.ClientConnectionSSO2 sso2Msg = sso2MsgBuilder.build();
		
		ClientWireProtocol.Request.Builder reqBuilder = ClientWireProtocol.Request.newBuilder();
		reqBuilder.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION_SSO2);
		reqBuilder.setClientConnectionSso2(sso2Msg);
		// Finish the poll message. We can use it over and over.
		Request sso2Req = reqBuilder.build();

		boolean keepPolling = true;
		int waitFor = 0;
		ClientWireProtocol.ClientConnectionSSO2Response.Builder sso2ResponseBuilder = null;
		while(keepPolling){
			Thread.sleep(waitFor * 1000);
			LOGGER.log(Level.INFO, String.format("Polling database for requestId: %s", requestId));

			// Poll
			out.write(intToBytes(sso2Req.getSerializedSize()));
			sso2Req.writeTo(out);
			out.flush();

			// Receive response.
			sso2ResponseBuilder = ClientWireProtocol.ClientConnectionSSO2Response.newBuilder();
			int length = getLength();
			byte[] data = new byte[length];
			readBytes(data);
			sso2ResponseBuilder.mergeFrom(data);
			ConfirmationResponse response = sso2ResponseBuilder.getResponse();
			ResponseType rType = response.getType();
			processResponseType(rType, response);
			// If we get to this point, then we didn't get an error. Either a continue polling, or a connection succeeded.
			
			// Handle the continue polling situation.
			ResponseOneofCase responseCase = sso2ResponseBuilder.getResponseOneofCase();
			if(responseCase == ResponseOneofCase.POLLINGINTERVALSECONDS){
				// Continue polling.
				LOGGER.log(Level.INFO, "Continue polling....");
				waitFor = sso2ResponseBuilder.getPollingIntervalSeconds();
				continue;				
			} else {
				// Success
				LOGGER.log(Level.INFO, "Poll successful");
				waitFor = 0;
				keepPolling = false;				
			}
		}
		
		// Save the security token, signature, and fingerprint. They will now be used for connecting henceforth in clientHandshakeSecurityToken.
		SessionInfo sessionInfo = sso2ResponseBuilder.getSessionInfo();
		ClientWireProtocol.SecurityToken receivedSecurityToken = sessionInfo.getSecurityToken();
		// Save the server session id
		LOGGER.log(Level.INFO, String.format("Connected to session id: %s", sessionInfo.getServerSessionId()));
		serverSessionId = sessionInfo.getServerSessionId();

		this.session = new Session(
			receivedSecurityToken.getData().toString(),
			receivedSecurityToken.getSignature().toString(),
			receivedSecurityToken.getIssuerFingerprint().toString()
		);
		this.sessionState = this.session.currentState; // record the current state.
		Session.SecurityToken securityToken = sessionState.securityToken.get();
		// Save the secondary interface for reconnecting and recirecting.
		saveSecondaryInterfaces(sso2ResponseBuilder.getCmdcompsList(), sso2ResponseBuilder.getSecondaryList());
		// Handle redirect
		if (sso2ResponseBuilder.getRedirect())
		{
			LOGGER.log(Level.INFO, "Redirect command in pollDatabase from server");
			final String host = sso2ResponseBuilder.getRedirectHost();
			final int port = sso2ResponseBuilder.getRedirectPort();
			redirect(host, port, shouldRequestVersion);
			// We have a lot of dangerous circular function calls.
			// If we were redirected, then we already have the server version. We need to
			// return here.
			if (!getVersion().equals(""))
			{
				LOGGER.log(Level.INFO, "Returning in handshake redirect. Already have protocol version.");
				return;
			}
		}
	}	

	@Override
	public void close() throws SQLException
	{
		LOGGER.log(Level.INFO, "close() called on the connection");
		if (closed)
		{
			return;
		}

		if (rs != null && !rs.isClosed())
		{
			rs.getStatement().cancel();
		}

		closed = true;

		if (sock != null)
		{
			try
			{
				sendClose();
			}
			catch (final Exception e)
			{
			}
		}

		try
		{
			if (in != null)
			{
				in.close();
			}

			if (out != null)
			{
				out.close();
			}

			if (sock != null)
			{
				sock.close();
			}
		}
		catch (final Exception e)
		{
		}

		// Cleanup our timer, if one exists
		Timer t = null;
		do
		{
			t = timer.get();
			if (t == null)
			{
				return;
			}
		}
		while (!timer.compareAndSet(t, null));
		t.cancel();
	}

	@Override
	public void commit() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called commit()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "commit() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		// !!!!!!!!!!!!!! NO-OP !!!!!!!!!!!!!!!!!!!
	}

	public void connect() throws Exception
	{
		connect(ip, portNum);
		try
		{
			clientHandshake(user, pwd, database, true);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, "Failed to connect()");
			throw e;
		}
	}

	private void connect(final String ip, final int port) throws Exception
	{
		LOGGER.log(Level.INFO, String.format("Trying to connect to IP: %s at port: %d", ip, port));
		try
		{
			switch (tls)
			{
				case OFF:
					LOGGER.log(Level.INFO, "Unencrypted connection");
					sock = new Socket();
					sock.setReceiveBufferSize(4194304);
					sock.setSendBufferSize(4194304);
					sock.connect(new InetSocketAddress(ip, port), networkTimeout);
					in = new BufferedInputStream(sock.getInputStream());
					out = new BufferedOutputStream(sock.getOutputStream());
					connectedIp = ip;
					connectedPort = port;
					break;

				case UNVERIFIED:
				case ON:
				case VERIFY:
					LOGGER.log(Level.INFO, "TLS Connection " + tls.name());
					final SSLContext sc = SSLContext.getInstance("TLS");

					final TrustManager[] tms = new TrustManager[] { new XGTrustManager(tls) };

					sc.init(null, tms, null);
					final SSLSocketFactory sslsocketfactory = sc.getSocketFactory();
					final SSLSocket sslsock = (SSLSocket) sslsocketfactory.createSocket(ip, port);
					sslsock.setReceiveBufferSize(4194304);
					sslsock.setSendBufferSize(4194304);
					sslsock.setUseClientMode(true);
					sslsock.startHandshake();
					sock = sslsock;
					in = new BufferedInputStream(sock.getInputStream());
					out = new BufferedOutputStream(sock.getOutputStream());
					connectedIp = ip;
					connectedPort = port;
					break;
			}
		}
		catch (final Exception e)
		{
			try
			{
				if (in != null)
				{
					in.close();
					in = null;
				}

			}
			catch (final IOException f)
			{
			}
			try
			{
				if (out != null)
				{
					out.close();
					out = null;
				}
			}
			catch (final IOException f)
			{
			}
			try
			{
				if (sock != null)
				{
					sock.close();
					sock = null;
				}
			}
			catch (final IOException f)
			{
			}
			throw e;
		}
	}

	/*
	 * Is the connection currently connected?
	 */
	public boolean connected()
	{
		return connected;
	}

	public XGConnection copy() throws SQLException
	{
		return copy(false, false);
	}

	public XGConnection copy(final boolean shouldRequestVersion) throws SQLException
	{
		return copy(shouldRequestVersion, false);
	}

	@SuppressWarnings("unchecked")
	public XGConnection copy(final boolean shouldRequestVersion, final boolean noRedirect) throws SQLException
	{
		boolean doForce = force;
		if (noRedirect)
		{
			doForce = true;
		}

		final XGConnection retval = new XGConnection(user, pwd, portNum, url, database, protocolVersion, clientVersion, doForce, tls, properties);
		try
		{
			retval.connected = false;
			retval.setSchema = setSchema;
			retval.defaultSchema = defaultSchema;
			retval.setPso = setPso;
			retval.timeoutMillis = timeoutMillis;
			retval.networkTimeout = networkTimeout;
			retval.cmdcomps = (ArrayList<String>) cmdcomps.clone();
			retval.secondaryInterfaces = (ArrayList<ArrayList<String>>) secondaryInterfaces.clone();
			retval.secondaryIndex = secondaryIndex;
			retval.ip = ip;
			retval.originalIp = originalIp;
			retval.connectedIp = connectedIp;
			retval.connectedPort = connectedPort;
			retval.originalPort = originalPort;
			retval.tls = tls;
			retval.serverVersion = serverVersion;
			// Pass on the session manager. By reference
			retval.session = session;
			// Have the newly copied connection save its own view of the world.
			final Optional<Session.State> maybeState = session.retain();
			if(maybeState.isPresent()){
				retval.sessionState = maybeState.get();
			} else {
				// Attempted to duplicate a closed session.
				throw SQLStates.FAILED_CONNECTION.cloneAndSpecify("Attempted to duplicate a closed session");
			}			
			retval.reconnect(shouldRequestVersion);
			retval.resetLocalVars();
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.SEVERE, String.format("Copying the connection for a new statement failed with exception %s with message %s", e.toString(), e.getMessage()));
			try
			{
				retval.close();
			}
			catch (final Exception f)
			{
			}
			throw new SQLException(e);
		}

		return retval;
	}

	@Override
	public Array createArrayOf(final String arg0, final Object[] arg1) throws SQLException
	{
		LOGGER.log(Level.WARNING, "createArrayOf() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Blob createBlob() throws SQLException
	{
		LOGGER.log(Level.WARNING, "createBlob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Clob createClob() throws SQLException
	{
		LOGGER.log(Level.WARNING, "createClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public NClob createNClob() throws SQLException
	{
		LOGGER.log(Level.WARNING, "createNClob() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public SQLXML createSQLXML() throws SQLException
	{
		LOGGER.log(Level.WARNING, "createSQLXML() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Statement createStatement() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called createStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "createStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (oneShotForce)
		{
			oneShotForce = false; // The statement inherits our one shot
			return XGStatement.newXGStatement(this, force, true);
		}
		else
		{
			return XGStatement.newXGStatement(this, force, false);
		}
	}

	@Override
	public Statement createStatement(final int arg0, final int arg1) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called createStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "createStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (oneShotForce)
		{
			oneShotForce = false; // Statement inherits our one shot
			return XGStatement.newXGStatement(this, arg0, arg1, force, true);
		}
		else
		{
			return XGStatement.newXGStatement(this, arg0, arg1, force, false);
		}
	}

	@Override
	public Statement createStatement(final int arg0, final int arg1, final int arg2) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called createStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "createStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (oneShotForce)
		{
			oneShotForce = false; // Statement inherits our one shot
			return XGStatement.newXGStatement(this, arg0, arg1, arg2, force, true);
		}
		else
		{
			return XGStatement.newXGStatement(this, arg0, arg1, arg2, force, false);
		}
	}

	@Override
	public Struct createStruct(final String arg0, final Object[] arg1) throws SQLException
	{
		LOGGER.log(Level.WARNING, "createStruct() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public boolean equals(final Object o)
	{
		if (!(o instanceof XGConnection))
		{
			return false;
		}

		final XGConnection other = (XGConnection) o;
		return this == o || originalIp.equals(other.originalIp) && originalPort == other.originalPort && user.equals(other.user) && pwd.equals(other.pwd) && database.equals(other.database)
			&& tls.equals(other.tls) && properties.equals(other.properties);
	}

	void fetchServerVersion() throws Exception
	{
		LOGGER.log(Level.INFO, "Attempting to fetch server version");
		try
		{
			final XGStatement stmt = XGStatement.newXGStatement(this, false);
			final String version = stmt.fetchSystemMetadataString(ClientWireProtocol.FetchSystemMetadata.SystemMetadataCall.GET_DATABASE_PRODUCT_VERSION);
			LOGGER.log(Level.INFO, String.format("Fetched server version: %s", version));
			setServerVersion(version);
			stmt.close();
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred while fetching server version with message %s", e.toString(), e.getMessage()));
			try
			{
				sock.close();
			}
			catch (final Exception f)
			{
			}

			throw e;
		}
	}

	public void forceExternal(final boolean force) throws Exception
	{
		LOGGER.log(Level.INFO, "Sending force external request to the server");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "Force external request is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		// send request
		final ClientWireProtocol.ForceExternal.Builder builder = ClientWireProtocol.ForceExternal.newBuilder();
		builder.setForce(force);
		final ForceExternal msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.FORCE_EXTERNAL);
		b2.setForceExternal(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			getStandardResponse();
		}
		catch (final IOException e)
		{
			// Doesn't matter...
			LOGGER.log(Level.WARNING, String.format("Failed sending set schema request to the server with exception %s with message %s", e.toString(), e.getMessage()));
		}
	}

	@Override
	public boolean getAutoCommit() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getAutoCommit()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getAutoCommit() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}
		return true;
	}

	@Override
	public String getCatalog() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getCatalog()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getCatalog() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}
		return null;
	}

	@Override
	public Properties getClientInfo() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getClientInfo()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getClientInfo() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return new Properties();
	}

	@Override
	public String getClientInfo(final String arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getClientInfo()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getClientInfo() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return null;
	}

	public String getDB()
	{
		return database;
	}

	public Properties getProperties(){
		return properties;
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

	private int getLength() throws Exception
	{
		final byte[] inMsg = new byte[4];

		int count = 0;
		while (count < 4)
		{
			final int temp = in.read(inMsg, count, 4 - count);
			if (temp == -1)
			{
				throw new IOException();
			}

			count += temp;
		}

		return bytesToInt(inMsg);
	}

	public int getMajorVersion()
	{
		return Integer.parseInt(protocolVersion.substring(0, protocolVersion.indexOf(".")));
	}

	@Override
	public DatabaseMetaData getMetaData() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getMetaData()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getMetaData() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return new XGDatabaseMetaData(this);
	}

	public int getMinorVersion()
	{
		final int i = protocolVersion.indexOf(".") + 1;
		return Integer.parseInt(protocolVersion.substring(i, protocolVersion.indexOf(".", i)));
	}

	@Override
	public int getNetworkTimeout() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getNetworkTimeout()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getNetworkTimeout() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}
		return networkTimeout;
	}

	@Override
	public String getSchema() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getSchema()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getSchema() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}
		try
		{
			return getSchemaFromServer();
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during getSchema() with message %s", e.toString(), e.getMessage()));
			if (e instanceof SQLException)
			{
				throw (SQLException) e;
			}
			else
			{
				throw SQLStates.newGenericException(e);
			}
		}
	}

	public String getSchemaLocal(){
		LOGGER.log(Level.INFO, "Called getSchemaLocal()");
		return setSchema;
	}

	public void setSchemaLocal(String newSchema){
		LOGGER.log(Level.INFO, String.format("Called setSchemaLocal() to set new schema: %s", newSchema));
		setSchema = newSchema;
	}

	private String getSchemaFromServer() throws Exception
	{
		// send request
		final ClientWireProtocol.GetSchema.Builder builder = ClientWireProtocol.GetSchema.newBuilder();
		final GetSchema msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.GET_SCHEMA);
		b2.setGetSchema(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
		}
		catch (final IOException | NullPointerException e)
		{		
			if (!setSchema.equals(""))
			{
				return setSchema;
			}
			else
			{
				reconnect();
				return getSchemaFromServer();
			}
		}

		// get response
		final ClientWireProtocol.GetSchemaResponse.Builder gsr = ClientWireProtocol.GetSchemaResponse.newBuilder();

		try
		{
			final int length = getLength();
			final byte[] data = new byte[length];
			readBytes(data);
			gsr.mergeFrom(data);
		}
		catch (SQLException | IOException e)
		{			
			if (e instanceof SQLException && !SQLStates.UNEXPECTED_EOF.equals((SQLException) e))
			{
				throw e;
			}

			if (!setSchema.equals(""))
			{
				return setSchema;
			}
			else
			{
				reconnect();
				return getSchemaFromServer();
			}
		}

		final ConfirmationResponse response = gsr.getResponse();
		final ResponseType rType = response.getType();
		try{
			processResponseType(rType, response);
		} catch (SQLException e){
			if(e instanceof SQLException && SQLStates.SESSION_EXPIRED.equals((SQLException) e)){
				LOGGER.log(Level.INFO, "getSchemaFromServer() received session expired. Attempting to refresh session");
				// Refresh my session.
				this.refreshSession();
				// Now we should be able to re-run the command.
				return getSchemaFromServer();
			} else {
				throw e;
			}
		}
		LOGGER.log(Level.INFO, String.format("Got schema: %s from server", gsr.getSchema()));
		return gsr.getSchema();
	}

	public String getServerVersion()
	{
		return serverVersion;
	}

	private void getStandardResponse() throws Exception
	{
		final int length = getLength();
		final byte[] data = new byte[length];
		readBytes(data);
		final ConfirmationResponse.Builder rBuild = ConfirmationResponse.newBuilder();
		rBuild.mergeFrom(data);
		final ResponseType rType = rBuild.getType();
		processResponseType(rType, rBuild.build());
	}

	protected long getTimeoutMillis()
	{
		return timeoutMillis;
	}

	/**
	 * Creates a new {@link Timer} or returns the existing one if it already exists
	 */
	private Timer getTimer()
	{
		return timer.updateAndGet(existing -> existing != null ? existing : new Timer(true));
	}

	@Override
	public int getTransactionIsolation() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called getTransactionIsolation()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "getTransactionIsolation() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return Connection.TRANSACTION_NONE;
	}

	@Override
	public Map<String, Class<?>> getTypeMap() throws SQLException
	{
		return typeMap;
	}

	public String getURL()
	{
		return url;
	}

	public String getUser()
	{
		return user;
	}

	public String getVersion()
	{
		return protocolVersion;
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

	/*!
	 * Add connection level settings here so that connections with different settings map to different hash codes.
	 */
	@Override
	public int hashCode()
	{
		int hash = originalIp.hashCode() + originalPort + user.hashCode()
		+ pwd.hashCode() + database.hashCode() + tls.hashCode() 
		+ properties.hashCode() + setSchema.hashCode() + Long.hashCode(setPso) 
		+ (force ? 1 : 0) + Long.hashCode(timeoutMillis) + networkTimeout;
		hash += maxRows == null ? 0 : maxRows.hashCode();
		hash += maxTime == null ? 0 : maxTime.hashCode();
		hash += maxTempDisk == null ? 0 : maxTempDisk.hashCode();
		hash += parallelism == null ? 0 : parallelism.hashCode();
		hash += priority == null ? 0 : priority.hashCode();

		return hash;
	}

	@Override
	public boolean isClosed() throws SQLException
	{
		return closed;
	}

	@Override
	public boolean isReadOnly() throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isReadOnly()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "isReadOnly() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return false;
	}

	/*
	 * ! Utility for checking if the previously connected ip and port is still
	 * available.
	 */
	boolean isSockConnected()
	{
		try
		{
			final Socket testSocket = new Socket();
			testSocket.connect(new InetSocketAddress(connectedIp, connectedPort), networkTimeout);
			testSocket.close();
			return true;
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, "isSockConnected() discovered connection is not working.");
			return false;
		}
	}

	@Override
	public boolean isValid(final int arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isValid()");
		if (arg0 < 0)
		{
			LOGGER.log(Level.WARNING, "isValid() is throwing INVALID_ARGUMENT");
			throw SQLStates.INVALID_ARGUMENT.clone();
		}

		if (closed)
		{
			LOGGER.log(Level.WARNING, "Returning false from isValid() because connection is closed");
			return false;
		}

		boolean retval = false;
		try
		{
			final XGConnection clone = copy();
			retval = copy().testConnection(arg0);
			clone.close();
		}
		catch (final Exception e)
		{
		}

		if (!retval)
		{
			LOGGER.log(Level.SEVERE, "Returning false from isValid() because connection test failed");
		}

		return retval;
	}

	@Override
	public boolean isWrapperFor(final Class<?> iface) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called isWrapperFor()");
		return false;
	}

	@Override
	public String nativeSQL(final String arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called nativeSQL()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "nativeSQL() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		return arg0;
	}

	@Override
	public CallableStatement prepareCall(final String arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "prepareCall() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public CallableStatement prepareCall(final String arg0, final int arg1, final int arg2) throws SQLException
	{
		LOGGER.log(Level.WARNING, "prepareCall() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public CallableStatement prepareCall(final String arg0, final int arg1, final int arg2, final int arg3) throws SQLException
	{
		LOGGER.log(Level.WARNING, "prepareCall() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public PreparedStatement prepareStatement(final String arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called prepareStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "prepareStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (oneShotForce)
		{
			oneShotForce = false; // Statement inherits our one shot
			return XGPreparedStatement.newXGPreparedStatement(this, arg0, force, true);
		}
		else
		{
			return XGPreparedStatement.newXGPreparedStatement(this, arg0, force, false);
		}
	}

	@Override
	public PreparedStatement prepareStatement(final String arg0, final int arg1) throws SQLException
	{
		LOGGER.log(Level.WARNING, "prepareStatement() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public PreparedStatement prepareStatement(final String arg0, final int arg1, final int arg2) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called prepareStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "prepareStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (oneShotForce)
		{
			oneShotForce = false; // Statement inherits our one shot
			return XGPreparedStatement.newXGPreparedStatement(this, arg0, arg1, arg2, force, true);
		}
		else
		{
			return XGPreparedStatement.newXGPreparedStatement(this, arg0, arg1, arg2, force, false);
		}
	}

	@Override
	public PreparedStatement prepareStatement(final String arg0, final int arg1, final int arg2, final int arg3) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called prepareStatement()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "prepareStatement() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (oneShotForce)
		{
			oneShotForce = false; // Statement inherits our one shot
			return XGPreparedStatement.newXGPreparedStatement(this, arg0, arg1, arg2, arg3, force, true);
		}
		else
		{
			return XGPreparedStatement.newXGPreparedStatement(this, arg0, arg1, arg2, arg3, force, false);
		}
	}

	@Override
	public PreparedStatement prepareStatement(final String arg0, final int[] arg1) throws SQLException
	{
		LOGGER.log(Level.WARNING, "prepareStatement() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public PreparedStatement prepareStatement(final String arg0, final String[] arg1) throws SQLException
	{
		LOGGER.log(Level.WARNING, "prepareStatement() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	private void processResponseType(final ResponseType rType, final ConfirmationResponse response) throws SQLException
	{
		if (rType.equals(ResponseType.INVALID))
		{
			LOGGER.log(Level.WARNING, "Server returned an invalid response");
			throw SQLStates.INVALID_RESPONSE_TYPE.clone();
		}
		else if (rType.equals(ResponseType.RESPONSE_ERROR))
		{
			final String reason = response.getReason();
			final String sqlState = response.getSqlState();
			final int code = response.getVendorCode();
			LOGGER.log(Level.WARNING, String.format("Server returned an error response [%s] %s", sqlState, reason));
			throw new SQLException(reason, sqlState, code);
		}
		else if (rType.equals(ResponseType.RESPONSE_WARN))
		{
			final String reason = response.getReason();
			final String sqlState = response.getSqlState();
			final int code = response.getVendorCode();
			LOGGER.log(Level.WARNING, String.format("Server issued a warning response [%s] %s", sqlState, reason));
			warnings.add(new SQLWarning(reason, sqlState, code));
		}
	}

	/**
	 * Purges all canceled tasks from the timer.
	 *
	 * <p>
	 * Note: You should only call this if you've canceled a timer. This call may
	 * create a {@link Timer} object if one does not already exist
	 */
	protected void purgeTimeoutTasks()
	{
		getTimer().purge();
	}

	private void readBytes(final byte[] data) throws Exception
	{
		final int z = data.length;
		int count = 0;
		while (count < z)
		{
			final int temp = in.read(data, count, z - count);
			if (temp == -1)
			{
				throw new IOException();
			}

			count += temp;
		}
	}

	public void reconnect() throws IOException, SQLException
	{
		reconnect(false);
	}

	/*
	 * We seem to have lost our connection. Reconnect to any cmdcomp
	 */
	public void reconnect(final boolean shouldRequestVersion) throws IOException, SQLException
	{
		// Try to find any cmdcomp that we can connect to
		// If we can't connect to any throw IOException

		// There's an issue here that we don't want to force
		// But we could get redirected back to the dead node
		// Until the heartbeat timeout happens
		// Which could be up to 30 seconds
		// If the redirect fails, it will call reconnect
		// And we will end up looping until the heartbeat times out
		// In 30 seconds, we would totally blow out the stack

		// Even forcing, it only guarantees the first request after reconnect
		// is forced, which if the client is making a fast series of short
		// requests, puts us in the same situation

		// We solve this by delaying slightly, which will slow the rate
		// of stack growth enough that we will be ok
		LOGGER.log(Level.INFO, String.format("Entered reconnect() with shouldRequestVersion: %b", shouldRequestVersion));
		try
		{
			Thread.sleep(250);
		}
		catch (final InterruptedException e)
		{
		}

		try
		{
			if (in != null)
			{
				in.close();
			}

			if (out != null)
			{
				out.close();
			}

			if (sock != null)
			{
				sock.close();
			}
		}
		catch (final IOException e)
		{
			LOGGER.log(Level.WARNING, "Reconnect failed to close a previous socket.");
		}

		if (force)
		{
			LOGGER.log(Level.INFO, "Forced reconnection.");
			sock = null;
			try
			{
				connect(ip, portNum);
			}
			catch (final Exception e)
			{
				// reconnect failed so we are no longer connected
				connected = false;

				LOGGER.log(Level.WARNING, String.format("Exception %s occurred in reconnect() with message %s", e.toString(), e.getMessage()));
				if (e instanceof IOException)
				{
					throw (IOException) e;
				}

				throw new IOException();
			}

			try
			{
				clientHandshake(user, pwd, database, shouldRequestVersion);
				if (!setSchema.equals(""))
				{
					setSchema(setSchema);
				}

				if (setPso == -1)
				{
					// We have to turn it off
					setPSO(false);
				}
				else if (setPso > 0)
				{
					// Set non-default threshold
					setPSO(setPso);
				}

				resendParameters();

				return;
			}
			catch (final Exception handshakeException)
			{
				try
				{
					in.close();
					out.close();
					sock.close();
				}
				catch (final IOException f)
				{
				}

				// reconnect failed so we are no longer connected
				connected = false;

				// Failed on the client handshake, so capture exception
				if (handshakeException instanceof SQLException)
				{
					throw (SQLException) handshakeException;
				}

				throw new IOException();
			}
		}

		// capture any exception from trying to connect
		SQLException retVal = null;
		if (secondaryIndex != -1)
		{
			LOGGER.log(Level.INFO, "reconnect() Trying secondary interfaces");
			for (final ArrayList<String> list : secondaryInterfaces)
			{
				final String cmdcomp = list.get(secondaryIndex);
				final StringTokenizer tokens = new StringTokenizer(cmdcomp, ":", false);
				final String host = tokens.nextToken();
				final int port = Integer.parseInt(tokens.nextToken());

				// Try to connect to this one
				ip = host;

				sock = null;
				try
				{
					connect(host, port);
				}
				catch (final Exception e)
				{
					LOGGER.log(Level.WARNING, String.format("Exception %s occurred in reconnect() with message %s", e.toString(), e.getMessage()));
					continue;
				}

				portNum = port;
				try
				{
					clientHandshake(user, pwd, database, shouldRequestVersion);
					if (!setSchema.equals(""))
					{
						setSchema(setSchema);
					}

					if (setPso == -1)
					{
						// We have to turn it off
						setPSO(false);
					}
					else if (setPso > 0)
					{
						// Set non-default threshold
						setPSO(setPso);
					}

					resendParameters();

					return;
				}
				catch (final Exception handshakeException)
				{
					try
					{
						in.close();
						out.close();
						sock.close();
					}
					catch (final IOException f)
					{
					}
					// Failed on the client handshake, so capture exception
					if (handshakeException instanceof SQLException)
					{
						retVal = (SQLException) handshakeException;
						LOGGER.log(Level.WARNING, String.format("Handshake exception %s occurred in reconnect() with message %s", retVal.toString(), retVal.getMessage()));
					}
				}
				// reconnect failed so we are no longer connected
				connected = false;
			}
		}

		// We should just try them all
		for (final ArrayList<String> list : secondaryInterfaces)
		{
			LOGGER.log(Level.WARNING, "Trying secondary interfaces again");
			int index = 0;
			for (final String cmdcomp : list)
			{
				final StringTokenizer tokens = new StringTokenizer(cmdcomp, ":", false);
				final String host = tokens.nextToken();
				final int port = Integer.parseInt(tokens.nextToken());

				// Try to connect to this one
				ip = host;

				sock = null;
				try
				{
					connect(host, port);
				}
				catch (final Exception e)
				{
					LOGGER.log(Level.WARNING, String.format("Exception %s occurred in reconnect() with message %s", e.toString(), e.getMessage()));
					index++;
					continue;
				}

				portNum = port;
				try
				{
					clientHandshake(user, pwd, database, shouldRequestVersion);
					if (!setSchema.equals(""))
					{
						setSchema(setSchema);
					}

					if (setPso == -1)
					{
						// We have to turn it off
						setPSO(false);
					}
					else if (setPso > 0)
					{
						// Set non-default threshold
						setPSO(setPso);
					}

					resendParameters();
					secondaryIndex = index;
					return;
				}
				catch (final Exception handshakeException)
				{
					try
					{
						in.close();
						out.close();
						sock.close();
					}
					catch (final IOException f)
					{
					}
					// Failed on the client handshake, so capture exception
					if (handshakeException instanceof SQLException)
					{
						retVal = (SQLException) handshakeException;
						LOGGER.log(Level.WARNING, String.format("Handshake exception %s occurred in reconnect() with message %s", retVal.toString(), retVal.getMessage()));
					}
				}
				// reconnect failed so we are no longer connected
				connected = false;
				index++;
			}
		}

		sock = null;
		ip = originalIp;
		portNum = originalPort;
		try
		{
			LOGGER.log(Level.INFO, "reconnect() Trying original IP and port.");
			connect(ip, portNum);
		}
		catch (final Exception e)
		{
			// reconnect failed so we are no longer connected
			connected = false;

			LOGGER.log(Level.WARNING, String.format("Exception %s occurred in reconnect() with message %s", e.toString(), e.getMessage()));
			if (e instanceof IOException)
			{
				throw (IOException) e;
			}

			throw new IOException("Failed to reconnect.");
		}

		try
		{
			clientHandshake(user, pwd, database, shouldRequestVersion);
			if (!setSchema.equals(""))
			{
				setSchema(setSchema);
			}

			if (setPso == -1)
			{
				// We have to turn it off
				setPSO(false);
			}
			else if (setPso > 0)
			{
				// Set non-default threshold
				setPSO(setPso);
			}

			resendParameters();
		}
		catch (final Exception handshakeException)
		{
			try
			{
				in.close();
				out.close();
				sock.close();
			}
			catch (final IOException f)
			{
			}

			// reconnect failed so we are no longer connected
			connected = false;

			// Failed on the client handshake, so capture exception
			if (handshakeException instanceof SQLException)
			{
				throw (SQLException) handshakeException;
			}

			throw new IOException("Failed to reconnect.");
		}
	}

	/*
	 * We have to told to redirect our request elsewhere.
	 */
	public void redirect(final String host, final int port, final boolean shouldRequestVersion) throws IOException, SQLException
	{
		LOGGER.log(Level.INFO, String.format("redirect(). Getting redirected to host: %s and port: %d", host, port));
		oneShotForce = true;

		// Close current connection
		try
		{
			in.close();
			out.close();
			sock.close();
		}
		catch (final IOException e)
		{
		}

		// Figure out the correct interface to use
		boolean tryAllInList = false;
		int listToTry = 0;
		if (secondaryIndex != -1)
		{
			final String combined = host + ":" + port;
			int listIndex = 0;
			for (final ArrayList<String> list : secondaryInterfaces)
			{
				if (list.get(0).equals(combined))
				{
					break;
				}

				listIndex++;
			}

			if (listIndex < secondaryInterfaces.size())
			{
				final StringTokenizer tokens = new StringTokenizer(secondaryInterfaces.get(listIndex).get(secondaryIndex), ":", false);
				ip = tokens.nextToken();
				portNum = Integer.parseInt(tokens.nextToken());
			}
			else
			{
				ip = host;
				portNum = port;
			}
		}
		else
		{
			final String combined = host + ":" + port;
			int listIndex = 0;
			for (final ArrayList<String> list : secondaryInterfaces)
			{
				if (list.get(0).equals(combined))
				{
					break;
				}

				listIndex++;
			}

			if (listIndex < secondaryInterfaces.size())
			{
				tryAllInList = true;
				listToTry = listIndex;
			}
			else
			{
				ip = host;
				portNum = port;
			}
		}

		if (!tryAllInList)
		{
			sock = null;
			try
			{
				connect(ip, portNum);
			}
			catch (final Exception e)
			{

				LOGGER.log(Level.WARNING, String.format("Exception %s occurred in redirect() with message %s", e.toString(), e.getMessage()));
				reconnect();
				return;
			}

			try
			{
				clientHandshake(user, pwd, database, shouldRequestVersion);
				oneShotForce = true;
				if (!setSchema.equals(""))
				{
					setSchema(setSchema);
				}

				if (setPso == -1)
				{
					// We have to turn it off
					setPSO(false);
				}
				else if (setPso > 0)
				{
					// Set non-default threshold
					setPSO(setPso);
				}

				resendParameters();
			}
			catch (final Exception e)
			{
				try
				{
					in.close();
					out.close();
					sock.close();
				}
				catch (final IOException f)
				{
				}

				reconnect();
			}
		}
		else
		{
			for (final String cmdcomp : secondaryInterfaces.get(listToTry))
			{
				final StringTokenizer tokens = new StringTokenizer(cmdcomp, ":", false);
				ip = tokens.nextToken();
				portNum = Integer.parseInt(tokens.nextToken());

				sock = null;
				try
				{
					connect(ip, portNum);
				}
				catch (final Exception e)
				{
					LOGGER.log(Level.WARNING, String.format("Exception %s occurred in redirect() with message %s", e.toString(), e.getMessage()));
					continue;
				}

				try
				{
					clientHandshake(user, pwd, database, shouldRequestVersion);
					oneShotForce = true;
					if (!setSchema.equals(""))
					{
						setSchema(setSchema);
					}

					if (setPso == -1)
					{
						// We have to turn it off
						setPSO(false);
					}
					else if (setPso > 0)
					{
						// Set non-default threshold
						setPSO(setPso);
					}

					resendParameters();

					return;
				}
				catch (final Exception e)
				{
					try
					{
						in.close();
						out.close();
						sock.close();
					}
					catch (final IOException f)
					{
					}
				}
			}

			reconnect(); // Everything else failed, so just call reconnect()
		}
	}

	@Override
	public void releaseSavepoint(final Savepoint arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "releaseAvepoint() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	/**
	 * Validates certain default properties and throws if an invalid properties
	 * is invalid. The checks here is the intersection of the set of parameters being sent in
	 * resendParameters and the set of those with limits in serviceClass.cpp (server side)
	 */

	
	private void validateDefaultProperties(Properties properties) throws SQLException 
	{
		LOGGER.log(Level.INFO, "Called validateDefaultProperties()");
		if (properties.containsKey("maxRows") && properties.get("maxRows") != null)
		{
			int proposedMaxRows = Integer.parseInt((String) properties.get("maxRows"));
			if((proposedMaxRows < 1) && (proposedMaxRows != -1)){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("maxrows must be a positive integer or -1 for infinite, specified: %d", proposedMaxRows));
			}
		}
		if (properties.containsKey("maxTempDisk") && properties.get("maxTempDisk") != null)
		{
			int proposedMaxTempDisk = Integer.parseInt((String) properties.get("maxTempDisk"));
			if((proposedMaxTempDisk < 0) || (proposedMaxTempDisk > 100)){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("max_temp_disk_usage must be a percentage between 0 and 100, specified: %d", proposedMaxTempDisk));
			}			
		}
		if (properties.containsKey("maxTime") && properties.get("maxTime") != null)
		{
			int proposedMaxTime = Integer.parseInt((String) properties.get("maxTime"));
			if((proposedMaxTime < 1) && (proposedMaxTime != -1)){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("max time must be a positive integer or -1 for infinite, specified: %d", proposedMaxTime));
			}		
		}
		// Parallelism is not checked.
		if (properties.containsKey("priority") && properties.get("priority") != null)
		{
			double proposedPriority = Double.parseDouble((String) properties.get("priority"));
			if(proposedPriority <= 0.0){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("scheduling priority must be greater than 0.0, specified: %d", proposedPriority));
			}
		}
		// Not sent to server. Only used driver side.
		if (properties.containsKey("networkTimeout") && properties.get("networkTimeout") != null)
		{
			int proposedNetworkTimeout = Integer.parseInt((String) properties.get("networkTimeout"));
			if(proposedNetworkTimeout <= 0){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("network timeout must be greater than 0, specified: %d", proposedNetworkTimeout));
			}
		}
		if (properties.containsKey("longQueryThreshold") && properties.get("longQueryThreshold") != null)
		{
			int proposedSetPso = Integer.parseInt((String) properties.get("longQueryThreshold"));
			if(proposedSetPso < -1){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("longQueryThreshold greater than 0 to specify, 0 for server default, -1 for no deep optimization. specified: %d", proposedSetPso));
			}			
		}
		// Not sent to server. Only used driver side.
		if (properties.containsKey("timeoutMillis") && properties.get("timeoutMillis") != null)
		{
			long proposedTimeoutMillis = Long.parseLong((String) properties.get("timeoutMillis"));
			if(proposedTimeoutMillis < 0){
				throw SQLStates.INVALID_ARGUMENT.cloneAndSpecify(String.format("timeoutMillis must be greater than or equal to 0. 0 means no timeout specified: %d", proposedTimeoutMillis));
			}
		}		
		LOGGER.log(Level.INFO, "Passed validateDefaultProperties()");
	}		

	/**
	 * Resends parameters to the server. Anything sent here should be verified in validateDefaulProperties
	 * so that there are no invalid defaults being sent.
	 */

	private void resendParameters()
	{
		LOGGER.log(Level.INFO, "resendParameters() called");
		try{
			if (maxRows != null)
			{
				setMaxRowsHardLimit(maxRows, false);
			} else {
				setMaxRowsHardLimit(0, true);
			}
			if (maxTime != null)
			{
				setMaxTime(maxTime, false);
			} else {
				setMaxTime(0, true);
			}
			if (maxTempDisk != null)
			{
				setMaxTempDisk(maxTempDisk, false);
			} else {
				setMaxTempDisk(0, true);
			}
			if (parallelism != null)
			{
				setParallelism(parallelism, false);
			} else {
				setParallelism(0, true);
			}
			if (priority != null)
			{
				setPriority(priority, false);
			} else {
				setPriority(0.0, true);
			}
		} catch (SQLException e){
			// This should never happen. We protect against bad arguments for these settings in the driver default. Also, we protect
			// against them when these methods are called from statement.executeUpdate(...). So the arguments here should always be valid.
			LOGGER.log(Level.WARNING, String.format("resendParameters go unexpected exception %s with message %s", e.toString(), e.getMessage()));
		}
	}

	void reset()
	{
		warnings.clear();
		force = false;
		oneShotForce = false;
		typeMap = new HashMap<>();

		resetLocalVars();

		// Now replay those settings to the server
		try
		{
			setSchema(setSchema);
		}
		catch (final Exception e)
		{
		}

		try
		{
			if (setPso == -1)
			{
				// We have to turn it off
				setPSO(false);
			}
			else if (setPso > 0)
			{
				// Set non-default threshold
				setPSO(setPso);
			}
			else
			{
				setPSO(true);
			}
		}
		catch (final Exception e)
		{
		}
		
		resendParameters();
	}

	void resetLocalVars()
	{
		// Reset all the member variables
		if (properties.containsKey("maxRows") && properties.get("maxRows") != null)
		{
			maxRows = Integer.parseInt((String) properties.get("maxRows"));
		}
		else
		{
			maxRows = null;
		}

		if (properties.containsKey("maxTempDisk") && properties.get("maxTempDisk") != null)
		{
			maxTempDisk = Integer.parseInt((String) properties.get("maxTempDisk"));
		}
		else
		{
			maxTempDisk = null;
		}

		if (properties.containsKey("maxTime") && properties.get("maxTime") != null)
		{
			maxTime = Integer.parseInt((String) properties.get("maxTime"));
		}
		else
		{
			maxTime = null;
		}

		if (properties.containsKey("networkTimeout") && properties.get("networkTimeout") != null)
		{
			networkTimeout = Integer.parseInt((String) properties.get("networkTimeout"));
		}
		else
		{
			networkTimeout = 10000;
		}

		if (properties.containsKey("priority") && properties.get("priority") != null)
		{
			priority = Double.parseDouble((String) properties.get("priority"));
		}
		else
		{
			priority = null;
		}

		if (properties.containsKey("longQueryThreshold") && properties.get("longQueryThreshold") != null)
		{
			setPso = Integer.parseInt((String) properties.get("longQueryThreshold"));
		}
		else
		{
			setPso = 0;
		}

		if (properties.containsKey("defaultSchema") && properties.get("defaultSchema") != null)
		{
			setSchema = properties.getProperty("defaultSchema");
		}
		else
		{
			setSchema = defaultSchema;
		}

		if (properties.containsKey("parallelism") && properties.get("parallelism") != null)
		{
			parallelism = Integer.parseInt((String) properties.get("parallelism"));
		}
		else
		{
			parallelism = null;
		}

		if (properties.containsKey("timeoutMillis") && properties.get("timeoutMillis") != null)
		{
			timeoutMillis = Long.parseLong((String) properties.get("timeoutMillis"));
		}
		else
		{
			timeoutMillis = 0;
		}
	}

	@Override
	public void rollback() throws SQLException
	{
		LOGGER.log(Level.WARNING, "rollback() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void rollback(final Savepoint arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "rollback() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	private void sendClose() throws Exception
	{
		// send request
		final ClientWireProtocol.CloseConnection.Builder builder = ClientWireProtocol.CloseConnection.newBuilder();
		boolean endSession = session.release();
		builder.setEndSession(endSession);
		final CloseConnection msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.CLOSE_CONNECTION);
		b2.setCloseConnection(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
		}
		catch (final IOException e)
		{
			// Who cares...
		}
	}

	public int sendParameterMessage(final ClientWireProtocol.SetParameter param) throws SQLException
	{
		final ClientWireProtocol.Request.Builder builder = ClientWireProtocol.Request.newBuilder();
		builder.setType(ClientWireProtocol.Request.RequestType.SET_PARAMETER);
		builder.setSetParameter(param);
		final Request wrapper = builder.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			getStandardResponse();
		} catch (final Exception ex)
		{
			if(ex instanceof SQLException && SQLStates.SESSION_EXPIRED.equals((SQLException) ex)){
				LOGGER.log(Level.INFO, "sendParameterMessage() received session expired. Attempting to refresh session");
				// Refresh my session.
				refreshSession();
				// Now we should be able to re-run the command.
				return sendParameterMessage(param);
			}				
			LOGGER.log(Level.WARNING, String.format("Failed sending set parameter request to the server with exception %s with message %s", ex, ex.getMessage()));
			throw SQLStates.newGenericException(ex);
		}
		return 0;
	}

	private void sendSetSchema(final String schema) throws Exception
	{
		// send request
		LOGGER.log(Level.INFO, String.format("Sending set schema (%s) request to the server", schema));
		final ClientWireProtocol.SetSchema.Builder builder = ClientWireProtocol.SetSchema.newBuilder();
		builder.setSchema(schema);
		final SetSchema msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.SET_SCHEMA);
		b2.setSetSchema(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			getStandardResponse();
		}
		catch (final IOException | SQLException e)
		{
			if(e instanceof SQLException && SQLStates.SESSION_EXPIRED.equals((SQLException) e)){
				LOGGER.log(Level.INFO, "sendSetSchema() received session expired. Attempting to refresh session");
				// Refresh my session.
				refreshSession();
				// Now we should be able to re-run the command.
				sendSetSchema(schema);
				return;
			}			
			// Doesn't matter...
			LOGGER.log(Level.WARNING, String.format("Failed sending set schema request to the server with exception %s with message %s", e.toString(), e.getMessage()));
		}

		setSchema = schema;
	}

	@Override
	public void setAutoCommit(final boolean arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "Called setAutoCommit()");
	}

	@Override
	public void setCatalog(final String arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "Called setCatalog()");
	}

	@Override
	public void setClientInfo(final Properties arg0) throws SQLClientInfoException
	{
		LOGGER.log(Level.WARNING, "Called setClientInfo()");
	}

	@Override
	public void setClientInfo(final String arg0, final String arg1) throws SQLClientInfoException
	{
		LOGGER.log(Level.WARNING, "Called setClientInfo()");
	}

	public int setParallelism(final Integer parallelism, final boolean reset) throws SQLException
	{
		LOGGER.log(Level.INFO, String.format("Setting parallelism to: %d", parallelism));
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		builder.setReset(reset);
		final ClientWireProtocol.SetParameter.Concurrency.Builder innerBuilder = ClientWireProtocol.SetParameter.Concurrency.newBuilder();
		innerBuilder.setConcurrency(parallelism != null ? parallelism : 0);
		builder.setConcurrency(innerBuilder.build());

		int rowsModified = sendParameterMessage(builder.build());
		// Change this only if sendParameterMessage succeeded. It would have thrown otherwise.
		if(reset){
			this.parallelism = null;
		} else {
			this.parallelism = parallelism;
		}
		return rowsModified;
	}

	@Override
	public void setHoldability(final int arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called setHoldability()");
		if (arg0 != ResultSet.CLOSE_CURSORS_AT_COMMIT)
		{
			LOGGER.log(Level.WARNING, "setHoldability() is throwing SQLFeatureNotSupportedException");
			throw new SQLFeatureNotSupportedException();
		}
	}

	public int setMaxRows(final Integer maxRows, final boolean reset)
	{
		// Set a "soft" limit on the number of rows returned. "Soft" in this case
		// implies the query should silently omit excess rows
		LOGGER.log(Level.INFO, String.format("Setting maxrow to: %d", maxRows));
		if (reset) {
			this.maxRows = null;
		} else {
			this.maxRows = maxRows;
		}
		return 0;
	}

	public int setMaxRowsHardLimit(final Integer maxRows, final boolean reset) throws SQLException
	{
		// Set a "hard" limit on the number of rows returned. "Hard" in this case
		// implies the server will abort queries which emit excess rows
		LOGGER.log(Level.INFO, String.format("Setting maxrow to: %d", maxRows));
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		builder.setReset(reset);
		final ClientWireProtocol.SetParameter.RowLimit.Builder innerBuilder = ClientWireProtocol.SetParameter.RowLimit.newBuilder();
		innerBuilder.setRowLimit(maxRows != null ? maxRows : 0);
		builder.setRowLimit(innerBuilder.build());
		int rowsModified = sendParameterMessage(builder.build());
		// Change this only if sendParameterMessage succeeded. It would have thrown otherwise.
		if(reset){
			this.maxRows = null;	
		} else {
			this.maxRows = maxRows;
		}
		return rowsModified;
	}

	public int setMaxTempDisk(final Integer maxTempDisk, final boolean reset) throws SQLException
	{
		LOGGER.log(Level.INFO, String.format("Setting maxTempDisk to: %d", maxTempDisk));
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		builder.setReset(reset);
		final ClientWireProtocol.SetParameter.MaxTempDiskLimit.Builder innerBuilder = ClientWireProtocol.SetParameter.MaxTempDiskLimit.newBuilder();
		innerBuilder.setTempDiskLimit(maxTempDisk != null ? maxTempDisk : 0);
		builder.setTempDiskLimit(innerBuilder.build());
		int rowsModified = sendParameterMessage(builder.build());	
		// Change this only if sendParameterMessage succeeded. It would have thrown otherwise.
		if(reset){
			this.maxTempDisk = null;
		} else {
			this.maxTempDisk = maxTempDisk;
		}
		return rowsModified;
	}

	public int setMaxTime(final Integer maxTime, final boolean reset) throws SQLException
	{
		LOGGER.log(Level.INFO, String.format("Setting maxTime to: %d", maxTime));
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		builder.setReset(reset);
		final ClientWireProtocol.SetParameter.TimeLimit.Builder innerBuilder = ClientWireProtocol.SetParameter.TimeLimit.newBuilder();
		innerBuilder.setTimeLimit(maxTime != null ? maxTime : 0);
		builder.setTimeLimit(innerBuilder.build());
		int rowsModified = sendParameterMessage(builder.build());		
		// Change this only if sendParameterMessage succeeded. It would have thrown otherwise.
		if(reset){
			this.maxTime = null;
		} else {
			this.maxTime = maxTime;
		}
		return rowsModified;
	}

	@Override
	public void setNetworkTimeout(final Executor executor, final int milliseconds) throws SQLException
	{
		LOGGER.log(Level.WARNING, "Called setNetworkTimeout()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "setNetworkTimeout() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		networkTimeout = milliseconds;
	}

	public int setPriority(final Double priority, final boolean reset) throws SQLException
	{
		LOGGER.log(Level.INFO, String.format("Setting priority to: %f", priority));
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		builder.setReset(reset);
		final ClientWireProtocol.SetParameter.Priority.Builder innerBuilder = ClientWireProtocol.SetParameter.Priority.newBuilder();
		innerBuilder.setPriority(priority != null ? priority : 0.0);
		builder.setPriority(innerBuilder.build());

		int rowsModified = sendParameterMessage(builder.build());
		// Change this only if sendParameterMessage succeeded. It would have thrown otherwise.	
		if(reset){
			this.priority = null;
		} else {
			this.priority = priority;
		}
		return rowsModified;
	}

	// sets the pso RNG seed. If this is never called, by default PSO uses current time to generate seed 
	public void setPSOSeed(final long seed, boolean reset) throws Exception 
	{
		LOGGER.log(Level.INFO, "Sending request to set pso seed to the server"); 
		if (closed)
		{
			LOGGER.log(Level.WARNING, "Set pso seed request is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		final ClientWireProtocol.SetParameter.PSOSeed.Builder innerBuilder = ClientWireProtocol.SetParameter.PSOSeed.newBuilder();
		innerBuilder.setSeed(seed);
		builder.setPsoSeed(innerBuilder.build());
		builder.setReset(reset);
		final SetParameter msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.SET_PARAMETER);
		b2.setSetParameter(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			getStandardResponse();
		}
		catch (final IOException e)
		{
			// Doesn't matter...
			LOGGER.log(Level.WARNING, String.format("Failed sending set pso seed request to the server with exception %s with message ", e.toString(), e.getMessage()));
		}
	}
	// sets the pso threshold on this connection to be -1(meaning pso is turned off)
	// or back to the default
	public void setPSO(final boolean on) throws Exception
	{
		LOGGER.log(Level.INFO, "Sending set pso request to the server");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "Set pso request is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (on)
		{
			setPso = 0;
		}
		else
		{
			setPso = -1;
		}

		// send request
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();
		final ClientWireProtocol.SetParameter.PSO.Builder innerBuilder = ClientWireProtocol.SetParameter.PSO.newBuilder();
		innerBuilder.setThreshold(-1);
		builder.setPsoThreshold(innerBuilder.build());
		builder.setReset(on);
		final SetParameter msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.SET_PARAMETER);
		b2.setSetParameter(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			getStandardResponse();
		}
		catch (final IOException e)
		{
			// Doesn't matter...
			LOGGER.log(Level.WARNING, String.format("Failed sending set pso request to the server with exception %s with message ", e.toString(), e.getMessage()));
		}
	}

	// sets the pso threshold on this connection to threshold
	public void setPSO(final long threshold) throws Exception
	{
		LOGGER.log(Level.INFO, "Sending set pso request to the server");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "Set pso request is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		// send request
		setPso = threshold;
		final ClientWireProtocol.SetParameter.Builder builder = ClientWireProtocol.SetParameter.newBuilder();

		final ClientWireProtocol.SetParameter.PSO.Builder innerBuilder = ClientWireProtocol.SetParameter.PSO.newBuilder();
		innerBuilder.setThreshold(threshold);
		builder.setPsoThreshold(innerBuilder.build());
		builder.setReset(false);
		final SetParameter msg = builder.build();
		final ClientWireProtocol.Request.Builder b2 = ClientWireProtocol.Request.newBuilder();
		b2.setType(ClientWireProtocol.Request.RequestType.SET_PARAMETER);
		b2.setSetParameter(msg);
		final Request wrapper = b2.build();

		try
		{
			out.write(intToBytes(wrapper.getSerializedSize()));
			wrapper.writeTo(out);
			out.flush();
			getStandardResponse();
		}
		catch (final IOException e)
		{
			// Doesn't matter...
			LOGGER.log(Level.WARNING, String.format("Failed sending set pso request to the server with exception %s with message %s", e, e.getMessage()));
		}
	}

	@Override
	public void setReadOnly(final boolean arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "Called setReadOnly()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "setReadOnly() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}
	}

	@Override
	public Savepoint setSavepoint() throws SQLException
	{
		LOGGER.log(Level.WARNING, "setSavepoint() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public Savepoint setSavepoint(final String arg0) throws SQLException
	{
		LOGGER.log(Level.WARNING, "setSavepoint() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	@Override
	public void setSchema(final String schema) throws SQLException
	{
		LOGGER.log(Level.INFO,String.format("Called setSchema() to set: %s", schema));
		if (closed)
		{
			LOGGER.log(Level.WARNING, "setSchema() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		try
		{
			sendSetSchema(schema);
		}
		catch (final Exception e)
		{
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during setSchema() with message %s", e.toString(), e.getMessage()));
			if (e instanceof SQLException)
			{
				throw (SQLException) e;
			}
			else
			{
				throw SQLStates.newGenericException(e);
			}
		}
	}

	public void setServerVersion(final String version)
	{
		// Versions are major.minor.patch-date
		// don't want the date
		final String cleanVersion = version.indexOf("-") == -1 ? version : version.substring(0, version.indexOf("-"));
		serverVersion = cleanVersion;
	}

	/*
	 * ! This timeout will be applied to every XGStatement created
	 */
	public void setTimeout(final int seconds) throws SQLException
	{
		if (seconds < 0)
		{
			LOGGER.log(Level.WARNING, "Throwing because a negative value was passed to setTimeout()");
			throw new SQLWarning(String.format("timeout value must be non-negative, was: %s", seconds));
		}

		LOGGER.log(Level.INFO, String.format("Setting timeout to %d seconds", seconds));
		timeoutMillis = seconds * 1000;
	}

	@Override
	public void setTransactionIsolation(final int arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called setTransactionIsolation()");
		if (closed)
		{
			LOGGER.log(Level.WARNING, "setTransactionIsolation() is throwing CALL_ON_CLOSED_OBJECT");
			throw SQLStates.CALL_ON_CLOSED_OBJECT.clone();
		}

		if (arg0 != Connection.TRANSACTION_NONE)
		{
			LOGGER.log(Level.WARNING, "setTransactionIsolation() is throwing SQLFeatureNotSupportedException");
			throw new SQLFeatureNotSupportedException();
		}
	}

	@Override
	public void setTypeMap(final Map<String, Class<?>> arg0) throws SQLException
	{
		LOGGER.log(Level.INFO, "Called setTypeMap()");
		typeMap = arg0;
	}

	private boolean testConnection(final int timeoutSecs)
	{
		final TestConnectionThread thread = new TestConnectionThread();
		thread.start();
		try
		{
			thread.join(timeoutSecs * 1000);
		}
		catch (final Exception e)
		{
		}

		if (thread.isAlive())
		{
			return false;
		}

		if (thread.e != null)
		{
			return false;
		}

		return true;
	}

	@Override
	public <T> T unwrap(final Class<T> iface) throws SQLException
	{
		LOGGER.log(Level.WARNING, "setSavepoint() was called, which is not supported");
		throw new SQLFeatureNotSupportedException();
	}

	// Requests that the server refreshes our current session.
	public Session.State sendRefresh(boolean shouldIgnoreSecurityToken) throws SQLException{

		LOGGER.log(Level.INFO, "Sending refresh request to server");
		final ClientWireProtocol.ClientConnectionRefreshSession.Builder refreshMsgBuilder = ClientWireProtocol.ClientConnectionRefreshSession.newBuilder();
		final ClientWireProtocol.ClientConnectionRefreshSession refreshMsg = refreshMsgBuilder.build();

		ClientWireProtocol.Request.Builder reqBuilder = ClientWireProtocol.Request.newBuilder();
		reqBuilder.setType(ClientWireProtocol.Request.RequestType.CLIENT_CONNECTION_REFRESH_SESSION);
		reqBuilder.setClientConnectionRefreshSession(refreshMsg);
		// Finish the poll message. We can use it over and over.
		ClientWireProtocol.ClientConnectionRefreshSessionResponse.Builder refreshResponseBuilder = ClientWireProtocol.ClientConnectionRefreshSessionResponse.newBuilder();
		Request refreshReq = reqBuilder.build();
		try {
			// Send request.
			out.write(intToBytes(refreshReq.getSerializedSize()));
			refreshReq.writeTo(out);
			out.flush();
			// Receive response.
			int length = getLength();
			byte[] data = new byte[length];
			readBytes(data);
			refreshResponseBuilder.mergeFrom(data);			
		} catch (final Exception e){
			LOGGER.log(Level.WARNING, String.format("Exception %s occurred during sendRefresh() with message %s", e.toString(), e.getMessage()));
			throw SQLStates.newGenericException(e);
		}
		ConfirmationResponse response = refreshResponseBuilder.getResponse();
		ResponseType rType = response.getType();
		processResponseType(rType, response);

		SessionInfo sessionInfo = refreshResponseBuilder.getSessionInfo();
		ClientWireProtocol.SecurityToken receivedSecurityToken = sessionInfo.getSecurityToken();
		// Save the server session ID
		LOGGER.log(Level.INFO, String.format("Connected to server session id: %s", sessionInfo.getServerSessionId()));
		serverSessionId = sessionInfo.getServerSessionId();
		if(shouldIgnoreSecurityToken){
			// Discard the security token.
			return new Session.State(new Session.UserAndPassword(user, pwd));
		} else {
			return new Session.State(new Session.SecurityToken(
				receivedSecurityToken.getData().toString(),
				receivedSecurityToken.getSignature().toString(),
				receivedSecurityToken.getIssuerFingerprint().toString()));
		}
	}
}
