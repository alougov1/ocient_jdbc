package com.ocient.jdbc;

import java.sql.SQLException;

public final class SQLStates implements Cloneable {
	private static String NORMAL_COMPLETION = "00000";
	private static String TRUNCATION_STATE = "01004";
	private static String EXCESSIVE_COST_STATE = "01616";
	private static String INVALID_CONN_STR_ATTR_STATE = "01S00";
	private static String NO_ROW_DATA_STATE = "02000";
	private static String CLIENT_ERROR = "03001";
	private static String INVALID_PARAMETER_MARKER_STATE = "07002";
	private static String NO_CURSOR_STATE = "07005";
	private static String INVALID_DESCRIPTOR_INDEX_STATE = "07009";
	private static String UNABLE_TO_CONNECT = "08001";
	private static String NO_CONNECTION_STATE = "08003";
	private static String REJECTED_CONNECTION = "08004";
	private static String SCALAR_SUBQUERY_CARDINALITY_VIOLATION_STATE = "21000";
	private static String MISSING_NULL_INDICATOR_STATE = "22002";
	private static String OUT_OF_RANGE_STATE = "22003";
	private static String DIVIDE_BY_ZERO_STATE = "22012";
	private static String INVALID_LIMIT_STATE = "2201W";
	private static String INVALID_OFFSET_STATE = "2201X";
	private static String INVALID_FLOATING_POINT_OPERATION_STATE = "2268E";
	private static String INVALID_CURSOR = "24000";
	private static String CURSOR_ALREADY_ASSIGNED_TO_RS = "24516";
	private static String VALUE_TOO_LARGE_STATE = "24920";
	private static String CONFLICT_STATE = "38H13";
	private static String ST_POINT_INVALID_CONVERSION_FROM_NULL_STATE = "38SUP";
	private static String AUTH_FAILURE = "42502";
	private static String SYNTAX_ERROR_STATE = "42601";
	private static String WRONG_NUMBER_OF_ARGUMENTS_STATE = "42605";
	private static String SQL_NOT_VALID_IN_CONTEXT = "42612";
	private static String INVALID_CASE_CONDITION_STATE = "42625";
	private static String AMBIGUOUS_COL_STATE = "42702";
	private static String COLUMN_NOT_FOUND_STATE = "42703";
	private static String OBJECT_NOT_FOUND_STATE = "42704";
	private static String DUPLICATE_OBJECT = "42710";
	private static String DUPLICATE_CTE_NAME_STATE = "42726";
	private static String INVALID_AGGREGATION_STATE = "42803";
	private static String INCOMPATIBLE_TYPES_IN_CASE_STATE = "42804";
	private static String INVALID_ORDER_BY_STATE = "42805";
	private static String SELECT_NUM_COLS_MISMATCH_STATE = "42811";
	private static String INVALID_BY_EXPRESSION_STATE = "42822";
	private static String BAD_DATA_TYPE = "42815";
	private static String INVALID_ARGUMENT_STATE = "42818";
	private static String NOT_COMPATIBLE_COLS_STATE = "42825";
	private static String INVALID_FUNCTION_USE = "42881";
	private static String BAD_SCALAR_TYPE_IN_LIST = "428HR";
	private static String INVALID_JOIN_CONDITION_STATE = "42972";
	private static String WINDOW_FUNC_EXPECTED_POSITIVE_CONSTANT_STATE = "429F6";
	private static String FRAME_SPEC_NOT_ALLOWED_STATE = "429F7";
	private static String INVALID_FRAME_BOUNDS_STATE = "429F8";
	private static String BAD_START_FRAME_BOUND_STATE = "429F9";
	private static String BAD_END_FRAME_BOUND_STATE = "429FA";
	private static String FRAME_WITHOUT_ORDERING_STATE = "429FB";
	private static String BAD_WINDOWED_ORDER_BY_STATE = "429FC";
	private static String BAD_RANGE_FRAME_SPECIFICATION_STATE = "429FD";
	private static String EXPECTED_CONST_WINDOWED_AGGREGATE_ARGUMENT_STATE = "429FE";
	private static String AGGREGATION_NOT_ALLOWED_IN_WINDOW_CONSTRUCTION_STATE = "429FF";
	private static String STORAGE_OR_DATABASE_RESOURCE_NOT_AVAILABLE_STATE = "57011";
	private static String NON_DATABASE_RESOURCE_NOT_AVAILABLE_STATE = "57013";
	private static String OPERATION_CANCELED_STATE = "57014";
	private static String PLAN_COMPILATION_ERROR_STATE = "560D1";
	private static String SYSTEM_ERROR = "58005";
	private static String GENERAL_DRIVER_ERROR = "HY000";
	private static String OUT_OF_MEMORY_STATE = "HY001";
	private static String INVALID_C_DATA_TYPE_STATE = "HY003";
	private static String INVALID_SQL_DATA_TYPE_STATE = "HY004";
	private static String INVALID_INPUT_STATE = "HY009";
	private static String SEQUENCE_ERROR_STATE = "HY010";
	private static String COPY_TARGET_IS_IRD_STATE = "HY016";
	private static String INVALID_IMPLICIT_DESC_HANDLE_USE_STATE = "HY017";
	private static String INVALID_DESCRIPTOR_INFORMATION_STATE = "HY021";
	private static String INVALID_BUFFER_LENGTH_STATE = "HY090";
	private static String INVALID_DESCRIPTOR_FIELD_STATE = "HY091";
	private static String INVALID_ATTRIBUTE_STATE = "HY092";
	private static String BAD_PARAM_NUM_STATE = "HY093";
	private static String NOT_IMPLEMENTED_STATE = "HYC00";
	private static String UNDEFINED_EXCEPTION_STATE = "99999"; // for internal-use only

	private static int NORMAL_COMPLETION_CODE = 0;

	// internal errors
	private static int GENERIC_EXCEPTION_CODE = -100;
	private static int INVALID_RESPONSE_CODE = -101;
	private static int INVALID_COLUMN_CODE = -102;
	private static int INTERNAL_ERROR_CODE = -103;

	// comms problems
	private static int MALFORMED_URL_CODE = -200;
	private static int FAILED_CONNECTION_CODE = -201;
	private static int FAILED_HANDSHAKE_CODE = -202;
	private static int UNEXPECTED_EOF_CODE = -203;
	private static int NETWORK_COMMS_ERROR_CODE = -204;
	private static int NO_SUCH_DATABASE_CODE = -205;

	// client problems
	private static int TRUNCATION_CODE = 300; // Warning
	private static int INVALID_ARGUMENT_CODE = -300;
	private static int CALL_ON_CLOSED_OBJECT_CODE = -301;
	private static int CURSOR_NOT_ON_ROW_CODE = -302;
	private static int PREVIOUS_RESULT_SET_STILL_OPEN_CODE = -303;
	private static int BAD_USER_PWD_CODE = -304;
	private static int NOT_A_SELECT_CODE = -305;
	private static int IS_A_SELECT_CODE = -306;
	private static int NULL_OUTPUT_BUFFER_CODE = -307;
	private static int NOT_IMPLEMENTED_CODE = -308;
	private static int SEQUENCE_ERROR_CODE = -309;
	private static int INVALID_ATTRIBUTE_CODE = -310;
	private static int INVALID_INPUT_CODE = -311;
	private static int DYNAMIC_LINK_FAILURE_CODE = -312;
	private static int BAD_PARAM_NUM_CODE = -313;
	private static int INVALID_C_DATA_TYPE_CODE = -314;
	private static int INVALID_SQL_DATA_TYPE_CODE = -315;
	private static int NO_CONNECTION_CODE = -316;
	private static int INVALID_PARAMETER_MARKER_CODE = -317;
	private static int INVALID_CURSOR_CODE = -318;
	private static int INVALID_BUFFER_LENGTH_CODE = -319;
	private static int NO_RESULT_SET_CODE = -320;
	private static int MISSING_NULL_INDICATOR_CODE = -321;
	private static int INVALID_CONN_STR_ATTR_CODE = -322;
	private static int INVALID_DESCRIPTOR_INDEX_CODE = -323;
	private static int INVALID_DESCRIPTOR_INFORMATION_CODE = -324;
	private static int INVALID_DESCRIPTOR_FIELD_CODE = -325;
	private static int COPY_TARGET_IS_IRD_CODE = -326;
	private static int INVALID_IMPLICIT_DESC_HANDLE_USE_CODE = -327;
	private static int DIVIDE_BY_ZERO_CODE = -328;
	private static int INVALID_FLOATING_POINT_OPERATION_CODE = -329;
	private static int CONFLICT_CODE = -330;

	// column and data type issues
	private static int COLUMN_NOT_FOUND_CODE = -400;
	private static int INVALID_DATA_TYPE_CONVERSION_CODE = -401;
	private static int UNKNOWN_DATA_TYPE_CODE = -402;
	private static int AMBIGUOUS_COL_CODE = -403;
	private static int INCOMPATIBLE_TYPES_IN_CASE_CODE = -404;
	private static int JOIN_LEADS_TO_DUPLICATE_COL_NAME_CODE = -405;
	private static int ST_POINT_INVALID_CONVERSION_FROM_NULL_CODE = -406;
	private static int VALUE_TOO_LARGE_CODE = -407;

	// syntax issues
	private static int SYNTAX_ERROR_CODE = -500;
	private static int SQL_NOT_VALID_IN_CONTEXT_CODE = -501;
	private static int DUPLICATE_CTE_CODE = -502;
	private static int SELECT_NUM_COLS_MISMATCH_CODE = -503;
	private static int NEGATIVE_LIMIT_CODE = -504;
	private static int NEGATIVE_OFFSET_CODE = -505;
	private static int WRONG_NUMBER_OF_ARGUMENTS_CODE = -506;
	private static int AGGREGATION_ON_CONSTANT_CODE = -507;
	private static int WRONG_ARGUMENT_TYPE_CODE = -508;
	private static int INVALID_COMPARISON_CODE = -509;
	private static int AGGREGATION_NOT_ALLOWED_CODE = -510;
	private static int NO_AGG_IN_HAVING_CODE = -511;
	private static int INVALID_ORDER_BY_CODE = -512;
	private static int LIST_TYPE_IN_SELECT_LIST_CODE = -513;
	private static int LIST_WITHIN_LIST_CODE = -514;
	private static int INCOMPATIBLE_TYPES_IN_LIST_CODE = -515;
	private static int UNKNOWN_FUNCTION_CODE = -516;
	private static int NAKED_INTERVAL_TYPE_CODE = -517;
	private static int INVALID_MATRIX_LITERAL_CODE = -518;
	private static int WRONG_SHAPE_MATRIX_LITERAL_CODE = -519;
	private static int INVALID_QUERY_PRIORITY_CODE = -520;
	private static int SELECT_AFTER_AGG_CODE = -521;
	private static int NOT_COMPATIBLE_COLS_CODE = -522;
	private static int INVALID_CASE_CONDITION_CODE = -523;
	private static int INVALID_JOIN_CONDITION_CODE = -524;
	private static int AGGREGATION_NOT_ALLOWED_IN_WINDOW_CONSTRUCTION_CODE = -525;
	private static int EXPECTED_CONST_WINDOWED_AGGREGATE_AGRUMENT_CODE = -526;
	private static int BAD_RANGE_FRAME_SPECIFICATION_CODE = -527;
	private static int BAD_WINDOWED_ORDER_BY_CODE = -528;
	private static int FRAME_WITHOUT_ORDERING_CODE = -529;
	private static int BAD_END_FRAME_BOUND_CODE = -530;
	private static int BAD_START_FRAME_BOUND_CODE = -531;
	private static int INVALID_FRAME_BOUNDS_CODE = -532;
	private static int FRAME_SPEC_NOT_ALLOWED_CODE = -533;
	private static int WINDOW_FUNC_EXPECTED_POSITIVE_CONSTANT_CODE = -534;
	private static int MISSING_ORDER_BY_CODE = -535;
	private static int INVALID_AGGREGATION_CODE = -536;
	private static int INVALID_BY_EXPRESSION_CODE = -537;
	private static int CASE_WITHIN_CASE_CODE = -538;

	// table related issues
	private static int TABLE_NOT_FOUND_CODE = -600;
	private static int DATABASE_ALREADY_EXISTS_CODE = -601;
	private static int TABLE_ALREADY_EXISTS_CODE = -602;
	private static int VIEW_ALREADY_EXISTS_CODE = -603;
	private static int VIEW_NOT_FOUND_CODE = -604;
	private static int DATABASE_NOT_FOUND_CODE = -605;
	private static int STORAGE_SPACE_NOT_FOUND_CODE = -606;
	private static int STORAGESPACE_ALREADY_EXISTS_CODE = -607;
	private static int USER_NOT_FOUND_CODE = -608;
	private static int USER_ALREADY_EXISTS_CODE = -609;
	private static int INVALID_NEW_USER_PWD_CODE = -610;
	private static int GROUP_ALREADY_EXISTS_CODE = -611;
	private static int GROUP_NOT_FOUND_CODE = -612;
	private static int CONNECTION_ALREADY_EXISTS_CODE = -613;
	private static int CONNECTION_NOT_FOUND_CODE = -614;
	private static int TRANSLATION_NOT_FOUND_CODE = -615;
	private static int TRANSLATION_ALREADY_EXISTS_CODE = -616;
	private static int USER_NOT_IN_GROUP_CODE = -617;

	// security related issues
	private static int READ_TABLE_AUTH_FAILURE = -700;
	private static int CREATE_DATABASE_AUTH_FAILURE = -701;
	private static int MODIFY_TABLE_AUTH_FAILURE = -702;
	private static int CREATE_VIEW_AUTH_FAILURE = -703;
	private static int MODIFY_DATABASE_AUTH_FAILURE = -704;
	private static int MODIFY_VIEW_AUTH_FAILURE = -705;
	private static int DROP_TABLE_AUTH_FAILURE = -706;
	private static int DELETE_ROW_AUTH_FAILURE = -707;
	private static int DROP_VIEW_AUTH_FAILURE = -708;
	private static int DROP_DATABASE_AUTH_FAILURE = -709;
	private static int CREATE_TABLE_AUTH_FAILURE = -710;
	private static int CREATE_STORAGESPACE_AUTH_FAILURE = -711;
	private static int DROP_STORAGE_SPACE_AUTH_FAILURE = -712;
	private static int CREATE_USER_AUTH_FAILURE = -713;
	private static int DROP_USER_AUTH_FAILURE = -714;
	private static int CREATE_GROUP_AUTH_FAILURE = -715;
	private static int DROP_GROUP_AUTH_FAILURE = -716;
	private static int CREATE_CONNECTION_AUTH_FAILURE = -717;
	private static int DROP_CONNECTION_AUTH_FAILURE = -718;
	private static int NOT_AUTHORIZED_CODE = -719;
	private static int MODIFY_GROUP_AUTH_FAILURE = -720;
	private static int EXECUTE_PLAN_AUTH_FAILURE = -721;
	private static int EXECUTE_INLINE_PLAN_AUTH_FAILURE = -722;
	private static int SESSION_EXPIRED_CODE = -733;

	// MLMODEL related issues
	private static int ML_MODEL_NOT_FOUND_CODE = -800;
	private static int ML_MODEL_ALREADY_EXISTS_CODE = -801;
	private static int NO_CREATE_MLMODEL_AUTH_CODE = -802;
	private static int NO_DROP_MLMODEL_AUTH_CODE = -803;
	private static int UNABLE_TO_INVERT_SINGULAR_MATRIX_CODE = -804;
	private static int ML_MODEL_ON_EMPTY_SET_CODE = -805;
	private static int UNABLE_TO_DECOMPOSE_SINGULAR_MATRIX_CODE = -806;

	// runtime related issues
	private static int NO_ROW_DATA_CODE = 900;
	private static int EXCESSIVE_COST_CODE = 901;
	private static int OPERATION_CANCELED_CODE = -900;
	private static int IO_ERROR_CODE = -901;
	private static int SCALAR_SUBQUERY_CARDINALITY_VIOLATION_CODE = -902;
	private static int NUMERIC_VALUE_OUT_OF_RANGE_CODE = -903;
	private static int PLAN_COMPILATION_ERROR_CODE = -904;
	private static int TKT_LIMIT_REACHED_CODE = -905;
	private static int OUT_OF_MEMORY_CODE = -906;
	private static int SEGMENT_NOT_AVAILABLE_CODE = -907;
	private static int SYSTEM_INITIALIZING_CODE = -908;
	private static int OUT_OF_TEMP_DISK_SPACE_CODE = -909;

	// node related issues
	private static int NODE_NOT_FOUND_CODE = -1101;

	private static int UNDEFINED_EXCEPTION_CODE = -9999; // for internal-use only

	// DCL
	private static int PRIVILEGE_ALREADY_POSSESSED_CODE = -1000;
	private static int NO_GRANT_AUTH_CODE = -1001;
	private static int PRIVILEGE_NOT_POSSESSED_CODE = -1002;
	private static int ROLE_NOT_FOUND_CODE = -1003;
	private static int ID_NOT_FOUND_CODE = -1004;

	// Security Integration related errors
	private static int SECURITY_INTEGRATION_DISABLED_CODE = -1200;
	private static int SECURITY_INTEGRATION_NOT_FOUND_CODE = -1201;
	private static int NETWORK_COMMUNICATIONS_ERROR_INVALID_CERTIFICATE_CODE = -1202;
	private static int SSO_REQUEST_ID_NOT_FOUND_CODE = -1203;
	private static int SESSION_DOES_NOT_EXIST_CODE = -1204;
	private static int INVALID_SECURITY_TOKEN_CODE = -1205;
	private static int INVALID_SECURITY_TOKEN_SIGNATURE_CODE = -1206;
	private static int INVALID_SECURITY_TOKEN_FINGERPRINT_CODE = -1207;
	private static int EXPIRED_SECURITY_TOKEN_CODE = -1208;

	// Relevant Open ID Connect 1.0 errors defined by https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	private static int OIDC_NETWORK_COMMUNICATIONS_ERROR_CODE = -1220;
	private static int OIDC_INVALID_REQUEST_OBJECT_CODE = -1221;
	private static int OIDC_INVALID_RESPONSE_OBJECT_CODE = -1222;
	private static int OIDC_INVALID_REQUEST_URI_CODE = -1223;
	private static int OIDC_REQUEST_NOT_SUPPORTED_CODE = -1224;
	private static int OIDC_REQUEST_URI_NOT_SUPPORTED_CODE = -1225;
	private static int OIDC_INVALID_DISCOVERY_DOCUMENT_CODE = -1226;
	private static int OIDC_INVALID_CONFIGURATION_CODE = -1227;

	// Additional Open ID Connect errors
	private static int OIDC_EXPIRED_TOKEN_CODE = -1228;
	private static int OIDC_SIGNING_KEY_NOT_FOUND_CODE = -1229;
	private static int OIDC_INVALID_SIGNING_KEY_CODE = -1230;
	private static int OIDC_INVALID_TOKEN_CLAIM_CODE = -1231;
	private static int OIDC_INVALID_TOKEN_ISSUER_CODE = -1232;
	private static int OIDC_INVALID_TOKEN_AUDIENCE_CODE = -1233;
	private static int OIDC_INVALID_TOKEN_SIGNATURE_CODE = -1234;
	private static int OIDC_INVALID_ID_TOKEN_CODE = -1235;
	private static int OIDC_INVALID_ACCESS_TOKEN_CODE = -1236;
	private static int OIDC_INVALID_REFRESH_TOKEN_CODE = -1237;

	// Relevant OAuth 2.0 errors defined by https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	private static int OAUTH_UNAUTHORIZED_CLIENT_CODE = -1250;
	private static int OAUTH_ACCESS_DENIED_CODE = -1251;
	private static int OAUTH_UNSUPPORTED_RESPONSE_TYPE_CODE = -1252;
	private static int OAUTH_INVALID_SCOPE_CODE = -1253;
	private static int OAUTH_INVALID_REQUEST_CODE = -1254;
	private static int OAUTH_SERVER_ERROR_CODE = -1255;
	private static int OAUTH_TEMPORARILY_UNAVAILABLE_CODE = -1256;

	// task related issues
	private static int CREATE_TASK_FAILURE_CODE = -1005;
	private static int TASK_ALREADY_IN_PROGRESS_ERROR_CODE = -1006;

	// cluster related issues
	private static int CLUSTER_NOT_FOUND_CODE = -1111;
	private static int CLUSTER_ALREADY_EXISTS_CODE = -1112;

	private static int OBJECT_NOT_FOUND_WARN_CODE = 1113; // warning
	private static int OBJECT_ALREADY_EXISTS_WARN_CODE = 1114; // warning

	public static final SQLStates INVALID_RESPONSE_TYPE = new SQLStates(
			"Received a response from the server that was not ok, warning, or error", SYSTEM_ERROR,
			INVALID_RESPONSE_CODE);
	public static final SQLStates INVALID_COLUMN_TYPE = new SQLStates("Corruption of serialized result set",
			SYSTEM_ERROR, INVALID_COLUMN_CODE);
	public static final SQLStates MALFORMED_URL = new SQLStates("Malformed connection URL", UNABLE_TO_CONNECT,
			MALFORMED_URL_CODE);
	public static final SQLStates FAILED_CONNECTION = new SQLStates("Connection failed", UNABLE_TO_CONNECT,
			FAILED_CONNECTION_CODE);
	public static final SQLStates FAILED_HANDSHAKE = new SQLStates("The handshake between client and server failed",
			UNABLE_TO_CONNECT, FAILED_HANDSHAKE_CODE);
	public static final SQLStates INVALID_ARGUMENT = new SQLStates("The argument is invalid",
			CLIENT_ERROR, INVALID_ARGUMENT_CODE);
	public static final SQLStates CALL_ON_CLOSED_OBJECT = new SQLStates("A client method was called on a closed object",
			CLIENT_ERROR, CALL_ON_CLOSED_OBJECT_CODE);
	public static final SQLStates COLUMN_NOT_FOUND = new SQLStates("The reference to referenced column is not valid",
			COLUMN_NOT_FOUND_STATE, COLUMN_NOT_FOUND_CODE);
	public static final SQLStates CORRELATED_SUBQUERY = new SQLStates("Correlated subqueries are not supported",
			COLUMN_NOT_FOUND_STATE, COLUMN_NOT_FOUND_CODE);
	public static final SQLStates CURSOR_NOT_ON_ROW = new SQLStates("The cursor was not positioned on a valid row",
			INVALID_CURSOR, CURSOR_NOT_ON_ROW_CODE);
	public static final SQLStates INVALID_DATA_TYPE_CONVERSION = new SQLStates(
			"Unable to do the requested data type conversion", NOT_IMPLEMENTED_STATE,
			INVALID_DATA_TYPE_CONVERSION_CODE);
	public static final SQLStates UNEXPECTED_EOF = new SQLStates("Unexpected EOF on network connection",
			UNABLE_TO_CONNECT, UNEXPECTED_EOF_CODE);
	public static final SQLStates NETWORK_COMMS_ERROR = new SQLStates("A network communications error occurred",
			UNABLE_TO_CONNECT, NETWORK_COMMS_ERROR_CODE);
	public static final SQLStates PREVIOUS_RESULT_SET_STILL_OPEN = new SQLStates(
			"Only one result set can be open at a time on a given connection", CURSOR_ALREADY_ASSIGNED_TO_RS,
			PREVIOUS_RESULT_SET_STILL_OPEN_CODE);
	public static final SQLStates UNKNOWN_DATA_TYPE = new SQLStates("Unknown data type", BAD_DATA_TYPE,
			UNKNOWN_DATA_TYPE_CODE);
	public static final SQLStates BAD_USER_PWD = new SQLStates("The userid/password combination was not valid",
			REJECTED_CONNECTION, BAD_USER_PWD_CODE);
	public static final SQLStates OK = new SQLStates("The operation completed successfully", NORMAL_COMPLETION,
			NORMAL_COMPLETION_CODE);
	public static final SQLStates SYNTAX_ERROR = new SQLStates("There is a syntax error in your statement",
			SYNTAX_ERROR_STATE, SYNTAX_ERROR_CODE);
	public static final SQLStates INTERNAL_ERROR = new SQLStates("An internal error occurred", SYSTEM_ERROR,
			INTERNAL_ERROR_CODE);
	public static final SQLStates DUPLICATE_CTE_NAME = new SQLStates(
			"There is a duplicate common table expression name", DUPLICATE_CTE_NAME_STATE, DUPLICATE_CTE_CODE);
	public static final SQLStates SELECT_NUM_COLS_MISMATCH = new SQLStates(
			"The number of columns does not match the SELECT statement", SELECT_NUM_COLS_MISMATCH_STATE,
			SELECT_NUM_COLS_MISMATCH_CODE);
	public static final SQLStates INVALID_BY_EXPRESSION = new SQLStates(
			"The expression in the ORDER BY or GROUP BY clause is not valid.", INVALID_BY_EXPRESSION_STATE,
			INVALID_BY_EXPRESSION_CODE);
	public static final SQLStates NEGATIVE_LIMIT = new SQLStates("The value of the LIMIT clause was negative",
			INVALID_LIMIT_STATE, NEGATIVE_LIMIT_CODE);
	public static final SQLStates NEGATIVE_OFFSET = new SQLStates("The value of the OFFSET clause was negative",
			INVALID_OFFSET_STATE, NEGATIVE_OFFSET_CODE);
	public static final SQLStates WRONG_NUMBER_OF_FUNCTION_ARGUMENTS = new SQLStates(
			"Wrong number of arguments in function call", WRONG_NUMBER_OF_ARGUMENTS_STATE,
			WRONG_NUMBER_OF_ARGUMENTS_CODE);
	public static final SQLStates AGGREGATION_ON_CONSTANT = new SQLStates("Aggregation of a constant value is invalid",
			INVALID_ARGUMENT_STATE, AGGREGATION_ON_CONSTANT_CODE);
	public static final SQLStates WRONG_FUNCTION_ARGUMENT_TYPE = new SQLStates(
			"The data type of a function parameter is invalid", INVALID_ARGUMENT_STATE, WRONG_ARGUMENT_TYPE_CODE);
	public static final SQLStates INVALID_COMPARISON = new SQLStates("A comparison operation is invalid",
			INVALID_ARGUMENT_STATE, INVALID_COMPARISON_CODE);
	public static final SQLStates NO_SUCH_DATABASE = new SQLStates("No database with that name exists",
			REJECTED_CONNECTION, NO_SUCH_DATABASE_CODE);
	public static final SQLStates STORAGESPACE_ALREADY_EXISTS = new SQLStates("A storage space with that name exists",
			DUPLICATE_OBJECT, STORAGESPACE_ALREADY_EXISTS_CODE);
	public static final SQLStates AGGREGATION_NOT_ALLOWED = new SQLStates(
			"Aggregation was used in a context where it is not allowed (perhaps a predicate in the WHERE clause that belongs in the HAVING clause)",
			SYNTAX_ERROR_STATE, AGGREGATION_NOT_ALLOWED_CODE);
	public static final SQLStates AMBIGUOUS_COL = new SQLStates("A column name was ambiguous", AMBIGUOUS_COL_STATE,
			AMBIGUOUS_COL_CODE);
	public static final SQLStates NO_AGG_IN_HAVING = new SQLStates(
			"There is no aggregation in the predicate in the HAVING clause", INVALID_AGGREGATION_STATE,
			NO_AGG_IN_HAVING_CODE);
	public static final SQLStates SELECT_AFTER_AGG = new SQLStates(
			"A column reference in a SELECT clause is invalid due to aggregation", INVALID_AGGREGATION_STATE,
			SELECT_AFTER_AGG_CODE);
	public static final SQLStates TABLE_NOT_FOUND = new SQLStates("The referenced table does not exist",
			OBJECT_NOT_FOUND_STATE, TABLE_NOT_FOUND_CODE);
	public static final SQLStates DATABASE_ALREADY_EXISTS = new SQLStates("A database with that name exists",
			DUPLICATE_OBJECT, DATABASE_ALREADY_EXISTS_CODE);
	public static final SQLStates TABLE_ALREADY_EXISTS = new SQLStates("A table with that name exists",
			DUPLICATE_OBJECT, TABLE_ALREADY_EXISTS_CODE);
	public static final SQLStates VIEW_ALREADY_EXISTS = new SQLStates("A view with that name exists", DUPLICATE_OBJECT,
			VIEW_ALREADY_EXISTS_CODE);
	public static final SQLStates USER_ALREADY_EXISTS = new SQLStates("A user with that name exists", DUPLICATE_OBJECT,
			USER_ALREADY_EXISTS_CODE);
	public static final SQLStates CLUSTER_ALREADY_EXISTS = new SQLStates("A cluster with that name exists",
			DUPLICATE_OBJECT, CLUSTER_ALREADY_EXISTS_CODE);
	public static final SQLStates GROUP_ALREADY_EXISTS = new SQLStates("A group with that name exists",
			DUPLICATE_OBJECT, GROUP_ALREADY_EXISTS_CODE);
	public static final SQLStates CONNECTION_ALREADY_EXISTS = new SQLStates("The referenced connection already exists",
			DUPLICATE_OBJECT, CONNECTION_ALREADY_EXISTS_CODE);
	public static final SQLStates CONNECTION_NOT_FOUND = new SQLStates("The referenced connection does not exist",
			OBJECT_NOT_FOUND_STATE, CONNECTION_NOT_FOUND_CODE);
	public static final SQLStates TRANSLATION_NOT_FOUND = new SQLStates("The referenced translation does not exist",
			OBJECT_NOT_FOUND_STATE, TRANSLATION_NOT_FOUND_CODE);
	public static final SQLStates TRANSLATION_ALREADY_EXISTS = new SQLStates(
			"The referenced translation already exists", DUPLICATE_OBJECT, TRANSLATION_ALREADY_EXISTS_CODE);
	public static final SQLStates DATABASE_NOT_FOUND = new SQLStates("The referenced database does not exist",
			OBJECT_NOT_FOUND_STATE, DATABASE_NOT_FOUND_CODE);
	public static final SQLStates STORAGE_SPACE_NOT_FOUND = new SQLStates("The referenced storage space does not exist",
			OBJECT_NOT_FOUND_STATE, STORAGE_SPACE_NOT_FOUND_CODE);
	public static final SQLStates VIEW_NOT_FOUND = new SQLStates("The referenced view does not exist",
			OBJECT_NOT_FOUND_STATE, VIEW_NOT_FOUND_CODE);
	public static final SQLStates USER_NOT_FOUND = new SQLStates("The referenced user does not exist",
			OBJECT_NOT_FOUND_STATE, USER_NOT_FOUND_CODE);
	public static final SQLStates CLUSTER_NOT_FOUND = new SQLStates("The referenced cluster does not exist",
			OBJECT_NOT_FOUND_STATE, CLUSTER_NOT_FOUND_CODE);
	public static final SQLStates GROUP_NOT_FOUND = new SQLStates("The referenced group does not exist",
			OBJECT_NOT_FOUND_STATE, GROUP_NOT_FOUND_CODE);
	public static final SQLStates USER_NOT_IN_GROUP = new SQLStates("The user is not in the specified group",
			OBJECT_NOT_FOUND_STATE, USER_NOT_IN_GROUP_CODE);
	public static final SQLStates NO_EXECUTE_PLAN_AUTH = new SQLStates(
		"The user does not have the authority to execute a plan", AUTH_FAILURE, EXECUTE_PLAN_AUTH_FAILURE);
	public static final SQLStates NO_EXECUTE_INLINE_PLAN_AUTH = new SQLStates(
		"The user does not have the authority to execute an inline plan", AUTH_FAILURE, EXECUTE_INLINE_PLAN_AUTH_FAILURE);

	public static final SQLStates INVALID_ORDER_BY = new SQLStates("Invalid ORDER BY clause", INVALID_ORDER_BY_STATE,
			INVALID_ORDER_BY_CODE);
	public static final SQLStates LIST_TYPE_IN_SELECT_LIST = new SQLStates("A query cannot return a list type",
			BAD_DATA_TYPE, LIST_TYPE_IN_SELECT_LIST_CODE);
	public static final SQLStates LIST_WITHIN_LIST = new SQLStates("Nested lists are not allowed", SYNTAX_ERROR_STATE,
			LIST_WITHIN_LIST_CODE);
	public static final SQLStates INCOMPATIBLE_TYPES_IN_LIST = new SQLStates(
			"All data types within a list must be implicitly convertible to a common data type",
			BAD_SCALAR_TYPE_IN_LIST, INCOMPATIBLE_TYPES_IN_LIST_CODE);
	public static final SQLStates NO_SUCH_FUNCTION = new SQLStates("Call to unknown function", INVALID_FUNCTION_USE,
			UNKNOWN_FUNCTION_CODE);
	public static final SQLStates TKT_RESTRICTIONS_VIOLATED = new SQLStates(
			"The SQL statement is not supported by the TKT engine", SQL_NOT_VALID_IN_CONTEXT,
			SQL_NOT_VALID_IN_CONTEXT_CODE);
	public static final SQLStates NO_READ_AUTH = new SQLStates(
			"The userid does not have read authority on a required table", AUTH_FAILURE, READ_TABLE_AUTH_FAILURE);

	public static final SQLStates NO_CREATE_DATABASE_AUTH = new SQLStates(
		"The user does not have the authority to create a database", AUTH_FAILURE, CREATE_DATABASE_AUTH_FAILURE);
	public static final SQLStates NO_CREATE_VIEW_AUTH = new SQLStates(
		"The user does not have the authority to create a view", AUTH_FAILURE, CREATE_VIEW_AUTH_FAILURE);
	public static final SQLStates NO_CREATE_TABLE_AUTH = new SQLStates(
		"The user does not have the authority to create a table", AUTH_FAILURE, CREATE_TABLE_AUTH_FAILURE);	
	public static final SQLStates NO_CREATE_USER_AUTH = new SQLStates(
		"The user does not have the authority to create a user", AUTH_FAILURE, CREATE_USER_AUTH_FAILURE);
	public static final SQLStates NO_CREATE_GROUP_AUTH = new SQLStates(
		"The user does not have the authority to create a group", AUTH_FAILURE, CREATE_GROUP_AUTH_FAILURE);
	public static final SQLStates NO_EXECUTE_PLAN_AUTH = new SQLStates(
		"The user does not have the authority to execute a plan", AUTH_FAILURE, EXECUTE_PLAN_AUTH_FAILURE);
	public static final SQLStates NO_EXECUTE_INLINE_PLAN_AUTH = new SQLStates(
		"The user does not have the authority to execute an inline plan", AUTH_FAILURE, EXECUTE_INLINE_PLAN_AUTH_FAILURE);

	public static final SQLStates SECURITY_INTEGRATION_DISABLED = new SQLStates("The security integration is disabled", UNABLE_TO_CONNECT, SECURITY_INTEGRATION_DISABLED_CODE);
	public static final SQLStates SECURITY_INTEGRATION_NOT_FOUND = new SQLStates("The security integration does not exist", OBJECT_NOT_FOUND_STATE, SECURITY_INTEGRATION_NOT_FOUND_CODE);
	public static final SQLStates NETWORK_COMMUNICATIONS_ERROR_INVALID_CERTIFICATE = new SQLStates("The request failed due to an network communications error", UNABLE_TO_CONNECT, NETWORK_COMMUNICATIONS_ERROR_INVALID_CERTIFICATE_CODE);
	public static final SQLStates SSO_REQUEST_ID_NOT_FOUND = new SQLStates("The Single Sign On request id could not be found", REJECTED_CONNECTION, SSO_REQUEST_ID_NOT_FOUND_CODE);
	public static final SQLStates SESSION_DOES_NOT_EXIST = new SQLStates("No session associated with the connection exists", NO_CONNECTION_STATE, SESSION_DOES_NOT_EXIST_CODE);
	public static final SQLStates INVALID_SECURITY_TOKEN = new SQLStates("The supplied security token is invalid", REJECTED_CONNECTION, INVALID_SECURITY_TOKEN_CODE);
	public static final SQLStates INVALID_SECURITY_TOKEN_SIGNATURE = new SQLStates("The supplied security token signature does not match the expected value", REJECTED_CONNECTION, INVALID_SECURITY_TOKEN_SIGNATURE_CODE);
	public static final SQLStates INVALID_SECURITY_TOKEN_FINGERPRINT = new SQLStates("The supplied security token has a signature fingerprint from an unknown entity", REJECTED_CONNECTION, INVALID_SECURITY_TOKEN_FINGERPRINT_CODE);
	public static final SQLStates EXPIRED_SECURITY_TOKEN = new SQLStates("The supplied security token has expired", REJECTED_CONNECTION, EXPIRED_SECURITY_TOKEN_CODE);
	public static final SQLStates OIDC_NETWORK_COMMUNICATIONS_ERROR = new SQLStates("A network communications error occurred", UNABLE_TO_CONNECT, OIDC_NETWORK_COMMUNICATIONS_ERROR_CODE);
	public static final SQLStates OIDC_INVALID_REQUEST_OBJECT = new SQLStates("The OpenID provider rejected the request. This indicates an internal server error", UNABLE_TO_CONNECT, OIDC_INVALID_REQUEST_OBJECT_CODE);
	public static final SQLStates OIDC_INVALID_RESPONSE_OBJECT = new SQLStates("The OpenID provider returned an invalid response. This indicates an error with the provider", UNABLE_TO_CONNECT, OIDC_INVALID_RESPONSE_OBJECT_CODE);
	public static final SQLStates OIDC_INVALID_REQUEST_URI = new SQLStates("The OpenID provider rejected the request for the URI. This indicates an internal server error", UNABLE_TO_CONNECT, OIDC_INVALID_REQUEST_URI_CODE);
	public static final SQLStates OIDC_REQUEST_NOT_SUPPORTED = new SQLStates("The OpenID provider does not support the request. This indicates a provider configuration error", UNABLE_TO_CONNECT, OIDC_REQUEST_NOT_SUPPORTED_CODE);
	public static final SQLStates OIDC_REQUEST_URI_NOT_SUPPORTED = new SQLStates("The OpenID provider does not support use of the request_uri parameter (see https://openid.net/specs/openid-connect-core-1_0.html#AuthError)", UNABLE_TO_CONNECT, OIDC_REQUEST_URI_NOT_SUPPORTED_CODE);
	public static final SQLStates OIDC_INVALID_DISCOVERY_DOCUMENT = new SQLStates("The OpenID provider's discovery document is invalid ", UNABLE_TO_CONNECT, OIDC_INVALID_DISCOVERY_DOCUMENT_CODE);
	public static final SQLStates OIDC_INVALID_CONFIGURATION = new SQLStates("The database's OpenID configuration is invalid ", INVALID_ARGUMENT_STATE, OIDC_INVALID_CONFIGURATION_CODE);
	public static final SQLStates OIDC_EXPIRED_TOKEN = new SQLStates("The ID or Access token has expired", REJECTED_CONNECTION, OIDC_EXPIRED_TOKEN_CODE);
	public static final SQLStates OIDC_SIGNING_KEY_NOT_FOUND = new SQLStates("The ID or Access token was signed by a key not known to the OpenID provider", UNABLE_TO_CONNECT, OIDC_SIGNING_KEY_NOT_FOUND_CODE);
	public static final SQLStates OIDC_INVALID_SIGNING_KEY = new SQLStates("The signing key returned by OpenID provider is invalid", UNABLE_TO_CONNECT, OIDC_INVALID_SIGNING_KEY_CODE);
	public static final SQLStates OIDC_INVALID_TOKEN_CLAIM = new SQLStates("The token contains an invalid valid", UNABLE_TO_CONNECT, OIDC_INVALID_TOKEN_CLAIM_CODE);
	public static final SQLStates OIDC_INVALID_TOKEN_ISSUER = new SQLStates("The token was issued by an unknown OpenID provider", AUTH_FAILURE, OIDC_INVALID_TOKEN_ISSUER_CODE);
	public static final SQLStates OIDC_INVALID_TOKEN_AUDIENCE = new SQLStates("The token was issued for an alternate audience", AUTH_FAILURE, OIDC_INVALID_TOKEN_AUDIENCE_CODE);
	public static final SQLStates OIDC_INVALID_TOKEN_SIGNATURE = new SQLStates("The token signature is invalid, implying the token was manipulated en route to the database", REJECTED_CONNECTION, OIDC_INVALID_TOKEN_SIGNATURE_CODE);
	public static final SQLStates OIDC_INVALID_ID_TOKEN = new SQLStates("The supplied ID token is invalid", REJECTED_CONNECTION, OIDC_INVALID_ID_TOKEN_CODE);
	public static final SQLStates OIDC_INVALID_ACCESS_TOKEN = new SQLStates("The supplied Access token is invalid", REJECTED_CONNECTION, OIDC_INVALID_ACCESS_TOKEN_CODE);
	public static final SQLStates OIDC_INVALID_REFRESH_TOKEN = new SQLStates("The Refresh token returned from the provider is invalid", REJECTED_CONNECTION, OIDC_INVALID_REFRESH_TOKEN_CODE);
	public static final SQLStates OAUTH_UNAUTHORIZED_CLIENT = new SQLStates("The client is not authorized to use this authorization grant", AUTH_FAILURE, OAUTH_UNAUTHORIZED_CLIENT_CODE);
	public static final SQLStates OAUTH_ACCESS_DENIED = new SQLStates("The resource owner or authorization server denied the request", AUTH_FAILURE, OAUTH_ACCESS_DENIED_CODE);
	public static final SQLStates OAUTH_UNSUPPORTED_RESPONSE_TYPE = new SQLStates("The authorization server does not support obtaining an authorization code or token using this method", UNABLE_TO_CONNECT, OAUTH_UNSUPPORTED_RESPONSE_TYPE_CODE);
	public static final SQLStates OAUTH_INVALID_SCOPE = new SQLStates("The requested scope is invalid, unknown, or malformed", UNABLE_TO_CONNECT, OAUTH_INVALID_SCOPE_CODE);
	public static final SQLStates OAUTH_INVALID_REQUEST = new SQLStates("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed", UNABLE_TO_CONNECT, OAUTH_INVALID_REQUEST_CODE);
	public static final SQLStates OAUTH_SERVER_ERROR = new SQLStates("The authorization server encountered an unexpected condition that prevented it from fulfilling the request", NON_DATABASE_RESOURCE_NOT_AVAILABLE_STATE, OAUTH_SERVER_ERROR_CODE);
	public static final SQLStates OAUTH_TEMPORARILY_UNAVAILABLE = new SQLStates("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server", NON_DATABASE_RESOURCE_NOT_AVAILABLE_STATE, OAUTH_TEMPORARILY_UNAVAILABLE_CODE);

	public static final SQLStates SESSION_EXPIRED = new SQLStates(
		"Session has expired. Refresh necessary.", AUTH_FAILURE, SESSION_EXPIRED_CODE);																			
			
	public static final SQLStates NO_CREATE_CONNECTION_AUTH = new SQLStates(
			"The user does not have the authority to create a connection.", AUTH_FAILURE,
			CREATE_CONNECTION_AUTH_FAILURE);
	public static final SQLStates CREATE_TASK_FAILURE = new SQLStates("Failed to create task", SYSTEM_ERROR,
			CREATE_TASK_FAILURE_CODE);
	public static final SQLStates NO_DROP_CONNECTION_AUTH = new SQLStates(
			"The user does not have the authority to drop the connection", AUTH_FAILURE, DROP_CONNECTION_AUTH_FAILURE);
	public static final SQLStates NAKED_INTERVAL_TYPE = new SQLStates(
			"If the result of an expression is a time interval type, it must be cast to an integral type",
			BAD_DATA_TYPE, NAKED_INTERVAL_TYPE_CODE);
	public static final SQLStates NOT_A_SELECT = new SQLStates(
			"A SELECT statement was expected, but the command received was not a SELECT statement",
			SQL_NOT_VALID_IN_CONTEXT, NOT_A_SELECT_CODE);
	public static final SQLStates IS_A_SELECT = new SQLStates(
			"A SELECT statement was found where we were not expecting a SELECT statement", SQL_NOT_VALID_IN_CONTEXT,
			IS_A_SELECT_CODE);
	public static final SQLStates ML_MODEL_NOT_FOUND = new SQLStates("Could not find an MLMODEL with that name",
			OBJECT_NOT_FOUND_STATE, ML_MODEL_NOT_FOUND_CODE);
	public static final SQLStates ML_MODEL_ALREADY_EXISTS = new SQLStates("An MLMODEL with that name already exists",
			DUPLICATE_OBJECT, ML_MODEL_ALREADY_EXISTS_CODE);
	public static final SQLStates NULL_OUTPUT_BUFFER = new SQLStates(
			"A null pointer was passed for an output buffer location to an ODBC API call", GENERAL_DRIVER_ERROR,
			NULL_OUTPUT_BUFFER_CODE);
	public static final SQLStates NOT_IMPLEMENTED = new SQLStates("The requested function is not implemented",
			NOT_IMPLEMENTED_STATE, NOT_IMPLEMENTED_CODE);
	public static final SQLStates SEQUENCE_ERROR = new SQLStates("ODBC function sequence error", SEQUENCE_ERROR_STATE,
			SEQUENCE_ERROR_CODE);
	public static final SQLStates INVALID_ATTRIBUTE = new SQLStates("An invalid ODBC attribute was specified",
			INVALID_ATTRIBUTE_STATE, INVALID_ATTRIBUTE_CODE);
	public static final SQLStates INVALID_INPUT = new SQLStates("Invalid input to an ODBC API call",
			INVALID_INPUT_STATE, INVALID_INPUT_CODE);
	public static final SQLStates DYNAMIC_LINK_FAILURE = new SQLStates(
			"The ODBC driver failed to load a required symbol from a shared library", GENERAL_DRIVER_ERROR,
			DYNAMIC_LINK_FAILURE_CODE);
	public static final SQLStates BAD_PARAM_NUM = new SQLStates("An invalid parameter marker number was specified",
			BAD_PARAM_NUM_STATE, BAD_PARAM_NUM_CODE);
	public static final SQLStates INVALID_C_DATA_TYPE = new SQLStates("An invalid C data type was specified",
			INVALID_C_DATA_TYPE_STATE, INVALID_C_DATA_TYPE_CODE);
	public static final SQLStates INVALID_SQL_DATA_TYPE = new SQLStates("An invalid SQL data type was specified",
			INVALID_SQL_DATA_TYPE_STATE, INVALID_SQL_DATA_TYPE_CODE);
	public static final SQLStates NO_CONNECTION = new SQLStates("No database connection exists", NO_CONNECTION_STATE,
			NO_CONNECTION_CODE);
	public static final SQLStates INVALID_PARAMETER_MARKER = new SQLStates(
			"Invalid data was detected for a parameter marker", INVALID_PARAMETER_MARKER_STATE,
			INVALID_PARAMETER_MARKER_CODE);
	public static final SQLStates TRUNCATION = new SQLStates(
			"Data was truncated while transferring data to/from the server", TRUNCATION_STATE, TRUNCATION_CODE);
	public static final SQLStates INVALID_CURSOR_STATE = new SQLStates(
			"The cursor was not in the necessary state for the requested operation", INVALID_CURSOR,
			INVALID_CURSOR_CODE);
	public static final SQLStates INVALID_BUFFER_LENGTH = new SQLStates("An invalid buffer length was specified",
			INVALID_BUFFER_LENGTH_STATE, INVALID_BUFFER_LENGTH_CODE);
	public static final SQLStates NO_ROW_DATA = new SQLStates("No data found", NO_ROW_DATA_STATE, NO_ROW_DATA_CODE);
	public static final SQLStates INVALID_MATRIX_LITERAL = new SQLStates("The syntax of the matrix was invalid",
			SYNTAX_ERROR_STATE, INVALID_MATRIX_LITERAL_CODE);
	public static final SQLStates WRONG_SHAPE_MATRIX_LITERAL = new SQLStates("The matrix has the wrong dimensions",
			SYNTAX_ERROR_STATE, WRONG_SHAPE_MATRIX_LITERAL_CODE);
	public static final SQLStates EXCESSIVE_COST = new SQLStates("The estimated query cost exceeds limit",
			EXCESSIVE_COST_STATE, EXCESSIVE_COST_CODE);
	public static final SQLStates ML_MODEL_ON_EMPTY_SET = new SQLStates("Training MLMODEL on no data",
			NO_ROW_DATA_STATE, ML_MODEL_ON_EMPTY_SET_CODE);
	public static final SQLStates NO_RESULT_SET = new SQLStates("There is currently no result set", NO_CURSOR_STATE,
			NO_RESULT_SET_CODE);
	public static final SQLStates MISSING_NULL_INDICATOR = new SQLStates(
			"A null indicator pointer was required but was not provided", MISSING_NULL_INDICATOR_STATE,
			MISSING_NULL_INDICATOR_CODE);
	public static final SQLStates INVALID_CONN_STR_ATTR = new SQLStates(
			"An invalid connection string attribute was specified", INVALID_CONN_STR_ATTR_STATE,
			INVALID_CONN_STR_ATTR_CODE);
	public static final SQLStates INVALID_DESCRIPTOR_INDEX = new SQLStates(
			"An invalid descriptor record index was specified", INVALID_DESCRIPTOR_INDEX_STATE,
			INVALID_DESCRIPTOR_INDEX_CODE);
	public static final SQLStates INVALID_DESCRIPTOR_INFORMATION = new SQLStates(
			"An invalid or inconsistent descriptor field type was specified", INVALID_DESCRIPTOR_INFORMATION_STATE,
			INVALID_DESCRIPTOR_INFORMATION_CODE);
	public static final SQLStates INVALID_DESCRIPTOR_FIELD = new SQLStates("An invalid descriptor field was specified",
			INVALID_DESCRIPTOR_FIELD_STATE, INVALID_DESCRIPTOR_FIELD_CODE);
	public static final SQLStates COPY_TARGET_IS_IRD = new SQLStates(
			"The target handle passed to SQLCopyDesc was an IRD", COPY_TARGET_IS_IRD_STATE, COPY_TARGET_IS_IRD_CODE);
	public static final SQLStates INVALID_IMPLICIT_DESC_HANDLE_USE = new SQLStates(
			"Invalid use of an automatically allocated descriptor handle", INVALID_IMPLICIT_DESC_HANDLE_USE_STATE,
			INVALID_IMPLICIT_DESC_HANDLE_USE_CODE);
	public static final SQLStates NO_CREATE_MLMODEL_AUTH = new SQLStates(
			"The user does not have the authority to create an MLMODEL", AUTH_FAILURE, NO_CREATE_MLMODEL_AUTH_CODE);
	public static final SQLStates NO_DROP_MLMODEL_AUTH = new SQLStates(
			"The user does not have the authority to drop the MLMODEL", AUTH_FAILURE, NO_DROP_MLMODEL_AUTH_CODE);
	public static final SQLStates DIVDE_BY_ZERO = new SQLStates("Division by zero is invalid", DIVIDE_BY_ZERO_STATE,
			DIVIDE_BY_ZERO_CODE);
	public static final SQLStates OUT_OF_RANGE = new SQLStates("A numeric value is out of range", OUT_OF_RANGE_STATE,
			NUMERIC_VALUE_OUT_OF_RANGE_CODE);
	public static final SQLStates INVALID_FLOATING_POINT_OPERATION = new SQLStates("Invalid floating point operation",
			INVALID_FLOATING_POINT_OPERATION_STATE, INVALID_FLOATING_POINT_OPERATION_CODE);
	public static final SQLStates CONFLICT = new SQLStates(
			"The action conflicts with the current state of the database", CONFLICT_STATE, CONFLICT_CODE);
	public static final SQLStates OPERATION_CANCELED = new SQLStates("Operation was canceled or aborted",
			OPERATION_CANCELED_STATE, OPERATION_CANCELED_CODE);
	public static final SQLStates INVALID_QUERY_PRIORITY = new SQLStates(
			"You do not have the authorization to submit the query, either due to requesting too high a priority or because you have no query privileges",
			SYNTAX_ERROR_STATE, INVALID_QUERY_PRIORITY_CODE);
	public static final SQLStates IO_ERROR = new SQLStates("An IO error occurred",
			NON_DATABASE_RESOURCE_NOT_AVAILABLE_STATE, IO_ERROR_CODE);
	public static final SQLStates INCOMPATIBLE_TYPES_IN_CASE = new SQLStates(
			"Two incompatible data types were specified as return value in a case statement",
			INCOMPATIBLE_TYPES_IN_CASE_STATE, INCOMPATIBLE_TYPES_IN_CASE_CODE);
	public static final SQLStates NOT_COMPATIBLE_COLS = new SQLStates(
			"Columns for first and second select for the UNION, EXCEPT or INTERSECT operator are not compatible.",
			NOT_COMPATIBLE_COLS_STATE, NOT_COMPATIBLE_COLS_CODE);
	public static final SQLStates JOIN_LEADS_TO_DUPLICATE_COL_NAME = new SQLStates(
			"Columns must be renamed so that column names are distinct after a join", AMBIGUOUS_COL_STATE,
			JOIN_LEADS_TO_DUPLICATE_COL_NAME_CODE);
	public static final SQLStates SCALAR_SUBQUERY_CARDINALITY_VIOLATION = new SQLStates(
			"A scalar subquery has too many result values", SCALAR_SUBQUERY_CARDINALITY_VIOLATION_STATE,
			SCALAR_SUBQUERY_CARDINALITY_VIOLATION_CODE);
	public static final SQLStates INVALID_CASE_CONDITION = new SQLStates(
			"An expression in the case condition is not allowed", INVALID_CASE_CONDITION_STATE,
			INVALID_CASE_CONDITION_CODE);
	public static final SQLStates INVALID_JOIN_CONDITION = new SQLStates(
			"An expression in the join condition is not allowed", INVALID_JOIN_CONDITION_STATE,
			INVALID_JOIN_CONDITION_CODE);
	public static final SQLStates AGGREGATION_NOT_ALLOWED_IN_WINDOW_CONSTRUCTION = new SQLStates(
			"Aggregation is not allowed in the PARTITION BY or ORDER BY clauses of a windowed aggregate",
			AGGREGATION_NOT_ALLOWED_IN_WINDOW_CONSTRUCTION_STATE, AGGREGATION_NOT_ALLOWED_IN_WINDOW_CONSTRUCTION_CODE);
	public static final SQLStates EXPECTED_CONST_WINDOWED_AGGREGATE_ARGUMENT = new SQLStates(
			"A non-constant value was found where a constant was expected in an argument to a windowed aggregate",
			EXPECTED_CONST_WINDOWED_AGGREGATE_ARGUMENT_STATE, EXPECTED_CONST_WINDOWED_AGGREGATE_AGRUMENT_CODE);
	public static final SQLStates BAD_RANGE_FRAME_SPECIFICATION = new SQLStates(
			"Range-based framing does not allow the PRECEDING or FOLLOWING keywords",
			BAD_RANGE_FRAME_SPECIFICATION_STATE, BAD_RANGE_FRAME_SPECIFICATION_CODE);
	public static final SQLStates BAD_WINDOWED_ORDER_BY = new SQLStates(
			"Order by with a column ordinal is not allowed in a windowed aggregate", BAD_WINDOWED_ORDER_BY_STATE,
			BAD_WINDOWED_ORDER_BY_CODE);
	public static final SQLStates FRAME_WITHOUT_ORDERING = new SQLStates(
			"A frame specification is not allowed if no ORDER BY is specified in a windowed aggregate",
			FRAME_WITHOUT_ORDERING_STATE, FRAME_WITHOUT_ORDERING_CODE);
	public static final SQLStates BAD_END_FRAME_BOUND = new SQLStates(
			"UNBOUNDED PRECEDING is only allowed on the starting frame bound", BAD_END_FRAME_BOUND_STATE,
			BAD_END_FRAME_BOUND_CODE);
	public static final SQLStates BAD_START_FRAME_BOUND = new SQLStates(
			"UNBOUNDED FOLLOWING is only allowed on the ending frame bound", BAD_START_FRAME_BOUND_STATE,
			BAD_START_FRAME_BOUND_CODE);
	public static final SQLStates INVALID_FRAME_BOUNDS = new SQLStates(
			"The ending frame bound cannot be less than the starting frame bound", INVALID_FRAME_BOUNDS_STATE,
			INVALID_FRAME_BOUNDS_CODE);
	public static final SQLStates FRAME_SPEC_NOT_ALLOWED = new SQLStates(
			"No frame specification is allowed for this particular windowed aggregate", FRAME_SPEC_NOT_ALLOWED_STATE,
			FRAME_SPEC_NOT_ALLOWED_CODE);
	public static final SQLStates WINDOW_FUNC_EXPECTED_POSITIVE_CONSTANT = new SQLStates(
			"A window function was expecting a positive integer argument", WINDOW_FUNC_EXPECTED_POSITIVE_CONSTANT_STATE,
			WINDOW_FUNC_EXPECTED_POSITIVE_CONSTANT_CODE);
	public static final SQLStates UNDEFINED_EXCEPTION = new SQLStates("Undefined exception", UNDEFINED_EXCEPTION_STATE,
			UNDEFINED_EXCEPTION_CODE); // used only when a give sql code is not found in
	// SQLCodeToException map
	public static final SQLStates MISSING_ORDER_BY = new SQLStates(
			"The requested window function requires an ORDER BY in the OVER() clause", SYNTAX_ERROR_STATE,
			MISSING_ORDER_BY_CODE);
	public static final SQLStates PLAN_COMPILATION_ERROR = new SQLStates("Plan Compilation Error",
			PLAN_COMPILATION_ERROR_STATE, PLAN_COMPILATION_ERROR_CODE);
	public static final SQLStates UNABLE_TO_INVERT_SINGULAR_MATRIX = new SQLStates("Unable to invert singular matrix",
			SYSTEM_ERROR, UNABLE_TO_INVERT_SINGULAR_MATRIX_CODE);
	public static final SQLStates UNABLE_TO_DECOMPOSE_SINGULAR_MATRIX = new SQLStates(
			"Unable to perform LUP decomposition on this singular matrix", SYSTEM_ERROR,
			UNABLE_TO_DECOMPOSE_SINGULAR_MATRIX_CODE);
	public static final SQLStates TKT_LIMIT_REACHED = new SQLStates("TKT Operator reached limit", SYSTEM_ERROR,
			TKT_LIMIT_REACHED_CODE);
	public static final SQLStates OUT_OF_MEMORY = new SQLStates("Out of memory", OUT_OF_MEMORY_STATE,
			OUT_OF_MEMORY_CODE);
	public static final SQLStates SEGMENT_NOT_AVAILABLE = new SQLStates("Data required for query is not available",
			STORAGE_OR_DATABASE_RESOURCE_NOT_AVAILABLE_STATE, SEGMENT_NOT_AVAILABLE_CODE);
	public static final SQLStates SYSTEM_INITIALIZING = new SQLStates("The system is initializing",
			STORAGE_OR_DATABASE_RESOURCE_NOT_AVAILABLE_STATE, SYSTEM_INITIALIZING_CODE);
	public static final SQLStates INVALID_AGGREGATION = new SQLStates("Invalid aggregation", INVALID_AGGREGATION_STATE,
			INVALID_AGGREGATION_CODE);
	public static final SQLStates ST_POINT_INVALID_CONVERSION_FROM_NULL = new SQLStates(
			"Invalid st_point conversion from NULL", ST_POINT_INVALID_CONVERSION_FROM_NULL_STATE,
			ST_POINT_INVALID_CONVERSION_FROM_NULL_CODE);
	public static final SQLStates VALUE_TOO_LARGE = new SQLStates("Value larger than internal limits",
			VALUE_TOO_LARGE_STATE, VALUE_TOO_LARGE_CODE);
	public static final SQLStates CASE_WITHIN_CASE = new SQLStates(
			"A CASE expression within a CASE expression is not allowed", INVALID_CASE_CONDITION_STATE,
			CASE_WITHIN_CASE_CODE);
	public static final SQLStates OUT_OF_TEMP_DISK_SPACE = new SQLStates("Out of temporary disk space",
			STORAGE_OR_DATABASE_RESOURCE_NOT_AVAILABLE_STATE, OUT_OF_TEMP_DISK_SPACE_CODE);
	public static final SQLStates INVALID_NEW_USER_PWD = new SQLStates(
			"The supplied password for the new user is invalid", SYNTAX_ERROR_STATE, INVALID_NEW_USER_PWD_CODE);
	public static final SQLStates PRIVILEGE_ALREADY_POSSESSED = new SQLStates(
			"The privilege target already has the privilege.", DUPLICATE_OBJECT, PRIVILEGE_ALREADY_POSSESSED_CODE);
	public static final SQLStates PRIVILEGE_NOT_POSSESSED = new SQLStates(
			"The privilege target does not have that privilege.", OBJECT_NOT_FOUND_STATE, PRIVILEGE_NOT_POSSESSED_CODE);
	public static final SQLStates NO_GRANT_AUTH = new SQLStates(
			"The user does not have the authority to grant this privilege.", AUTH_FAILURE, NO_GRANT_AUTH_CODE);

	public static final SQLStates NODE_NOT_FOUND = new SQLStates("Node not found", OBJECT_NOT_FOUND_STATE,
			NODE_NOT_FOUND_CODE);
	public static final SQLStates TASK_ALREADY_IN_PROGRESS = new SQLStates("Task already in progress", DUPLICATE_OBJECT,
			TASK_ALREADY_IN_PROGRESS_ERROR_CODE);
	public static final SQLStates ID_NOT_FOUND = new SQLStates("The provided object was not found",
			OBJECT_NOT_FOUND_STATE, ID_NOT_FOUND_CODE);
	public static final SQLStates ROLE_NOT_FOUND = new SQLStates("The referenced role does not exist",
			OBJECT_NOT_FOUND_STATE, ROLE_NOT_FOUND_CODE);
	public static final SQLStates OBJECT_NOT_FOUND_WARN = new SQLStates("The referenced object does not exist",
			OBJECT_NOT_FOUND_STATE, OBJECT_NOT_FOUND_WARN_CODE);
	public static final SQLStates OBJECT_ALREADY_EXISTS_WARN = new SQLStates("An object with that name exists",
			DUPLICATE_OBJECT, OBJECT_ALREADY_EXISTS_WARN_CODE);

	public static final SQLException newGenericException(final Exception e) {
		String reason = e.getMessage();
		if (reason == null) {
			reason = "";
		}

		final SQLException retval = new SQLException(reason, SYSTEM_ERROR, GENERIC_EXCEPTION_CODE);
		retval.initCause(e);
		return retval;
	}

	private final String reason;
	private final String sqlState;
	private final int sqlCode;

	private SQLStates(final String reason, final String sqlState, final int sqlCode) {
		this.reason = reason;
		this.sqlState = sqlState;
		this.sqlCode = sqlCode;
	}

	@Override
	public SQLException clone() {
		return new SQLException(reason, sqlState, sqlCode);
	}

	public SQLException cloneAndSpecify(final String newReason) {
		return new SQLException(newReason, sqlState, sqlCode);
	}

	public boolean equals(final SQLException e) {
		return e.getErrorCode() == sqlCode;
	}

	public int getSqlCode() {
		return sqlCode;
	}

	public String getSqlState() {
		return sqlState;
	}
}
