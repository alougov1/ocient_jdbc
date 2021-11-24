package com.ocient.cli.extract;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.HashMap;
import java.util.Map;

import com.ocient.cli.ParseException;

/**
 * A utility class for parsing the "EXTRACT TO" syntax into its
 * configuration and query components
 */ 
public class ExtractSyntaxParser
{
    private static String TYPE_GROUP = "type";
    private static String OPTIONS_GROUP = "ops";
    private static String QUERY_GROUP = "query";
    private static String ARG_GROUP = "arg";
    private static String VAL_GROUP = "val";
    private static String QUOTED_GROUP = "quoted";
    private static String UNQUOTED_GROUP = "unquoted";

    // Courtesy of https://stackoverflow.com/questions/1757065/java-splitting-a-comma-separated-string-but-ignoring-commas-in-quotes?rq=1
    private static String TOKEN_SPLITTER_STRING = new String(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

    private static final Pattern EXTRACT_PATTERN = Pattern.compile(
        "^EXTRACT\\s+TO\\s+(?<" + TYPE_GROUP +
        ">\\w+)\\s+(?:OPTIONS\\((?<" + OPTIONS_GROUP +
        ">(?s).*)\\)\\s+)?AS\\s+(?<" + QUERY_GROUP + 
        ">(.|\n)*)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern ARG_VAL_PATTERN = Pattern.compile(
        "(?<" + ARG_GROUP +
        ">\\w+)\\s*=\\s*(?<" + VAL_GROUP +
        ">(?<" + UNQUOTED_GROUP +
        ">\\w+)|(\\\"(?<" + QUOTED_GROUP +
        ">[^\\\"]*)\\\"))",
        Pattern.CASE_INSENSITIVE
    );
    
    /**
     * A class to wrap the result of an "EXTRACT TO" parse
     */
    public static class ParseResult
    {
        private String query;
        private Properties config;

        private ParseResult(final String query, final Properties config)
        {
            this.query = query;
            this.config = config;
        }

        /**
        * Returns the query associated with the statement
        * 
        * @return the query string
        */
        public String getQuery()
        {
            return this.query;
        }

        /**
        * Gets the configuration assocated with the statement
        * 
        * @return the configuration as a Properties object
        */
        public Properties getConfig()
        {
            return this.config;
        }
    }

    /**
    * Parse an "EXTRACT TO" command
    * 
    * @param cmd the command string
    * @return the ParseResult from the command string
    * @throws ParseException if the command could not be parsed
    */
    public static ParseResult parse(final String cmd)
    {

        final Matcher m = EXTRACT_PATTERN.matcher(cmd);
        if (!m.matches()) 
        {
            throw new ParseException("Bad syntax");
        }

        final String type = m.group(TYPE_GROUP);
        final String query = m.group(QUERY_GROUP);

        final Properties config = parseOptions(m.group(OPTIONS_GROUP));
        config.setProperty(ExtractConfiguration.LOCATION_TYPE, type);
        return new ParseResult(query, config);
    }

    // https://stackoverflow.com/questions/1757065/java-splitting-a-comma-separated-string-but-ignoring-commas-in-quotes?rq=1
    private static Properties parseOptions(String ops) throws ParseException
    {
        if (ops == null || ops.equals("")) 
        {
            return new Properties();
        }
        
        Map<String, String> keyValuePairs = new HashMap<String,String>();

        String[] tokens = ops.split(TOKEN_SPLITTER_STRING, -1);

        for(String token : tokens) {
            final Matcher tokenMatcher = ARG_VAL_PATTERN.matcher(token);
            if(!tokenMatcher.find()){
                throw new ParseException(String.format("Parsing found bad token: %s", token));
            }

            String key = tokenMatcher.group(ARG_GROUP);
            String val = (tokenMatcher.group(UNQUOTED_GROUP) != null) ? tokenMatcher.group(UNQUOTED_GROUP) : tokenMatcher.group(QUOTED_GROUP);
            String maybePrevVal = keyValuePairs.put(key, val);
            if(maybePrevVal != null){
                throw new ParseException(String.format("Duplicate value detected for key: %s which was: %s", key, maybePrevVal));
            }
        }
        Properties ret = new Properties();
        ret.putAll(keyValuePairs);
        return ret;
    }
}                        