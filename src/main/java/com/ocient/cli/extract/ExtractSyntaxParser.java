package com.ocient.cli.extract;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
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

    private static final Pattern EXTRACT_PATTERN = Pattern.compile(
        "^EXTRACT\\s+TO\\s+(?<" + TYPE_GROUP +
        ">\\w+)\\s+(?:OPTIONS\\((?<" + OPTIONS_GROUP +
        ">(?s).*)\\)\\s+)?AS\\s+(?<" + QUERY_GROUP + 
        ">(.|\n)*)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern ARG_VAL_PATTERN = Pattern.compile(
        "\\s*(?<" + ARG_GROUP +
        ">\\w+)\\s*=\\s*(?<" + VAL_GROUP +
        ">(?<" + UNQUOTED_GROUP +
        ">\\w+)|(\\\"(?<" + QUOTED_GROUP +
        ">.*)\\\"))\\s*",
        Pattern.CASE_INSENSITIVE
    );

    private enum ParseState
    {
        UNQUOTED,
        QUOTED,
        QUOTED_ESCAPED
    }

    private final static char QUOTE_CHARACTER = '\"';
    private final static char COMMA_CHARACTER = ',';
    private final static char ESCAPE_CHARACTER = '\\';
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
        ArrayList<String> tokens = stringTokenizer(ops);

        for(String token : tokens) {
            final Matcher tokenMatcher = ARG_VAL_PATTERN.matcher(token);
            if(!tokenMatcher.matches()){
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

    /**
     * Seperates key and value(possible quoted) pairs into sets
     * Ex: key1=val1,key2="val2",key3=val3 -> [key1=val1, key2=val2, key3=val3]
     * @param options option string containing all the options.
     * @return ArrayList<String> seperated key=value pairs.
     * @throws ParseException
     */

    private static ArrayList<String> stringTokenizer(String options) throws ParseException{
        
        ArrayList<String> tokens = new ArrayList<String>();
        final StringBuilder runningString = new StringBuilder(options.length());
        char[] chars = options.toCharArray();
        ParseState currentState = ParseState.UNQUOTED;

        for(char currentChar: chars){
            switch(currentState){
                case UNQUOTED:{
                    if(currentChar == QUOTE_CHARACTER){
                        // We enter quoted mode
                        runningString.append(currentChar);
                        currentState = ParseState.QUOTED;
                    } else if (currentChar == COMMA_CHARACTER){
                        if(runningString.length() > 0){
                            // We finished a string. Add it then clear the curentString
                            tokens.add(runningString.toString());
                            runningString.setLength(0);
                        }
                    } else {
                        // Otherwise, just add it to the current string
                        runningString.append(currentChar);
                    }
                    break;
                }
                case QUOTED:{
                    if(currentChar == ESCAPE_CHARACTER){
                        // We've been escaped. Don't add this character, but enter quote escape
                        currentState = ParseState.QUOTED_ESCAPED;
                    } else if(currentChar == QUOTE_CHARACTER){
                        // We hit the end of our quote
                        runningString.append(currentChar);
                        currentState = ParseState.UNQUOTED;
                    } else {
                        // Otherwise, just add it to the current string
                        runningString.append(currentChar);
                    }
                    break;
                }
                case QUOTED_ESCAPED:{
                    // Just add the next character, then return back to the quoted state.
                    runningString.append(currentChar);
                    currentState = ParseState.QUOTED;
                    break;
                }
            }
        }
        // Add the last pair which is not followed by a COMMA_CHARACTER.
        if(runningString.length() > 0){
            tokens.add(runningString.toString());
        }
        // We should have returned back to the unquoted state at this point.
        if(currentState != ParseState.UNQUOTED){
            throw new ParseException(String.format("Malformed options missing a closing quote character: %s", options));
        }

        return tokens;
    }
}                        