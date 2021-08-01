package com.ocient.jdbc;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XGRegexUtils{

	public static Pattern connectToSyntax = Pattern.compile(
		"connect\\s+to\\s+(?<preurl>jdbc:ocient://?)(?<hosts>.+?)(?<posturl>/.+?)(?<up>\\s+user\\s+(" + userTk() + ")\\s+using\\s+(?<q>\"?)(?<pwd>.+?)\\k<q>)?(?<force>\\s+force)?",
		Pattern.CASE_INSENSITIVE);    

	public static Pattern listTablesSyntax = Pattern.compile("list\\s+tables(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);
    public static Pattern listSystemTablesSyntax = Pattern.compile("list\\s+system\\s+tables(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);
	public static Pattern listViewsSyntax = Pattern.compile("list\\s+views(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);
	public static Pattern listIndexesSyntax = Pattern.compile("list\\s+ind(ic|ex)es\\s+((" + XGRegexUtils.tk("schema") + ")\\.)?(" + XGRegexUtils.tk("table") + ")(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);
	public static Pattern describeTableSyntax = Pattern.compile("describe(\\s+table\\s+)?((" + XGRegexUtils.tk("schema") + ")\\.)?(" + XGRegexUtils.tk("table") + ")(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);
	public static Pattern describeViewSyntax = Pattern.compile("describe(\\s+view\\s+)?((" + XGRegexUtils.tk("schema") + ")\\.)?(" + XGRegexUtils.tk("view") + ")(?<verbose>\\s+verbose)?", Pattern.CASE_INSENSITIVE);    


    // Get a token from its generated regex according to SQL case-sensitivity rules
	// (sensitive iff quoted).
	// Do not call on a matcher that has not yet called matches().
	public static String getTk(final Matcher m, final String name, final String def)
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

	// Generate a regex for an unquoted alphanumeric ([a-zA-Z0-9_]) or quoted free
	// (.) token. Reluctant.
	// Do not insert multiple regexes for tokens of the same name (or "q0" + another
	// name) into a single pattern.
	public static String tk(final String name)
	{
		return "(?<q0" + name + ">\"?)(?<" + name + ">(\\w+?|(?<=\").+?(?=\")))\\k<q0" + name + ">";
	}   
    
    // Syntax is set <optionName> <optionValue>;
    // Option value can be quoted or unquoted. Unquoted values can only be alphanumeric
    public static Matcher genericSetSyntaxMatch(final String optionName, final String cmd) 
    {
        String regex = "set\\s+" + optionName + "\\s+" + XGRegexUtils.tk(optionName);
        Pattern genericSetSyntax = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        return genericSetSyntax.matcher(cmd);
    }

	// Generate a regex for an unquoted alphanumeric ([a-zA-Z0-9_]) or quoted free
	// (.) token possibly followed
	// by @ and more unquoted alphanumeric ([a-zA-Z0-9_]) or quoted free (.) tokens.
	private static String userTk()
	{
		return "(?<q0user>\"?)(?<user>(\\w+?|(?<=\").+?(?=\"))(@(\\w+?|(?<=\").+?(?=\")))?)\\k<q0user>";
	}    

}