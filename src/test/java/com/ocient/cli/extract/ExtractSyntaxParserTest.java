package com.ocient.cli.extract;

import com.ocient.cli.ParseException;
import com.ocient.cli.extract.ExtractSyntaxParser.ParseResult;

import org.junit.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

public class ExtractSyntaxParserTest
{
    final private static String QUERY = "SELECT * FROM db";
    final private static String WITH_QUERY = "WITH t1 (c1) as (select c1 from table1) select t2 from table2 where t1 > t2";

    // Any options which contain alphanumeric characters need to be quoted.
    final private static Map<String,String> MANY_LOCAL_OPS = Map.of(
        ExtractConfiguration.LOCATION_TYPE, "local",
        ExtractConfiguration.FIELD_DELIMITER, "\"|\"",
        ExtractConfiguration.AWS_KEY_ID, "my_aws_key_id",
        ExtractConfiguration.AWS_SECRET_KEY, "secret_key",
        ExtractConfiguration.FILE_EXTENSION, "\".txt\"",
        ExtractConfiguration.COMPRESSION, "gzip",
        ExtractConfiguration.FILE_PREFIX, "\"/my/path/to/files/data-\""
    );

    private String makeLocalCommand(final Map<String,String> ops, final String query, final String eol, final String delim)
    {
        if (ops != null)
        {
            final String configs = ops.entrySet()
                                        .stream()
                                        .map(kV -> kV.getKey() + delim + kV.getValue())
                                        .collect(
                                            Collectors.joining(eol));
            return  "EXTRACT TO local OPTIONS(" + configs + ") AS " + query;
        }
        else
        {
            return "EXTRACT TO local AS " + query;
        }
    }

    private void checkOptions(final Properties configs, final Map<String,String> ops)
    {        
        assertThat(configs.size(), is(ops.size()));

        for (final Map.Entry<String,String> op: ops.entrySet())
        {
            if(op.getValue().charAt(0) == '"' && op.getValue().charAt(op.getValue().length() - 1) == '"'){
                String quotedVal = op.getValue();
                // If it is a quoted val, then the parser unquotes it automatically.
                assertThat(configs.get(op.getKey()), is(quotedVal.substring(1, quotedVal.length() - 1)));
            } else {
                assertThat(configs.get(op.getKey()), is(op.getValue()));
            }
        }
    }

    @Test
    public void noOptionsLocal()
    {
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(null, QUERY, ",", "="));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), Map.of(
            ExtractConfiguration.LOCATION_TYPE, "local"
        ));
    }

    @Test
    public void noOptionsS3()
    {
        final String cmd = "EXTRACT TO S3 AS " + QUERY;
        final ParseResult res = ExtractSyntaxParser.parse(cmd);
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), Map.of(
            ExtractConfiguration.LOCATION_TYPE, "S3"
        ));
    }

    @Test
    public void singleOption()
    {
        final Map<String,String> ops = Map.of(
            ExtractConfiguration.LOCATION_TYPE, "local",
            ExtractConfiguration.FIELD_DELIMITER, "\"|\""
        );

        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(ops, QUERY, ",", "="));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), ops);
    }

    @Test
    public void blankSpace()
    {
        final Map<String,String> ops = Map.of(
            ExtractConfiguration.LOCATION_TYPE, "local",
            ExtractConfiguration.FIELD_DELIMITER, "\" \""
        );

        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(ops, QUERY, ",", "="));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), ops);
    }    

    @Test(expected = ParseException.class)
    public void repeatedKeys()
    {
        // Have to write custom command because makeLocalCommand takes a map.
        final String repeatedKeyCmd = String.format("EXTRACT to local OPTIONS(%s = %s, %s = %s) AS SELECT * FROM table", ExtractConfiguration.FIELD_DELIMITER, "\"|\"", ExtractConfiguration.FIELD_DELIMITER, "\",\"");
        // This should throw a Parse Exception
        final ParseResult res = ExtractSyntaxParser.parse(repeatedKeyCmd);
    }

    @Test
    public void manyOptions()
    {        
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(MANY_LOCAL_OPS, QUERY, ",", "="));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), MANY_LOCAL_OPS);
    }

    @Test
    public void manyOptionsNewLines()
    {        
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(MANY_LOCAL_OPS, QUERY, ",\n", "="));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), MANY_LOCAL_OPS);
    }

    @Test
    public void manyOptionsSpaces()
    {        
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(MANY_LOCAL_OPS, QUERY, ",", " = "));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), MANY_LOCAL_OPS);
    }

    @Test
    public void manyOptionsManySpaces()
    {        
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(MANY_LOCAL_OPS, QUERY, ",", "  =  "));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), MANY_LOCAL_OPS);
    }

    @Test
    public void manyOptionsMultipleNewlines()
    {   
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(MANY_LOCAL_OPS, QUERY, ",\n\n", "="));
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), MANY_LOCAL_OPS);
    }

    @Test
    public void withQuery()
    {
        final ParseResult res = ExtractSyntaxParser.parse(makeLocalCommand(null, WITH_QUERY, ",", "="));
        assertThat(res.getQuery(), is(WITH_QUERY));

        checkOptions(res.getConfig(), Map.of(
            ExtractConfiguration.LOCATION_TYPE, "local"
        ));
    }

    @Test
    public void emptyOptions()
    {
        final ParseResult res = ExtractSyntaxParser.parse("EXTRACT TO local OPTIONS() AS " + QUERY);
        assertThat(res.getQuery(), is(QUERY));

        checkOptions(res.getConfig(), Map.of(
            ExtractConfiguration.LOCATION_TYPE, "local"
        ));
    }

    @Test(expected = ParseException.class)
    public void noExtract()
    {
        ExtractSyntaxParser.parse("NOT AN EXTRACT STATEMENT");
    }

    @Test(expected = ParseException.class)
    public void missingAs()
    {
        ExtractSyntaxParser.parse("EXTRACT TO local SELECT * FROM table");
    }

    @Test(expected = ParseException.class)
    public void noQuery()
    {
        ExtractSyntaxParser.parse("EXTRACT TO local AS");
    }

    @Test(expected = ParseException.class)
    public void missingTo()
    {
        ExtractSyntaxParser.parse("EXTRACT local AS SELECT * FROM table");
    }

    @Test(expected = ParseException.class)
    public void missingType()
    {
        ExtractSyntaxParser.parse("EXTRACT TO AS SELECT * FROM table");
    }
}            