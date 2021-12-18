package com.ocient.cli.extract;


import com.ocient.cli.CLI;
import com.ocient.cli.extract.ExtractSyntaxParser.ParseResult;

import org.junit.Test;
import org.junit.runner.RunWith;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;

@RunWith(JUnitParamsRunner.class)
public class CliTest {
    
    private final String EXTRACT_LEFT = "EXTRACT TO local OPTIONS(";
    private final String EXTRACT_RIGHT = ") AS select c1 + 1, c1 from sys.dummy10";
    // Test which will ensure scrub command does not get broken for extract.
    @Test
    @Parameters({
        "file_prefix=\"/ocient/db/clone_xgsrc/xgsrc/testExtract/results/result\"", // Simple path prefix option
        "field_delimiter=\"\\\"\"", // Option with escaped quote
        "field_delimiter=\" \"",
        "field_delimiter=\"\"",
        "record_delimiter=unquoted",
        "field_delimiter=\"'with single quotes'\"",
        "file_prefix=\"prefix\"\\,\nfield_delimiter=\"\\\"\"\\,record_delimiter=\"\\|\"\n"

    })
    public void scrubCommand(String options){

        String cmd = EXTRACT_LEFT + options + EXTRACT_RIGHT;
        String scrubbedCommand = CLI.scrubCommand(cmd);
        ParseResult result = ExtractSyntaxParser.parse(scrubbedCommand);

    }
}
