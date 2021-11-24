package com.ocient.cli.extract;

import com.ocient.cli.extract.ExtractConfiguration;
import com.ocient.cli.ParseException;

import org.junit.Test;
import org.junit.runner.RunWith;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import static org.junit.Assert.assertEquals;

import java.nio.charset.Charset;
import java.util.Properties;

@RunWith(JUnitParamsRunner.class)
public class ExtractConfigurationTest 
{

    @Test
    public void defaultConfig()
    {
        Properties prop = new Properties();
        prop.setProperty("location_type", "local");

        ExtractConfiguration config = new ExtractConfiguration(prop);
        assertEquals(config.getLocationType(), ExtractConfiguration.LocationType.LOCAL); // Case insensitive
        assertEquals(config.getFileType(), ExtractConfiguration.FileType.DELIMITED);
        assertEquals(config.getFilePrefix(), ExtractConfiguration.DEFAULT_FILE_PREFIX);
        assertEquals(config.getFileExtension(), ExtractConfiguration.DEFAULT_FILE_EXTENSION);
        assertEquals(config.getMaxRowsPerFile(), ExtractConfiguration.DEFAULT_MAX_ROWS_PER_FILE);
        assertEquals(config.getCompression(), ExtractConfiguration.Compression.NONE);
        assertEquals(config.getBucket(), ExtractConfiguration.DEFAULT_BUCKET);
        assertEquals(config.getAwsKeyId(), ExtractConfiguration.DEFAULT_AWS_KEY_ID);
        assertEquals(config.getAwsKeySecret(), ExtractConfiguration.DEFAULT_AWS_SECRET_KEY);
        assertEquals(config.getRecordDelimiter(), ExtractConfiguration.DEFAULT_RECORD_DELIMITER);
        assertEquals(config.getFieldDelimiter(), ExtractConfiguration.DEFAULT_FIELD_DELIMITER);
        assertEquals(config.getSkipHeader(), ExtractConfiguration.DEFAULT_SKIP_HEADER);
        assertEquals(config.getNullFormat(), ExtractConfiguration.DEFAULT_NULL_FORMAT);
        assertEquals(config.getEncoding(), ExtractConfiguration.DEFAULT_ENCODING);
        assertEquals(config.getEscape(), ExtractConfiguration.DEFAULT_ESCAPE);
        assertEquals(config.getFieldOptionallyEnclosedBy(), ExtractConfiguration.DEFAULT_FIELD_OPTIONALL_ENCLOSED_BY);
        assertEquals(config.getBinaryFormat(), ExtractConfiguration.BinaryFormat.HEXADECIMAL);
    }

    @Test
    public void nonDefaults()
    {
        Properties prop = new Properties();
        prop.setProperty("location_type", "s3");
        prop.setProperty("file_type", "delimited");
        prop.setProperty("file_prefix", "somePrefix-");
        prop.setProperty("file_extension", ".tsv");
        prop.setProperty("max_rows_per_file", "100");
        prop.setProperty("compression", "gzip");
        prop.setProperty("bucket", "fakeBucket");
        prop.setProperty("aws_key_id", "fakeId");
        prop.setProperty("aws_secret_key", "fakeSecret");
        prop.setProperty("record_delimiter", " ");
        prop.setProperty("field_delimiter", "\t");
        prop.setProperty("skip_header", "true");
        prop.setProperty("null_format", "NULL");
        prop.setProperty("encoding", "UTF-16");
        prop.setProperty("escape", "+");
        prop.setProperty("field_optionally_enclosed_by", "|");
        prop.setProperty("binary_format", "UTF8");
        // Build config
        ExtractConfiguration config = new ExtractConfiguration(prop);
        // Assert the non defaults are set correctly.
        assertEquals(config.getLocationType(), ExtractConfiguration.LocationType.S3); // Case insensitive
        assertEquals(config.getFileType(), ExtractConfiguration.FileType.DELIMITED); // Case insensitive
        assertEquals(config.getFilePrefix(), "somePrefix-");
        assertEquals(config.getFileExtension(), ".tsv");
        assertEquals(config.getMaxRowsPerFile(), Integer.valueOf(100));
        assertEquals(config.getCompression(), ExtractConfiguration.Compression.GZIP); // Case insensitive
        assertEquals(config.getBucket(), "fakeBucket");
        assertEquals(config.getAwsKeyId(), "fakeId");
        assertEquals(config.getAwsKeySecret(), "fakeSecret");
        assertEquals(config.getRecordDelimiter(), " ");
        assertEquals(config.getFieldDelimiter(), "\t");
        assertEquals(config.getSkipHeader(), true);
        assertEquals(config.getNullFormat(), "NULL");
        assertEquals(config.getEncoding(), Charset.forName("UTF-16"));
        assertEquals(config.getEscape(), '+');
        assertEquals(config.getFieldOptionallyEnclosedBy(), '|');
        assertEquals(config.getBinaryFormat(), ExtractConfiguration.BinaryFormat.UTF8);;
    }

    // These should throw an illegal argument exception because they fail to convert to our specified enums.
    @Test(expected = ParseException.class)
    @Parameters({
        "location_type, badLocationType", // A bad location type
        "file_type, notDelimited", // Filetype is not delimited
        "compression, random", // Not either None or GZIP
        "max_rows_per_file, -1", // A negative number
        "max_rows_per_file, NotANumber", // Not a number
        "encoding, badEncoding", // Bad encoding name
        "binary_format, a_bad_format", // Not a valid format
    })
    public void invalidInputs(String configKey, String configValue)
    {
        Properties properties = new Properties();
        // Location type is required to test the other configs.
        properties.setProperty("location_type", "local");        
        properties.setProperty(configKey, configValue);
        ExtractConfiguration config = new ExtractConfiguration(properties);  
    }

    // Setting S3 but not providing a bucket should throw a parse exception.
    @Test(expected = ParseException.class)
    public void S3NoBuckets()
    {
        Properties properties = new Properties();
        // Location type is required to test the other configs.
        properties.setProperty("location_type", "s3");
        ExtractConfiguration config = new ExtractConfiguration(properties);        
    }

    // Test shouldn't throw, but will log a warning.
    @Test
    public void LocalWithBucket()
    {
        Properties properties = new Properties();
        // Location type is required to test the other configs.
        properties.setProperty("location_type", "local");
        properties.setProperty("bucket", "someBucket");
        ExtractConfiguration config = new ExtractConfiguration(properties);
    }
}
