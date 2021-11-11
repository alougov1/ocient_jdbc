package com.ocient.cli.extract;

import java.util.Properties;
import java.util.stream.Collectors;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.ConfigurationConverter;
import org.apache.commons.configuration2.ImmutableConfiguration;
import org.apache.commons.configuration2.MapConfiguration;
import org.apache.commons.configuration2.ex.ConversionException;

import static org.apache.commons.lang3.Validate.notNull;

import com.ocient.cli.ParseException;

public class ExtractConfiguration 
{

    public ExtractConfiguration(final Properties properties)
    {
        notNull(properties, "ExtractConfiguration received null properties object");
        final ImmutableConfiguration config = createConfig(properties);

        try{
            // Only location type is required.
            locationType = LocationType.valueOf(notNull(config.getString(LOCATION_TYPE), "Location type is a required configuration option").toUpperCase());
            // To achieve case insensitivity for file type
            fileType = FileType.valueOf(config.getString(FILE_TYPE, DEFAULT_FILE_TYPE).toUpperCase());
            // To achieve case insensitivity for compression
            compression = Compression.valueOf(config.getString(COMPRESSION, DEFAULT_COMPRESSION).toUpperCase());            
            maxRowsPerFile = config.getInt(MAX_ROWS_PER_FILE, DEFAULT_MAX_ROWS_PER_FILE);
            skipHeader = config.getBoolean(SKIP_HEADER, DEFAULT_SKIP_HEADER);
        } 
        catch (NullPointerException | IllegalArgumentException | ConversionException ex)
        {
            LOGGER.log(Level.WARNING, "Caught exception in ExtractConfiguration constructor with message: %s", ex.getMessage());
            throw new ParseException(ex.getMessage(), ex);
        }
        filePrefix = config.getString(FILE_PREFIX, DEFAULT_FILE_PREFIX);
        fileExtension = config.getString(FILE_EXTENSION, DEFAULT_FILE_EXTENSION);
        bucket = config.getString(BUCKET, DEFAULT_BUCKET);
        awsKeyId = config.getString(AWS_KEY_ID, DEFAULT_AWS_KEY_ID);
        awsKeySecret = config.getString(AWS_SECRET_KEY, DEFAULT_AWS_SECRET_KEY);
        recordDelimiter = config.getString(RECORD_DELIMITER, DEFAULT_RECORD_DELIMITER);
        fieldDelimiter = config.getString(FIELD_DELIMITER, DEFAULT_FIELD_DELIMITER);
        nullFormat = config.getString(NULL_FORMAT, DEFAULT_NULL_FORMAT);

        // Validate the configurations.
        validateConfiguration();
    }

    public enum LocationType
    {
        LOCAL,
        S3;
    }

    public enum FileType
    {
        DELIMITED;
    }
    
    public enum Compression
    {
        NONE,
        GZIP;
    }

    // Defaults for all options and expected paths in the property map.
    public static final String LOCATION_TYPE = "location_type";
    
    public static final String FILE_TYPE = "file_type";
    public static final String DEFAULT_FILE_TYPE = FileType.DELIMITED.toString();

    public static final String FILE_PREFIX = "file_prefix";
    public static final String DEFAULT_FILE_PREFIX = "results-";

    public static final String FILE_EXTENSION = "file_extension";
    public static final String DEFAULT_FILE_EXTENSION = ".csv";

    public static final String MAX_ROWS_PER_FILE = "max_rows_per_file";
    public static final int DEFAULT_MAX_ROWS_PER_FILE = 0;

    public static final String COMPRESSION = "compression";
    public static final String DEFAULT_COMPRESSION = Compression.NONE.toString();

    public static final String BUCKET = "bucket";
    public static final String DEFAULT_BUCKET = null;

    public static final String AWS_KEY_ID = "aws_key_id";
    public static final String DEFAULT_AWS_KEY_ID = "";

    public static final String AWS_SECRET_KEY = "aws_secret_key";
    public static final String DEFAULT_AWS_SECRET_KEY = "";

    public static final String RECORD_DELIMITER = "record_delimiter";
    public static final String DEFAULT_RECORD_DELIMITER = "\n";

    public static final String FIELD_DELIMITER = "field_delimiter";
    public static final String DEFAULT_FIELD_DELIMITER = ",";

    public static final String SKIP_HEADER = "skip_header";
    public static final boolean DEFAULT_SKIP_HEADER = false;

    public static final String NULL_FORMAT = "null_format";
    public static final String DEFAULT_NULL_FORMAT = "";

    // Only required configuration. Local or S3
    private final LocationType locationType;

    // Optional configurations

    // Delimited file type (e.g. CSV files). Default and only supported type.
    private final FileType fileType;
    // Prefix of the file to write. May contain an absolute or relative path containing the folder location.
    private final String filePrefix;
    //  Extension to append to each file prefix after the file number.
    private final String fileExtension;
    // If non-zero, the MAX_ROWS_PER_FILE modifier splits the results into files with maximum MAX_ROWS_PER_FILE in each file.
    private final int maxRowsPerFile;
    // Compression type to use
    private final Compression compression;
    // S3 bucket to use. Only relevant when locationType is S3.
    private final String bucket;
    // AWS key ID. If empty, the CLI will use the Java AWS SDK default credentials provider chain.
    private final String awsKeyId;
    // AWS secret key. If empty, the CLI will use the Java AWS SDK default credentials provider chain.
    private final String awsKeySecret;
    // Delimiter to use between records. This supports Java strings, so special characters can be input via escape characters.
    private final String recordDelimiter;
    // Delimiter to use between fields within a record. This supports Java strings, so special characters can be input via escape characters.
    private final String fieldDelimiter;
    // If false, write a header with column names into each file. If true, skip the header.
    private final boolean skipHeader;
    // Format string to use for writing NULL values to the output files.
    private final String nullFormat;

    private static final Logger LOGGER = Logger.getLogger("com.ocient.cli.extract");
    
    // Getters for all configurations.
    public LocationType getLocationType()
    {
        return locationType;
    }

    public FileType getFileType()
    {
        return fileType;
    }

    public String getFilePrefix()
    {
        return filePrefix;
    }

    public String getFileExtension()
    {
        return fileExtension;
    }

    public int getMaxRowsPerFile()
    {
        return maxRowsPerFile;
    }

    public Compression getCompression()
    {
        return compression;
    }

    public String getBucket()
    {
        return bucket;
    }

    public String getAwsKeyId()
    {
        return awsKeyId;
    }

    public String getAwsKeySecret()
    {
        return awsKeySecret;
    }

    public String getRecordDelimiter()
    {
        return recordDelimiter;
    }

    public String getFieldDelimiter()
    {
        return fieldDelimiter;
    }

    public boolean getSkipHeader()
    {
        return skipHeader;
    }

    public String getNullFormat()
    {
        return nullFormat;
    }

    private static ImmutableConfiguration createConfig(final Properties properties) 
    {
      return remapConfigKeys(ConfigurationConverter.getConfiguration(properties));
    }
    
    // Helper function to implement case insensitivity by making everything lower case.
    private static Configuration remapConfigKeys(final ImmutableConfiguration config)
    {
        return new MapConfiguration(
            IteratorUtils.toList(config.getKeys()).stream()
            .collect(
                Collectors.toUnmodifiableMap(String::toLowerCase, config::getProperty)
            )
        );    
    }

    // For certain configuration options, additional checks are necessary.
    // Future validation logic can be added here as necessary.
    private void validateConfiguration() throws ParseException
    {
        if(maxRowsPerFile < 0)
        {
            throw new ParseException(String.format("A non negative number is necessary for max rows per file. Specified: %d.", maxRowsPerFile));
        }
        if(locationType == LocationType.S3 && bucket == null)
        {
            throw new ParseException("S3 specified but no bucket provided");
        }
        if(locationType != LocationType.S3 && bucket != null)
        {
            LOGGER.log(Level.WARNING, String.format("Location type was not S3 (was %s) and a bucket (%s) was specified. Bucket will be ignored.", locationType.name(), bucket));
        }
    }
}
