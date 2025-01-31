package com.ocient.cli.extract;

import java.nio.charset.Charset;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.Optional;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.ConfigurationConverter;
import org.apache.commons.configuration2.ImmutableConfiguration;
import org.apache.commons.configuration2.MapConfiguration;
import org.apache.commons.configuration2.ex.ConversionException;

import software.amazon.awssdk.regions.Region;
import static org.apache.commons.lang3.Validate.notNull;

import com.ocient.cli.ParseException;

public class ExtractConfiguration 
{

    public ExtractConfiguration(final Properties properties)
    {
        notNull(properties, "ExtractConfiguration received null properties object");
        final ImmutableConfiguration config = createConfig(properties);

        try
        {
            // Only location type is required.
            locationType = LocationType.valueOf(notNull(config.getString(LOCATION_TYPE), "Location type is a required configuration option").toUpperCase());
            // To achieve case insensitivity for file type
            fileType = FileType.valueOf(config.getString(FILE_TYPE, DEFAULT_FILE_TYPE).toUpperCase());
            // To achieve case insensitivity for compression
            compression = Compression.valueOf(config.getString(COMPRESSION, DEFAULT_COMPRESSION).toUpperCase());            
            maxRowsPerFile = config.getInteger(MAX_ROWS_PER_FILE, DEFAULT_MAX_ROWS_PER_FILE);
            skipHeader = config.getBoolean(SKIP_HEADER, DEFAULT_SKIP_HEADER);
            pathStyleAccess = config.getBoolean(PATH_STYLE_ACCESS, DEFAULT_PATH_STYLE_ACCESS);
            multiThreadingAllowed = config.getBoolean(MULTITHREADING_ALLOWED, DEFAULT_MULTITHREADING_ALLOWED);
            numExtractThreads = config.getInt(NUM_EXTRACT_THREADS, DEFAULT_NUM_EXTRACT_THREADS);
            // This Charset.forName will throw illegalArgumentException if name is not valid.
            encoding = Optional.ofNullable(config.getString(ENCODING)).map(Charset::forName).orElse(DEFAULT_ENCODING);
            escape = config.get(Character.class, ESCAPE, DEFAULT_ESCAPE);
            fieldOptionallyEnclosedBy = config.get(Character.class, FIELD_OPTIONALLY_ENCLOSED_BY, DEFAULT_FIELD_OPTIONALL_ENCLOSED_BY);
            binaryFormat = BinaryFormat.valueOf(config.getString(BINARY_FORMAT, DEFAULT_BINARY_FORMAT).toUpperCase());
        } 
        catch (NullPointerException | IllegalArgumentException | ConversionException ex)
        {
            throw new ParseException(ex.getMessage(), ex);
        }
        filePrefix = config.getString(FILE_PREFIX, DEFAULT_FILE_PREFIX);
        fileExtension = config.getString(FILE_EXTENSION, DEFAULT_FILE_EXTENSION);
        bucket = config.getString(BUCKET, DEFAULT_BUCKET);
        region = config.getString(REGION, DEFAULT_REGION);
        endpoint = config.getString(ENDPOINT, DEFAULT_ENDPOINT);
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

    // These are the formats supported by snowflake.
    public enum BinaryFormat
    {
        HEXADECIMAL,
        UTF8,
        BASE64,
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
    public static final Integer DEFAULT_MAX_ROWS_PER_FILE = null;

    public static final String COMPRESSION = "compression";
    public static final String DEFAULT_COMPRESSION = Compression.NONE.toString();

    public static final String BUCKET = "bucket";
    public static final String DEFAULT_BUCKET = null;

    public static final String REGION = "region";
    public static final String DEFAULT_REGION = Region.US_EAST_2.toString();

    public static final String ENDPOINT = "endpoint";
    public static final String DEFAULT_ENDPOINT = null;

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

    public static final String PATH_STYLE_ACCESS = "path_style_access";
    public static final boolean DEFAULT_PATH_STYLE_ACCESS = false;

    public static final String MULTITHREADING_ALLOWED = "allow_multithreading";
    public static final boolean DEFAULT_MULTITHREADING_ALLOWED = false;

    public static final String NUM_EXTRACT_THREADS = "num_extract_threads";
    public static final int DEFAULT_NUM_EXTRACT_THREADS = 4;

    public static final String NULL_FORMAT = "null_format";
    public static final String DEFAULT_NULL_FORMAT = "";

    public static final String ENCODING = "encoding";
    public static final Charset DEFAULT_ENCODING = Charset.defaultCharset(); 

    public static final String ESCAPE = "escape";
    public static final char DEFAULT_ESCAPE = '\\';

    public static final String FIELD_OPTIONALLY_ENCLOSED_BY = "field_optionally_enclosed_by";
    public static final char DEFAULT_FIELD_OPTIONALL_ENCLOSED_BY = '\"';

    public static final String BINARY_FORMAT = "binary_format";
    public static final String DEFAULT_BINARY_FORMAT = BinaryFormat.HEXADECIMAL.toString();

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
    private final Integer maxRowsPerFile;
    // Compression type to use
    private final Compression compression;
    // S3 bucket to use. Only relevant when locationType is S3.
    private final String bucket;
    // S3 region to use. Only relevant when locationType is S3.
    private final String region;    
    // S3 endpoint to use. Only relevant when locationType is S3.
    private final String endpoint;    
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
    // Indicates whether path style access will be used for writing to S3.
    private final boolean pathStyleAccess;
    // Indicates whether multithreaded writing will be allowed.
    private final boolean multiThreadingAllowed;
    // Number of threads used for extracting if multiThreadingAllowed is set to true.
    private final int numExtractThreads;
    // Format string to use for writing NULL values to the output files.
    private final String nullFormat;
    // Encoding to use when writing out bytes.
    private final Charset encoding;
    // Character used to escape quotes.
    private final char escape;
    // Character used to enclose strings.
    private final char fieldOptionallyEnclosedBy;
    // The format with which to encode binary data.
    private final BinaryFormat binaryFormat;
    
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

    public Integer getMaxRowsPerFile()
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

    public String getRegion()
    {
        return region;
    }

    public String getEndpoint()
    {
        return endpoint;
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

    public boolean getPathStyleAccess()
    {
        return pathStyleAccess;
    }

    public boolean isMultiThreadingAllowed()
    {
        return multiThreadingAllowed;
    }

    public int getNumExtractThreads()
    {
        return numExtractThreads;
    }

    public String getNullFormat()
    {
        return nullFormat;
    }

    public Charset getEncoding()
    {
        return encoding;
    }
    
    public char getEscape()
    {
        return escape;
    }

    public char getFieldOptionallyEnclosedBy()
    {
        return fieldOptionallyEnclosedBy;
    }
            
    public BinaryFormat getBinaryFormat()
    {
        return binaryFormat;
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
        if(maxRowsPerFile != null && maxRowsPerFile <= 0)
        {
            throw new ParseException(String.format("A non negative number is necessary for max rows per file. Specified: %d.", maxRowsPerFile));
        }
        if(locationType == LocationType.S3 && (bucket == null || endpoint == null))
        {
            throw new ParseException("When using S3, bucket and endpoint must be specified");
        }
        if((!awsKeyId.equals("") && awsKeySecret.equals("")) || awsKeyId.equals("") && !awsKeySecret.equals("")){
            throw new ParseException("When specifying either aws_key_id or aws_secret_key, both must be specified");
        }
        if(multiThreadingAllowed && numExtractThreads <= 1){
            throw new ParseException("Multithreading is enabled but the number of threads is set to 1 or less. Either disable multithreaded extract or increase the number of threads");
        }
        if(locationType != LocationType.S3 && bucket != null)
        {
            System.out.println(String.format("Location type was not S3 (was %s) and a bucket (%s) was specified. Bucket will be ignored.", locationType.name(), bucket));
        }
    }
}
