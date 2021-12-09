package com.ocient.cli.extract;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.util.zip.GZIPOutputStream;

import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;

import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;

/*!
 * The record extractor factory is responsible for creating RecordExtractors by layering the extraction stages 
 * together based on the supplied configuration. Each time a record extractor is created a file index will be supplied. 
 * This file index is used to create the file name for the extractor.
 */
public class RecordExtractorFactory {

    private ExtractConfiguration extractConfig;
    private boolean isMultiThreaded;    

    // Create the record extractor factory from the supplied config
    RecordExtractorFactory(ExtractConfiguration config, boolean isMultiThreaded){
        this.extractConfig = config;
        this.isMultiThreaded = isMultiThreaded;
    }

    // Create a record extractor for a single file of extraction.
    // The factory will use the fileIndex and supplied config to 
    // determine the name of the file. 
    // threadNumber is used only if this is a multiThreaded extract.
    CsvWriter create(int fileIndex, int threadNumber) throws IOException{

        // Calculate the name of the output file.
        String fileName = resolveFileName(fileIndex, threadNumber);

        // Construct our write pipeline. 
        // Todo: Extract phase 2. Handle writing to S3. This means using S3OutputStream instead of FileOutputStream
        OutputStream outputStream = null;
        try {
            if(extractConfig.getLocationType() == ExtractConfiguration.LocationType.S3){
                // S3
                outputStream = makeS3OutputStream(fileName);
            } else {
                // Local
                outputStream = new FileOutputStream(fileName);
            }
            // Add a compression component if necessary.
            if(extractConfig.getCompression() == ExtractConfiguration.Compression.GZIP){
                outputStream = new GZIPOutputStream(outputStream);
            }
        } catch (IOException ex){
            if(outputStream != null){
                tryCloseOutputStream(outputStream);
            }
            throw ex;
        }
        // Generate the output stream writer with the proper encoding.
        Writer writer = new OutputStreamWriter(outputStream, extractConfig.getEncoding());
        // If we are extracting locally, then add a buffered writer.
        if(extractConfig.getLocationType() == ExtractConfiguration.LocationType.LOCAL){
            writer = new BufferedWriter(writer);
        }

        // Apply appropriate settings to our file format.
        CsvWriterSettings settings = new CsvWriterSettings();
        CsvFormat format = settings.getFormat();
        // Delimiter between fields. Default: ','
        format.setDelimiter(extractConfig.getFieldDelimiter());
        // Delimiter between records. Default: '\n'
        format.setLineSeparator(extractConfig.getRecordDelimiter());
        // Set the quote character
        format.setQuote(extractConfig.getFieldOptionallyEnclosedBy());
        // Set the quote escape character.
        format.setQuoteEscape(extractConfig.getEscape());
        return new CsvWriter(writer, settings);
    }

    // Simple utility function to help resolve the file name.
    private String resolveFileName(int fileIndex, int threadNumber){

        String newFileName = extractConfig.getFilePrefix();
        if(isMultiThreaded){
            newFileName += String.valueOf(threadNumber) + "_";
        }
        newFileName += String.valueOf(fileIndex) + extractConfig.getFileExtension();
        // Either None or Gzip. Add ".gz" if necessary.
        return extractConfig.getCompression() == ExtractConfiguration.Compression.GZIP ? newFileName + ".gz" : newFileName;
    }

    // Tries to close an output stream in case of exception. Does not throw.
    private void tryCloseOutputStream(OutputStream outputStream){
        try{
            outputStream.close();
        } catch (IOException ex){
            System.out.println("Error: In handling exception, failed to close outputstream");
        }
    }

    private S3OutputStream makeS3OutputStream(final String fileName) throws IOException{

        AwsCredentialsProvider credentialProvider = resolveCredentials();
        // Build the client.
        try {
            S3Client s3Client = S3Client.builder().
            region(Region.of(extractConfig.getRegion()))
            .serviceConfiguration(
                S3Configuration.builder()
                    .pathStyleAccessEnabled(extractConfig.getPathStyleAccess())
                    .build())
            .endpointOverride(URI.create(extractConfig.getEndpoint()))
            .credentialsProvider(credentialProvider)
            .build();
            return new S3OutputStream(s3Client, extractConfig.getBucket(), fileName);
        } catch (IllegalArgumentException ex){
            // Illegal argument exception is thrown by URI.create.
            throw new IOException(ex.getMessage());
        }
    }

    // If credentials are specified by the user, then use those.
    // If not, then fall back to searching for credentials with default provider chain.
    // If no credentials are found, then fall back to using anonymous crendentials
    // https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/auth/AnonymousAWSCredentials.html
    private AwsCredentialsProvider resolveCredentials(){
        if(!extractConfig.getAwsKeyId().equals("")){
            // Extract configuration enforces that both of these are specified together.
            return StaticCredentialsProvider.create(AwsBasicCredentials.create(extractConfig.getAwsKeyId(), extractConfig.getAwsKeySecret()));
        }
        try{
            return DefaultCredentialsProvider.create();
        } catch (SdkClientException ex){
            // Failed to locate any credentials. Fall back to using anonymous
            return AnonymousCredentialsProvider.create();
        }
        
    }
}

