package com.ocient.cli.extract;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.zip.GZIPOutputStream;

import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;

/*!
 * The record extractor factory is responsible for creating RecordExtractors by layering the extraction stages 
 * together based on the supplied configuration. Each time a record extractor is created a file index will be supplied. 
 * This file index is used to create the file name for the extractor.
 */
public class RecordExtractorFactory {
    // Create the record extractor factory from the supplied config
    RecordExtractorFactory(ExtractConfiguration config){
        extractConfig = config;
    }

    // Create a record extractor for a single file of extraction.
    // The factory will use the fileIndex and supplied config to 
    // determine the name of the file. 
    CsvWriter create(int fileIndex) throws IOException{

        // Calculate the name of the output file.
        String fileName = resolveFileName(fileIndex);

        // Construct our write pipeline. 
        // Todo: Extract phase 2. Handle writing to S3. This means using S3OutputStream instead of FileOutputStream
        OutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(fileName);
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
        OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream, Charset.defaultCharset());
        BufferedWriter bufferedWriter = new BufferedWriter(outputStreamWriter);

        // Apply appropriate settings to our file format.
        CsvWriterSettings settings = new CsvWriterSettings();
        CsvFormat format = settings.getFormat();
        // Delimiter between fields. Default: ','
        format.setDelimiter(extractConfig.getFieldDelimiter());
        // Delimiter between records. Default: '\n'
        format.setLineSeparator(extractConfig.getRecordDelimiter());

        return new CsvWriter(bufferedWriter, settings);
    }

    // Simple utility function to help resolve the file name.
    private String resolveFileName(int fileIndex){
        String newFileName = extractConfig.getFilePrefix() + String.valueOf(fileIndex) + extractConfig.getFileExtension();
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

    private ExtractConfiguration extractConfig;
}

