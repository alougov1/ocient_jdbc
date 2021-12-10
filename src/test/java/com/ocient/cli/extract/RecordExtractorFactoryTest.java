package com.ocient.cli.extract;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

import com.ocient.jdbc.XGConnection;
import com.ocient.jdbc.XGResultSet;
import com.ocient.jdbc.XGResultSetMetaData;
import com.univocity.parsers.csv.CsvParser;
import com.univocity.parsers.csv.CsvParserSettings;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;

@RunWith(JUnitParamsRunner.class)
public class RecordExtractorFactoryTest {

    private Properties properties = null;
    private File workingDirectory = new File(Paths.get(".").toAbsolutePath().normalize().toString());
    private static final Logger LOGGER = Logger.getLogger("com.ocient.cli.extract.test");

    private static int DEFAULT_ROWS_IN_RS = 100;

    // Temporary folder to which we write our result files.
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder(workingDirectory);
    
    @Before
    public void beforeTest(){
        // Set up the properties for each test. They will all at least use location_type = "local" for now.
        properties = new Properties();
        properties.setProperty("location_type", "local");
        // Set up file_prefix to write the results to a proper place within our temporary folder.
        String filePrefix = testFolder.getRoot() + "/result";
        properties.setProperty("file_prefix", filePrefix);
    }

    @After
    public void aftertest(){
        // Delete the files in this folder in preparation for the next test.
        try {
            FileUtils.cleanDirectory(testFolder.getRoot());
        } catch (Exception ex){
            LOGGER.log(Level.WARNING, "Failed to clear test directory after test");
            fail(ex.getMessage());
        }

    }

    @Test
    @Parameters({
        "file_type, delimited",
        "file_extension, .tsv",
        "file_extension, .csv",
        "comression, none",
        "compression, gzip",
        "record_delimiter, .",
        "record_delimiter, \\|",
        "recored_delimiter, &",
        "field_delimiter, \\t",
        "field_delimiter, \\n",
        "field_delimiter, xD",
        "skip_header, true",
        "skip_header, false",
        "null_format, NULL",
        "null_format, NONE",
        "null_format, \" \"",
        "encoding, UTF-8",
        "encoding, UTF-16BE",
        "encoding, UTF-16LE",
        "encoding, UTF-16",
        "encoding, US-ASCII",
        "encoding, ISO-8859-1",
        "escape, \\", // Use backslash to escape
        "escape, +",
        "escape, \"",
        "field_optionally_enclosed_by, \'",
        "field_optionally_enclosed_by, \"",
        "binary_format, UTF8",
        "binary_format, HEXADECIMAL",
        "binary_format, BASE64"
    }) // These parameters are tested one at a time. Separately.
    public void variousExtracts(String configKey, String configValue){
        // Set the property we are testing.
        properties.setProperty(configKey, configValue);
        ExtractConfiguration config = new ExtractConfiguration(properties);
        // Manufacture our fake result set.
        XGResultSet rs = makeFakeResultSet(DEFAULT_ROWS_IN_RS);
        XGResultSetMetaData rsMetaData = makeFakeMetaData();
        rs.setCols2Pos(rsMetaData.getCols2Pos());
        rs.setPos2Cols(rsMetaData.getPos2Cols());
        rs.setCols2Types(rsMetaData.getCols2Types());
        // Extract
        extractResultSet(config, rs, rsMetaData);

        // There should only be 1 file.
        int numFilesProduced = testFolder.getRoot().listFiles().length;
        assertEquals(numFilesProduced, 1);
        String fileName = resolveFileNames(config, 0, 0);
        validateFile(config, fileName, DEFAULT_ROWS_IN_RS, getNumColsFromMeta(rsMetaData));

    }

    // Test which tries various row number and max rows combinations. Tests that the correct number of files are produced.
    @Test
    @Parameters({
        "0, 100",
        "1, 100",
        "100, 10",
        "101, 10",
        "17, 2",
        "18, 2",
        "19, 2",
        "100000, 50000"
    })
    public void maxRowCombinations(int numRowsInRs, int maxRowsPerFile){
        // Set up the max row parameter.
        properties.setProperty("max_rows_per_file", String.valueOf(maxRowsPerFile));
        ExtractConfiguration config = new ExtractConfiguration(properties);
        // Manufacture our fake result set.
        XGResultSet rs = makeFakeResultSet(numRowsInRs);
        XGResultSetMetaData rsMetaData = makeFakeMetaData();
        rs.setCols2Pos(rsMetaData.getCols2Pos());
        rs.setPos2Cols(rsMetaData.getPos2Cols());
        rs.setCols2Types(rsMetaData.getCols2Types());
        // Extract
        extractResultSet(config, rs, rsMetaData);

        int numFilesProduced = testFolder.getRoot().listFiles().length;
        // At least 1 file needs to be produced, even if the result set is empty.
        // If the result set is non empty, then the number of files produced is ceil(rows / maxRowsPerFile)
        int expectedNumber = Math.max((int) Math.ceil((double)numRowsInRs / maxRowsPerFile), 1);
        assertEquals(expectedNumber, numFilesProduced);
    }

    // Test for multi threaded extract. Tries various combinations of number of rows,
    // threads, and max rows settings.
    // Ensures that each file is created and each file has the correct number of rows.
    @Test
    @Parameters({
        "100, 10, 2",
        "1700, 4, 56",
        "0, 1, 17",
        "97, 5, 12",
        "1,1,1",
        "1000, 4, 50",
        "1000, 23, 18",
        "12, 5, 6",
        "20, 7, 3"
    })
    public void multiThreadedExtract(int numRows, int numThreads, int maxRows) throws SQLException, InterruptedException {
        properties.setProperty("allow_multithreading", "true");
        properties.setProperty("max_rows_per_file", String.valueOf(maxRows));
        // Make config
        ExtractConfiguration config = new ExtractConfiguration(properties);
        // Make a mock result set
        XGResultSet rs = makeFakeMockResultSet(numRows, numThreads);
        XGResultSetMetaData rsMetaData = makeFakeMetaData();
        
        rs.setCols2Pos(rsMetaData.getCols2Pos());
        rs.setPos2Cols(rsMetaData.getPos2Cols());
        rs.setCols2Types(rsMetaData.getCols2Types());
        // Extract
        extractResultSet(config, rs, rsMetaData);

        int numCols = getNumColsFromMeta(rsMetaData);
        for(int threadNumber = 0; threadNumber < numThreads; ++threadNumber){

            int remainderForThreads = numRows % numThreads;
            int rowsForThisThread = (remainderForThreads > threadNumber) ? (numRows / numThreads) + 1 : (numRows / numThreads);
            int numFilesForThisThread = Math.max((int) Math.ceil((double) rowsForThisThread / maxRows), 1);

            for(int fileNumber = 0; fileNumber < numFilesForThisThread; fileNumber++){
                String fileName = resolveFileNames(config, fileNumber, threadNumber);
                int remainderForFile = rowsForThisThread % maxRows;
                int rowsForThisFile = 0;
                if(remainderForFile == 0){
                    // If this is an even distribution of rows, then each file will have max rows. Unless it was 0 rows to begin with.
                    rowsForThisFile = (rowsForThisThread == 0) ? 0 : maxRows;
                } else {
                    // Is this the last file? if it is, then it will have the remainder. Otherwise it will have maxrows number of files.
                    rowsForThisFile = (fileNumber == numFilesForThisThread - 1) ? remainderForFile : maxRows;
                }
                validateFile(config, fileName, rowsForThisFile, numCols);
            }
        }
    }

    private void extractResultSet(ExtractConfiguration config, XGResultSet resultSet, XGResultSetMetaData rsMetaData){

        ResultSetExtractor rsExtractor = null;
        if(config.isMultiThreadingAllowed()){
            rsExtractor = new MultiThreadedResultSetExtractor(config);
        } else {
            rsExtractor = new SingleThreadedResultSetExtractor(config);
        }
        try {
            rsExtractor.extract(resultSet, rsMetaData);
        } catch (final SQLException | IOException ex) {
            LOGGER.log(Level.WARNING, "Failed extract result set");
            fail(ex.getMessage());
        }        
    }

    // Utility to verify that we can read the file after we've written it.
    private void validateFile(ExtractConfiguration extractConfig, String fileName, int expectedRows, int expectedCols){

        String fileToRead = fileName;
        // If file is compressed, we need to decompress first.
        if(extractConfig.getCompression() == ExtractConfiguration.Compression.GZIP){
            fileToRead = decompressGzip(fileName);
        }

        // Set the reader settings.
        CsvParserSettings settings = new CsvParserSettings();
        settings.getFormat().setDelimiter(extractConfig.getFieldDelimiter());
        settings.getFormat().setLineSeparator(extractConfig.getRecordDelimiter());
        settings.getFormat().setQuote(extractConfig.getFieldOptionallyEnclosedBy());
        settings.getFormat().setQuoteEscape(extractConfig.getEscape());

        Reader inputReader = null;
        try {
            inputReader = new InputStreamReader(new FileInputStream(new File(fileToRead)), extractConfig.getEncoding());
        } catch (FileNotFoundException ex) {
            LOGGER.log(Level.WARNING, String.format("Failed to find file: %s", fileToRead));
            fail(ex.getMessage());
        }        

        // creates a CSV parser
        CsvParser parser = new CsvParser(settings);
        parser.parse(new File(fileToRead));
        // Read the rows
        List<String[]> parsedRows = parser.parseAll(inputReader);
        // Assert the correct number of rows and columns.
        assertEquals((extractConfig.getSkipHeader()) ? expectedRows : expectedRows + 1 , parsedRows.size());        
        for(String[] row: parsedRows){
            assertEquals(expectedCols, row.length);
        }
    }

    // Utility for making a fake result set.
    // Schema is char, int, int, char, binary. The fourth column will be all nulls
    private XGResultSet makeFakeResultSet(int numRows){

        final ArrayList<Object> rows = new ArrayList<>();
        for (int i = 0; i < numRows; ++i){
            final ArrayList<Object> row = new ArrayList<>();
            // Just some random values.
            row.add(String.valueOf(i + 1));
            row.add(i);
            row.add(i + 5);
            row.add(null);
            row.add(new String("row \" with \"\" . ,qu,otes and other , \\things")); // add a string with quotes and other characters.
            row.add("deadbeef".getBytes(Charset.defaultCharset())); // This tests the byte array wrapper.
            rows.add(row);
        }
        return new XGResultSet(makeFakeConnection(), rows, null);
    }

    // Utility for making a fake MOCK result set.
    // Each row will be exactly the same.
    private XGResultSet makeFakeMockResultSet(int numRows, int numThreads) throws SQLException{

        XGResultSet fakeMockResultSet = mock(XGResultSet.class);
        // For the first numRows times, this will return true. Then it will return false.
        when(fakeMockResultSet.next()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation){
                if(count++ == numRows){
                    return false;
                }
                return true;
            }
        });
        // Each cell will just be this string.
        when(fakeMockResultSet.getObject(anyInt())).thenReturn("TestString");
        // Have the result set return numThreads threads when asked.
        when(fakeMockResultSet.getNumClientThreads()).thenReturn(numThreads);
        return fakeMockResultSet;
    }

    // Utility function for generating some fake metadata.
    // We use this for our fake mock result set too, which actually has 5 columns of CHARS,
    // but that doesn't matter here because the extract tool doesn't actually use the types of the metadata.
    private XGResultSetMetaData makeFakeMetaData(){

        // These names are bad, but they follow the driver's current naming scheme.
		final Map<String, Integer> cols2Pos = new HashMap<>();
		final TreeMap<Integer, String> pos2Cols = new TreeMap<>();
		final Map<String, String> cols2Types = new HashMap<>();
                
        cols2Pos.put("col0", 0);
        cols2Pos.put("col1", 1);
        cols2Pos.put("col2", 2);
        cols2Pos.put("col3", 3);
        cols2Pos.put("col4", 4);
        pos2Cols.put(0, "col0");
        pos2Cols.put(1, "col1");
        pos2Cols.put(2, "col2");
        pos2Cols.put(3, "col3");
        pos2Cols.put(4, "col4");
        cols2Types.put("col0", "CHAR");
        cols2Types.put("col1", "INT");
        cols2Types.put("col2", "INT");
        cols2Types.put("col3", "CHAR");
        cols2Types.put("col4", "CHAR");
        cols2Types.put("col4", "BINARY");

        return new XGResultSetMetaData(cols2Pos, pos2Cols, cols2Types);
    }

    // Utility function for generating a fake connection.
    // Necessary because result sets are constructed with a connection.
    // The arguments for the connection does not matter for our purposes.
    private XGConnection makeFakeConnection(){
        XGConnection conn = null;
        try {
            conn = new XGConnection(
                "fakeUser",
                "fakePassword",
                "fakeIp",
                0, // Fake port
                "fakeUrl",
                "fakeDatabase",
                "fakeProtocolVersion",
                "fakeClientVersion",
                "fakeForce",
                XGConnection.Tls.OFF,
                new Properties()
            );
        } catch (Exception ex){
            // Should never fail since we are making a fake connection. But this throws so we have to catch it.
            LOGGER.log(Level.WARNING, "Failed to make a fake connection");
            fail(ex.getMessage());
        }
        return conn;
    }

    // Utility function for decompressing zip files and returning their new names.
    // Used to test the compression option.
    // Courtesy of https://mkyong.com/java/how-to-decompress-file-from-gzip-file/
    private String decompressGzip(String sourceFile){
        // The last part should be "gz"
        assertEquals(sourceFile.substring(sourceFile.length() - 2), "gz");
        // Cut away ".gz"
        String targetFile = sourceFile.substring(0, sourceFile.length() - 3);
        byte[] buffer = new byte[1024];
        int len = 0;        
        try{
            GZIPInputStream gzipInputStream = new GZIPInputStream(new FileInputStream(new File(sourceFile)));
            FileOutputStream fileOutputStream = new FileOutputStream(new File(targetFile));
            while ((len = gzipInputStream.read(buffer)) > 0) {
                fileOutputStream.write(buffer, 0, len);
            }            
        } catch (IOException ex){
            LOGGER.log(Level.WARNING, "Failed to unzip compressed file");
            fail(ex.getMessage());
        }
        return targetFile;
    }

    // A utility function for calculating the output file names
    private String resolveFileNames(ExtractConfiguration extractConfig, int fileNumber, int threadNumber){
        String newName = extractConfig.getFilePrefix();
        // For the purposes of these tests, if we are allowing multithreading that means we are multithreading.
        if(extractConfig.isMultiThreadingAllowed()){
            newName += String.valueOf(threadNumber) + "_";
        }
        newName += String.valueOf(fileNumber) + extractConfig.getFileExtension();
        return extractConfig.getCompression() == ExtractConfiguration.Compression.GZIP ? newName + ".gz" : newName;
    }

    private int getNumColsFromMeta(ResultSetMetaData rsMetaData){
        int rsNumCols = 0;
        try {
            rsNumCols = rsMetaData.getColumnCount();
        } catch (SQLException ex){
            // Should never happen since this is all fake.
            LOGGER.log(Level.WARNING, "Failed to get number of result set column");
            fail(ex.getMessage());
        }     
        return rsNumCols;        
    }
}
