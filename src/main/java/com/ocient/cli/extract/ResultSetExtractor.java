package com.ocient.cli.extract;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;

import com.ocient.cli.extract.wrappers.ByteArrayWrapperFactory;
import com.univocity.parsers.csv.CsvWriter;

/*!
 * The ResultSetExtractor will be responsible for taking a result set and its metadata, iterating the result set,
 * and passing records to the RecordExtractor. During this iteration, it will apply the MAX_ROWS_PER_FILE config, 
 * flush the previous file, and start with a new one.
 */
public class ResultSetExtractor{

    public ResultSetExtractor(final ExtractConfiguration config){
        extractConfig = config;
        recordExtractorFactory = new RecordExtractorFactory(config);
    }

    // Extract the result set given its metadata and desired ExtractConfiguration.
    public void extract(final ResultSet resultSet, final ResultSetMetaData resultSetMetaData) throws IllegalStateException, IOException, SQLException{

        final int colCount = resultSetMetaData.getColumnCount();
        // Grab the headers
        final ArrayList<String> headers = new ArrayList<String>(colCount);
        // Note that the columns of resultSetMetadata is 1 indexed.
        for(int i = 1; i <= colCount; ++i){
            headers.add(resultSetMetaData.getColumnName(i));
        }
        // The file count indexer. For File naming.
        int fileIndex = 0; 
        Integer maxRowsPerFile = extractConfig.getMaxRowsPerFile();
        // We want to create 1 file even if the result set is empty.
        CsvWriter currentWriter = startNewWriter(fileIndex++, headers);
        int currentRowInFile = 0;
        try{
            // next() can throw SQLException
            while (resultSet.next()){
                // The next call to getRow() will return a new row.
                // This way, if the last row fits into the last line allowed by a file, then a new file will NOT be made.
                if(maxRowsPerFile != null && currentRowInFile == maxRowsPerFile){
                    // Hit the max on this current file. Create a new one.
                    currentWriter.close();
                    currentWriter = startNewWriter(fileIndex++, headers);
                    // Reset the current row count.
                    currentRowInFile = 0;
                }
                // Get the result row and write it. getRow() can throw SQLException.
                Object[] row = getRow(resultSet, colCount);
                currentWriter.writeRow(row);
                currentRowInFile++;
            }
        } catch (SQLException ex) {
            currentWriter.close();
            throw ex;
        }
        currentWriter.close();
    }

    // Helper function which takes the steps in starting a new file.
    private CsvWriter startNewWriter(int fileIndex, final ArrayList<String> headers) throws IOException {
        CsvWriter newWriter = recordExtractorFactory.create(fileIndex);
        // Write header to the first file if necessary.
        if(!extractConfig.getSkipHeader()){
            newWriter.writeHeaders(headers);
        }
        return newWriter;
    }

    /*!
     * Get row retrieves the next row to be written. It assumes that next() has already been called
     * on the resultSet and that it returned true.
     */
    private Object[] getRow(final ResultSet resultSet, int colCount) throws SQLException{
        final Object[] rowElements = new Object[colCount];
        // Rows are 1 indexed.
        for(int i = 1; i <= colCount; i++){
            Object element = resultSet.getObject(i);
            if(resultSet.wasNull()){
                element = extractConfig.getNullFormat();
            } else if (element instanceof byte[]){
                element = ByteArrayWrapperFactory.getWrapper((byte[]) element, extractConfig.getBinaryFormat());                
            }
            rowElements[i - 1] = element;
        }
        return rowElements;
    }

    private final RecordExtractorFactory recordExtractorFactory;
    private final ExtractConfiguration extractConfig;
}