package com.ocient.cli.extract;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;

import com.ocient.cli.extract.wrappers.ByteArrayWrapperFactory;
import com.univocity.parsers.csv.CsvWriter;

public abstract class ResultSetExtractor {
    
    protected final RecordExtractorFactory recordExtractorFactory;
    protected final ExtractConfiguration extractConfig;
    protected final ArrayList<String> headers;

    ResultSetExtractor(final ExtractConfiguration config, boolean isMultiThreaded){
        extractConfig = config;
        recordExtractorFactory = new RecordExtractorFactory(config, isMultiThreaded);
        headers = new ArrayList<String>();
    }

    abstract public void extract(ResultSet resultSet, final ResultSetMetaData resultSetMetaData) throws IllegalStateException, IOException, SQLException;

    protected CsvWriter startNewWriter(int fileIndex) throws IOException{
        return startNewWriter(fileIndex, 0);
    }

    // Helper function which takes the steps in starting a new file.
    protected CsvWriter startNewWriter(int fileIndex, final int threadNumber) throws IOException {
        CsvWriter newWriter = recordExtractorFactory.create(fileIndex, threadNumber);
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
    protected Object[] getRow(final ResultSet resultSet, int colCount) throws SQLException{
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

    protected void parseHeader(final ResultSetMetaData resultSetMetaData) throws SQLException{
        final int colCount = resultSetMetaData.getColumnCount();
        // Note that the columns of resultSetMetadata is 1 indexed.
        for(int i = 1; i <= colCount; ++i){
            headers.add(resultSetMetaData.getColumnName(i));
        }
    }
}
