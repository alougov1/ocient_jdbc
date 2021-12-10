package com.ocient.cli.extract;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;

import com.univocity.parsers.csv.CsvWriter;

/*!
 * The SingleThreadedResultSetExtractor will be responsible for taking a result set and its metadata, iterating the result set,
 * and passing records to the RecordExtractor. During this iteration, it will apply the MAX_ROWS_PER_FILE config, 
 * flush the previous file, and start with a new one.
 */
public class SingleThreadedResultSetExtractor extends ResultSetExtractor{

    public SingleThreadedResultSetExtractor(final ExtractConfiguration config){
        super(config, false);
    }

    // Extract the result set given its metadata and desired ExtractConfiguration.
    @Override
    public void extract(final ResultSet resultSet, final ResultSetMetaData resultSetMetaData) throws IllegalStateException, IOException, SQLException{
        // Parse header for result set.
        parseHeader(resultSetMetaData);
        // The file count indexer. For File naming.
        int fileIndex = 0; 
        Integer maxRowsPerFile = extractConfig.getMaxRowsPerFile();
        // We want to create 1 file even if the result set is empty.
        CsvWriter currentWriter = startNewWriter(fileIndex++);
        int currentRowInFile = 0;
        try{
            // next() can throw SQLException
            while (resultSet.next()){
                // The next call to getRow() will return a new row.
                // This way, if the last row fits into the last line allowed by a file, then a new file will NOT be made.
                if(maxRowsPerFile != null && currentRowInFile == maxRowsPerFile){
                    // Hit the max on this current file. Create a new one.
                    currentWriter.close();
                    currentWriter = startNewWriter(fileIndex++);
                    // Reset the current row count.
                    currentRowInFile = 0;
                }
                // Get the result row and write it. getRow() can throw SQLException.
                Object[] row = getRow(resultSet, headers.size());
                currentWriter.writeRow(row);
                currentRowInFile++;
            }
        } catch (SQLException ex) {
            currentWriter.close();
            throw ex;
        }
        currentWriter.close();
    }
}
