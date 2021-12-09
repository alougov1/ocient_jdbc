package com.ocient.cli.extract;

import java.util.ArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.io.IOException;
import java.sql.ResultSet;

import com.ocient.jdbc.XGResultSet;
import com.univocity.parsers.csv.CsvWriter;

public class MultiThreadedResultSetExtractor extends ResultSetExtractor{

    // flag for signaling threads to join
    private final AtomicBoolean isFinishedAdding;
    // Result queues for each thread
    private ArrayList<LinkedBlockingQueue<Object[]>> resultQueues;
    // Writing threads
    private ArrayList<Thread> writerThreads;

    public MultiThreadedResultSetExtractor(final ExtractConfiguration config){
        super(config, true);
        isFinishedAdding = new AtomicBoolean(false);
        resultQueues = new ArrayList<LinkedBlockingQueue<Object[]>>();
        writerThreads = new ArrayList<>();
    }

    @Override
    public void extract(final ResultSet resultSet, final ResultSetMetaData resultSetMetaData) throws IllegalStateException, IOException, SQLException{

        int numClientThreads = ((XGResultSet) resultSet).getNumClientThreads();
        // Parse header for result set.
        parseHeader(resultSetMetaData);

        for(int i = 0; i < numClientThreads; i++){
            // Make a new queue for sending results
            LinkedBlockingQueue<Object[]> newQueue = new LinkedBlockingQueue<Object[]>();
            // Make the writing thread
            final Thread thread = new WriterThread(headers, i, newQueue);
            // Add the queue
            resultQueues.add(newQueue);
            // Start thread
            thread.start();
            writerThreads.add(thread);
        }

        int threadIndex = 0;
        try {
            while(resultSet.next()){
                Object[] row = getRow(resultSet, headers.size());
                try {
                    resultQueues.get(threadIndex).put(row);
                    // Increment thread index and loop back if necessary.
                    threadIndex = (threadIndex + 1) % numClientThreads;
                } catch (InterruptedException | NullPointerException ex) {
                    // Can't really happen. This is the main thread and won't be interrupted by us.
                    // And the object (row) is not null.
                    joinThreads();
                    printError(String.format("Main thread encountered error while enqueing with message: %s", ex.getMessage()));
                    return;
                }
            }
        } catch (SQLException ex){
            // Need to fail and cleanup.
            joinThreads();
            printError(String.format("Main thread encountered error while attempting to fetch row from result set with message: %s", ex.getMessage()));
            return;
        }
        // Join the threads.
        joinThreads();
    }

    private void joinThreads(){
        // Tell the threads that they should return.
        isFinishedAdding.set(true); 

        for(Thread thread: writerThreads){
            try{
                thread.join();            
            } catch (InterruptedException ex){
                // Shouldn't ever happen because this thread is the only one capable of interrupting these writer threads.
                printError(String.format("Joined thread was interrupted with message: %s", ex.getMessage()));
            }
        }   
    }

    // Implementation of writing threads
    private class WriterThread extends Thread{

        private final int threadNumber;
        // Queue from which we retrieve the rows we are responsible for writing
        private final LinkedBlockingQueue<Object[]> queue;
        
        public WriterThread(final ArrayList<String> headers, int threadNumber, LinkedBlockingQueue<Object[]> queue){
            this.threadNumber = threadNumber;
            this.queue = queue;
        }

        @Override
        public void run(){

            int fileIndex = 0;
            Integer maxRowsPerFile = extractConfig.getMaxRowsPerFile();
            try{
                CsvWriter currentWriter = startNewWriter(fileIndex++, threadNumber);
                int currentRowInFile = 0;

                while(true){
                    // Try for 1 second to get something.
                    Object[] row = queue.poll(1, TimeUnit.SECONDS);
                    if(row == null){
                        // We got a null, meaning nothing was popped from the queue.
                        // Is the main thread finished or has the main thread just not enqueue anything for us yet?
                        if(isFinishedAdding.get() == true){
                            // We have written everything we need! Or there was an error. Return
                            currentWriter.close();
                            return;
                        } else {
                            // We have not finished, the enqueueing thread just didn't add anything for us yet.
                            continue;
                        }
                    }
                    if(maxRowsPerFile != null && currentRowInFile == maxRowsPerFile){
                        // Hit the max on this current file. Create a new one.
                        currentWriter.close();
                        currentWriter = startNewWriter(fileIndex++, threadNumber);
                        // Reset the current row count.
                        currentRowInFile = 0;
                    }
                    currentWriter.writeRow(row);
                    currentRowInFile++;
                }
            } catch (IOException | InterruptedException ex){
                // Something happened when we were writing on this thread. Just stop and return
                printError(String.format("Thread %d failed to finish writing with message: %s", threadNumber, ex.getMessage()));
                return;
            }
        }
    }

    // Synchronized thread printing helper.
    private synchronized void printError(String message){
        System.out.println(message);
    }
}
