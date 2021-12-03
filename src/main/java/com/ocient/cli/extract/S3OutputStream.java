package com.ocient.cli.extract;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class S3OutputStream extends OutputStream{

    // Note according to https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html
    // Each part except the last part needs to be at least 5MB in size.
    // Default buffer size: 10MB.
    protected static final int DEFAULT_BUFFER_SIZE = 10000000;    
    // S3 bucket to use
    private final String bucket;
    // File path to upload to
    private final String filePath;
    // Buffer used for writing
    private final byte[] buffer;
    // The current position in the buffer
    private int bufferPosition;
    // Amazon S3 client. Used for uploading.
    private final S3Client s3Client;
    // Unique ID for this upload
    private String uploadId;
    // List of etags for parts that have been uploaded.
    private final List<CompletedPart> completedParts;
    // Indicates if this stream is still open.
    private boolean isOpen;

    /**
     * 
     * @param s3Client The AmazonS3 client. Created by the caller
     * @param bucket S3 bucket
     * @param filePath path within the bucket
     */
    public S3OutputStream(S3Client s3Client, final String bucket, final String filePath) throws IOException{
        this.s3Client = s3Client;
        this.bucket = bucket;
        this.filePath = filePath;
        this.buffer = new byte[DEFAULT_BUFFER_SIZE];
        this.bufferPosition = 0;
        this.completedParts = new ArrayList<>();
        this.isOpen = true;

        // Start the upload.
        try{
            CreateMultipartUploadResponse createResponse = s3Client.createMultipartUpload(
                                                                CreateMultipartUploadRequest.builder()
                                                                    .bucket(bucket)
                                                                    .key(filePath)
                                                                    .build()
                                                            );
            // Store the upload id. This is the id for the entire upload.
            this.uploadId = createResponse.uploadId();
        } catch (AwsServiceException | SdkClientException ex) {
            throw new IOException(ex.getMessage());
        }
    }

    // Write a byte array to the S3OutputStream
    @Override
    public void write(byte[] byteArray) throws IOException{
        write(byteArray, 0, byteArray.length);
    }

    // Write to the outputstream, buffering in the byteArray if necessary.
    @Override
    public void write(final byte[] byteArray, final int offset, final int length) throws IOException{
        assertOpen();
        int runningOffset = offset;
        int runningLength = length;
        int spaceRemaining = 0;
        while(runningLength > (spaceRemaining = buffer.length - bufferPosition)){
            // The number of bytes we need to write exceeds the space length in our buffer.
            // Flush and upload until this is not true.
            System.arraycopy(byteArray, runningOffset, buffer, bufferPosition, spaceRemaining);
            bufferPosition += spaceRemaining;
            // Upload the part.
            flushInternal();
            runningOffset += spaceRemaining;
            runningLength -= spaceRemaining;
        }
        // At this point, there is enough space to write the rest of the bytes.
        System.arraycopy(byteArray, runningOffset, buffer, bufferPosition, runningLength);
        bufferPosition += runningLength;
    }

    // According to the documentation: https://docs.oracle.com/javase/8/docs/api/java/io/OutputStream.html
    // this method only need to write the lowest 8 bits of this int. The rest are ignored.
    @Override
    public void write(int b) throws IOException{
        assertOpen();
        if(bufferPosition >= buffer.length){
            flushInternal();
        }
        buffer[bufferPosition++] = (byte) b;
    }

    // This method does nothing.
    @Override
    public synchronized void flush(){
        return;
    }

    // Flushes the output stream. This generates a new part.
    private synchronized void flushInternal() throws IOException{
        if(bufferPosition == 0){
            // Nothing to upload
            return;
        }
        // Now upload the part.
        uploadPart();
        // Reset the position.
        bufferPosition = 0;
    }

    // Upload a part and store the eTag.
    protected void uploadPart() throws IOException{
        try {
            UploadPartResponse uploadResponse = s3Client.uploadPart(UploadPartRequest.builder()
                                                    .bucket(bucket)
                                                    .key(filePath)
                                                    .uploadId(uploadId)
                                                    .partNumber(completedParts.size() + 1)
                                                    .build(), RequestBody.fromInputStream(new ByteArrayInputStream(buffer, 0, bufferPosition), bufferPosition));
            // Record this completed part.
            completedParts.add(CompletedPart.builder()
                            .partNumber(completedParts.size() + 1)
                            .eTag(uploadResponse.eTag())
                            .build());
        } catch (AwsServiceException | SdkClientException ex){
            throw new IOException(ex.getMessage());
        }
    }

    // Closes the output stream, flushing if necessary. It is necessary to make a complete upload request.
    @Override
    public void close() throws IOException{
        if(isOpen){
            isOpen = false;
            if(bufferPosition > 0){
                // Flush whatever is remaining.
                flushInternal();
            }
            // Complete the upload.
            CompletedMultipartUpload completedMultipartUpload = CompletedMultipartUpload.builder()
                                                                    .parts(completedParts)
                                                                    .build();
            try{
                s3Client.completeMultipartUpload(
                    CompleteMultipartUploadRequest.builder()
                        .bucket(bucket)
                        .key(filePath)
                        .uploadId(uploadId)
                        .multipartUpload(completedMultipartUpload)
                        .build()
                );
            } catch (AwsServiceException | SdkClientException ex){
                throw new IOException(ex.getMessage());
            }
        }
    }

    // Check if the stream is open.
    private void assertOpen() {
        if (!isOpen) {
            throw new IllegalStateException("S3OutputStream is closed");
        }
    }    

}
