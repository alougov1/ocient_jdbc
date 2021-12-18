package com.ocient.cli.extract;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;

import java.io.IOException;

import org.apache.commons.lang3.RandomUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

@RunWith(JUnitParamsRunner.class)
public class S3OutputStreamTest {
    private S3Client S3_CLIENT;
    private String BUCKET;
    private String KEY;
    private String UPLOAD_ID;
    private String ETAG;
    private S3OutputStream OUTPUT_STREAM;

    private CreateMultipartUploadRequest CREATE_REQUEST;
    private CreateMultipartUploadResponse CREATE_RESPONSE;

    private UploadPartResponse UPLOAD_RESPONSE;

    @Before
    public void beforeTest(){
        S3_CLIENT = mock(S3Client.class);
        BUCKET = "fakeBucket";
        KEY = "fakeKey";
        UPLOAD_ID = "faleUploadID";
        ETAG = "fakeEtag";

        CREATE_REQUEST = CreateMultipartUploadRequest.builder().bucket(BUCKET).key(KEY).build();
        CREATE_RESPONSE = CreateMultipartUploadResponse.builder().uploadId(UPLOAD_ID).build();

        UPLOAD_RESPONSE = UploadPartResponse.builder().eTag(ETAG).build();
        // When a create request is made, it should return a create reesponse
        when(S3_CLIENT.createMultipartUpload(eq(CREATE_REQUEST))).thenReturn(CREATE_RESPONSE);
        // When an upload request is made, it should return an upload response
        when(S3_CLIENT.uploadPart(any(UploadPartRequest.class), any(RequestBody.class))).thenReturn(UPLOAD_RESPONSE);
        // Now construct the output stream.
        try {
            OUTPUT_STREAM = new S3OutputStream(S3_CLIENT, BUCKET, KEY);
        } catch (IOException e) {
            fail();
        }
    }

    // Utility function for generating a byte array of given length with random data.
    private byte[] randomData(int arrayLen){
        byte[] byteArray = RandomUtils.nextBytes(arrayLen);
        return byteArray;
    }

    @Test
    public void sentCreateRequest(){
        // Create request should always be called once. It should have already been called 
        verify(S3_CLIENT, times(1)).createMultipartUpload(eq(CREATE_REQUEST));
    }

    // Test that multiplies the buffer size by a factor and then writes that many bytes to the stream.
    // Then we can control how many times uploadParts is called internally by the S3OutputStream.
    @Test
    @Parameters({
        "0.5, 0",
        "1.1, 1",
        "1.5, 1",
        "2.1, 2",
        "9.9, 9",
    })
    public void expectedUploads(float factor, int expectedTimesCalled) throws IOException{
        // Just don't do anything crazy with the factor and this should suffice for this test.
        int numberOfBytes = Math.round(S3OutputStream.DEFAULT_BUFFER_SIZE * factor);
        OUTPUT_STREAM.write(randomData(numberOfBytes));
        // Verify uploadParts was called the correct number of times.
        verify(S3_CLIENT, times(expectedTimesCalled)).uploadPart(any(UploadPartRequest.class), any(RequestBody.class));
        
    }

    // Tests that close will upload when appropriate.
    @Test
    public void uploadOnClose() throws IOException{
        // This number of bytes will cause an upload part, but then a second one when closed.
        OUTPUT_STREAM.write(randomData(S3OutputStream.DEFAULT_BUFFER_SIZE + 10));
        verify(S3_CLIENT, times(1)).uploadPart(any(UploadPartRequest.class), any(RequestBody.class));
        OUTPUT_STREAM.close();
        // A close should have caused another upload.
        verify(S3_CLIENT, times(2)).uploadPart(any(UploadPartRequest.class), any(RequestBody.class));
    }

    // Tests that the complete message is sent once closing.
    @Test
    public void completeOnClose() throws IOException{
        OUTPUT_STREAM.write(randomData(S3OutputStream.DEFAULT_BUFFER_SIZE - 1));
        // Now close, which should trigger a complete.
        OUTPUT_STREAM.close();
        verify(S3_CLIENT, times(1)).completeMultipartUpload(any(CompleteMultipartUploadRequest.class));
    }

    @Test(expected = IllegalStateException.class)
    public void writeOnClosedThrows() throws IllegalStateException, IOException{
        OUTPUT_STREAM.close();
        OUTPUT_STREAM.write(randomData(10));
    }

    // Writing ints should only result in single bytes being written.
    @Test
    public void writeInt() throws IOException{
        OUTPUT_STREAM.write(randomData(S3OutputStream.DEFAULT_BUFFER_SIZE - 1));
        // There is enough room for 1 more byte.
        OUTPUT_STREAM.write(0);
        // Should not have uploaded yet. We are full though.
        verify(S3_CLIENT, times(0)).uploadPart(any(UploadPartRequest.class), any(RequestBody.class));
        // Write one more byte.
        OUTPUT_STREAM.write(0);
        verify(S3_CLIENT, times(1)).uploadPart(any(UploadPartRequest.class), any(RequestBody.class));
    }

}
