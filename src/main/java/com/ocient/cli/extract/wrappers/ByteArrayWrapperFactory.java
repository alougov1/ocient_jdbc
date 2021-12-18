package com.ocient.cli.extract.wrappers;

import com.ocient.cli.extract.ExtractConfiguration.BinaryFormat;

public class ByteArrayWrapperFactory {
    public static ByteArrayWrapper getWrapper(final byte[] byteArray, BinaryFormat binaryFormat) throws IllegalArgumentException{
        switch(binaryFormat){
            case BASE64:{
                return new Base64ByteArrayWrapper(byteArray);
            }
            case UTF8: {
                return new UTF8ByteArrayWrapper(byteArray);
            }
            case HEXADECIMAL:{
                return new HexadecimalByteArrayWrapper(byteArray);
            }
            default: {
                throw new IllegalArgumentException(String.format("Invalid binary format specified: %s", binaryFormat.toString()));
            }
        }
    }
}
