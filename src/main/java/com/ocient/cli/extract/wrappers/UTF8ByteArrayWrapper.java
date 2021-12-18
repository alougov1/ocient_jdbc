package com.ocient.cli.extract.wrappers;

import java.nio.charset.StandardCharsets;

public class UTF8ByteArrayWrapper implements ByteArrayWrapper{
    
    final private byte[] byteArray;

    public UTF8ByteArrayWrapper(final byte[] byteArray){
        this.byteArray = byteArray;
    }

    @Override
    public String toString(){
        return new String(byteArray, StandardCharsets.UTF_8);
    }    
}
