package com.ocient.cli.extract.wrappers;

import java.nio.charset.Charset;
import org.apache.commons.codec.binary.Base64;

public class Base64ByteArrayWrapper implements ByteArrayWrapper{

    final private byte[] byteArray;

    public Base64ByteArrayWrapper(final byte[] byteArray){
        this.byteArray = byteArray;
    }

    @Override
    public String toString(){
        return new String(Base64.encodeBase64(byteArray), Charset.defaultCharset());
    }
}
