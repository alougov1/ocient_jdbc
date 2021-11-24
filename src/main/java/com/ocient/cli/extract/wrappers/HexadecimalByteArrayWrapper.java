package com.ocient.cli.extract.wrappers;

import com.ocient.jdbc.XGByteArrayHelper;

public class HexadecimalByteArrayWrapper implements ByteArrayWrapper{
    final private byte[] byteArray;

    public HexadecimalByteArrayWrapper(final byte[] byteArray){
        this.byteArray = byteArray;
    }

    @Override
    public String toString(){
        return  "0x" + XGByteArrayHelper.bytesToHex(byteArray);
    }        
}
