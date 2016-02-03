package ch.joebar.qos.log.qssign;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.OutputStream;

public class SigningOutputStreamWriter extends OutputStreamWriter {

    public SigningOutputStreamWriter(OutputStream out, String enc) throws IOException {
	super(out, enc);
    }
    
    @Override
    public void write(String value) throws IOException {
	super.write(value);
    }

    //public void close() throws IOException {
    //	super.close();
    //}
}
