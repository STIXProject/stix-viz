package org.mitre.node_rpc.test;

import com.google.gson.Gson;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Type;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;

import org.mitre.node_rpc.Message;
import org.mitre.node_rpc.RequestMessage;
import org.mitre.node_rpc.requests.Echo;
import org.mitre.node_rpc.requests.Goodbye;
import org.mitre.node_rpc.requests.ProcessXslt;
import org.mitre.node_rpc.responses.Hello;
import org.mitre.node_rpc.responses.Info;
import org.mitre.node_rpc.responses.XsltResponse;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 *
 * @author Texashammer
 */
public class SimpleTest {
    
    private static final ByteArrayOutputStream _outContent = new ByteArrayOutputStream();
    private static final Gson                  _gson       = new Gson();
    
    private static final HashMap<String, Type> _responseMessages;
    
    static {
        _responseMessages = new HashMap<>();
        _responseMessages.put(Error.class.getSimpleName(), Error.class);
        _responseMessages.put(Hello.class.getSimpleName(), Hello.class);
        _responseMessages.put(Info.class.getSimpleName(), Info.class);
        _responseMessages.put(XsltResponse.class.getSimpleName(), XsltResponse.class);
    }
    
    public SimpleTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        System.setOut(new PrintStream(_outContent));
    }
    
    @AfterClass
    public static void tearDownClass() {
        System.setOut(null);
        System.setErr(null);
    }
    
    @Before
    public void setUp() {
        // Clear any output still in the stdout buffer
        _outContent.reset();
    }
    
    @After
    public void tearDown() {
    }
    
    
    private static void sendToInput(String message)
    {
        byte[] jsonBytes = message.getBytes();
        
        // Stuff the byte array into a buffer with a 4-byte int at the front
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + jsonBytes.length);
        byteBuffer.putInt(jsonBytes.length);
        byteBuffer.put(jsonBytes);
        byteBuffer.rewind();
        
        // Convert that to the final byte array that we will feed to standard in
        jsonBytes = new byte[4 + jsonBytes.length];
        byteBuffer.get(jsonBytes);
        
        // Swap the stream being used for input by the RequestMessage processor
        RequestMessage.setInputStream(new DataInputStream((new ByteArrayInputStream(jsonBytes))));
    }
    
    private static Message[] readFromOutput()
    {
        Gson gson = new Gson();
        
        // We don't know how many messages are in the buffer until we parse it
        ArrayList<Message> messages = new ArrayList<>();
        
        // Get the standard out buffer bytes and wrap it so we can parse it
        byte[] bytes = _outContent.toByteArray();
        ByteBuffer byteBuf = ByteBuffer.wrap(bytes);
        
        // Messages are a lead by an int size and then string message
        for(int pos = 0, length = 0; pos < bytes.length; pos += length + 4) {
            length = byteBuf.getInt(pos);
            String json = new String(bytes, pos + 4, length);
            Message message = RequestMessage.jsonToMessage(json, _responseMessages);
            messages.add(message);
        }
        
        return messages.toArray((new Message[0]));
    }
    
    
    @Test
    public void testRequestHello() throws IOException {
        // Send the request
        sendToInput("{messageName:'Hello', version:'0.1'}");
        
        RequestMessage message = RequestMessage.fetchRequest();
        assertEquals(message.getClass(), org.mitre.node_rpc.requests.Hello.class);
        
        // process the hello request
        message.process();
        
        // Read the response(s)
        Message[] messages = readFromOutput();
        
        assertEquals(1, messages.length);
        assertEquals(messages[0].getClass(), Info.class);
    }
    
    
    @Test
    public void testXsltRequest() throws IOException  {
      sendToInput("{messageName:'ProcessXslt', index:0, xmlFilePath:'C:\\\\Users\\\\gertner\\\\git\\\\StixViz\\\\StixViz\\\\data\\\\fireeye_pivy_stix.xml', xsltFilePath:'c:\\\\Users\\\\gertner\\\\Documents\\\\GitHub\\\\stix-viz\\\\public\\\\xslt\\\\stix_to_html.xsl'}");
      RequestMessage message = RequestMessage.fetchRequest();
      assertEquals(message.getClass(), ProcessXslt.class);
      message.process();
      Message[] messages = readFromOutput();
      assertEquals(1,messages.length);
      assertEquals(messages[0].getClass(),XsltResponse.class);
    }
    
    @Test
    public void testBadRequestHello() throws IOException {
        // Send the request
        sendToInput("{messageName:'Hello', version:'0.0'}"); // invalid version
        
        RequestMessage message = RequestMessage.fetchRequest();
        assertEquals(message.getClass(), org.mitre.node_rpc.requests.Hello.class);
        
        // process the hello request
        message.process();
        
        // Read the response(s)
        Message[] messages = readFromOutput();
        
        assertEquals(1, messages.length);
        assertEquals(messages[0].getClass(), Error.class);
    }
    
    
    @Test
    public void testRequestGoodbye() throws IOException {
        sendToInput("{messageName:'Goodbye'}");
        
        RequestMessage message = RequestMessage.fetchRequest();
        assertEquals(message.getClass(), Goodbye.class);
    }
    
    
    @Test
    public void testEcho() throws IOException {
        String text = "This is the text I want echoed.";
        sendToInput("{messageName:'Echo', message:'" + text + "'}");
        
        RequestMessage message = RequestMessage.fetchRequest();
        assertEquals(message.getClass(), Echo.class);
        
        message.process();
        
        // Read the response(s)
        Message[] messages = readFromOutput();
        
        assertEquals(1, messages.length);
        assertEquals(messages[0].getClass(), Info.class);
        
        Info info = (Info)messages[0];
        assertEquals(text, info.getMessage());
    }
}
