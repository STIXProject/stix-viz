package org.mitre.node_rpc.requests;

import java.io.File;
import java.io.StringWriter;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.mitre.node_rpc.NodeRpc;
import org.mitre.node_rpc.RequestMessage;
import org.mitre.node_rpc.ResponseMessage;
import org.mitre.node_rpc.responses.Error;
import org.mitre.node_rpc.responses.Info;
import org.mitre.node_rpc.responses.XsltResponse;


/**
 * A friendly hello from the client. We'll either reject with an error message
 * or accept with an Info message response.
 */
public class ProcessXslt extends RequestMessage {

    private Integer index;
    private String xmlFilePath;
    private String xsltFilePath;
    
    
    static { 
      System.setProperty("javax.xml.transform.TransformerFactory",  "net.sf.saxon.TransformerFactoryImpl");    
    }
      
    @Override
    public void process() {
        ResponseMessage response = simpleTransform(index,xmlFilePath,xsltFilePath);

        response.send();
    }
    
    
    /** 
     * Simple transformation method. 
     * @param sourcePath - Absolute path to source xml file. 
     * @param xsltPath - Absolute path to xslt file. 
     */  
    public static ResponseMessage simpleTransform(Integer index,String sourcePath, String xsltPath) {
      
        TransformerFactory tFactory = TransformerFactory.newInstance();  
        try {  
            Transformer transformer =  
                tFactory.newTransformer(new StreamSource(new File(xsltPath)));  

            StringWriter writer = new StringWriter();
            
            transformer.transform(new StreamSource(new File(sourcePath)),  
                                  new StreamResult(writer));
            
            return new XsltResponse(index,writer.toString());
            
        } catch (Exception e) {  
            e.printStackTrace(); 
            return new Error(e);
        }  
    }  
  

}  
    
