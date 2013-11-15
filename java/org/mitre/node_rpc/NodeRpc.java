package org.mitre.node_rpc;

import org.mitre.node_rpc.requests.Goodbye;
import org.mitre.node_rpc.responses.Hello;

import java.io.IOException;


/**
 * A simple RPC protocol to call Java from a node.js script. Adapted from 
 * https://github.com/bspotswood/java-gson-rpc-example. 
 * 
 * The node.js script sends a JSON encoded request object that is converted into a 
 * RequestMessage object. The RequestMessage processes the request and returns
 * any number of ResponseMessage objects, as necessary, to fulfill the request. 
 * 
 * Uses the Google Gson library to convert between JSON objects and native Java objects. 
 */

public class NodeRpc {

    public static final String APP_VERSION = "0.1";
    
    public static void main(String[] args) throws IOException {
        NodeRpc instance = new NodeRpc();

        instance.run();
    }

    private void run() throws IOException {
        // When started, we automatically send out a Hello message
        (new Hello()).send();

        // Now pump messages until we receive a Goodbye
        RequestMessage message;
        while ((message = RequestMessage.fetchRequest()) != null) {
            if (message instanceof Goodbye) {
                return;
            }
            
            message.process();
        }
    }
}
