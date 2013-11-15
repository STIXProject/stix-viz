package org.mitre.node_rpc.requests;

import org.mitre.node_rpc.NodeRpc;
import org.mitre.node_rpc.RequestMessage;
import org.mitre.node_rpc.ResponseMessage;
import org.mitre.node_rpc.responses.Error;
import org.mitre.node_rpc.responses.Info;

/**
 * A friendly hello from the client. We'll either reject with an error message
 * or accept with an Info message response.
 */
public class Hello extends RequestMessage {

    private String version;
    
    @Override
    public void process() {
        ResponseMessage response;
        if(!NodeRpc.APP_VERSION.equals(version)) {
            response = new Error(new Exception("Client does not match expected version " + NodeRpc.APP_VERSION));
        } else {
            response = new Info("Ready to receive requests.");
        }
        
        response.send();
    }
    
}
