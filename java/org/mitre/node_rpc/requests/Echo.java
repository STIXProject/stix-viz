package org.mitre.node_rpc.requests;

import org.mitre.node_rpc.RequestMessage;
import org.mitre.node_rpc.responses.Info;

public class Echo extends RequestMessage {

    private String message;
    
    @Override
    public void process() {
        (new Info(message)).send();
    }
    
}
