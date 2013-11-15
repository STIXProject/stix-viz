package org.mitre.node_rpc.responses;

import org.mitre.node_rpc.ResponseMessage;

/**
 * A simple informational response message
 */
public class Info extends ResponseMessage {
    private String message;

    public Info(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
    
}
