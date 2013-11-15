package org.mitre.node_rpc.requests;

import org.mitre.node_rpc.RequestMessage;


/**
 * Tells the java program that it is done and can end.
 */
public class Goodbye extends RequestMessage {
    
    @Override
    public void process() {
    }

}