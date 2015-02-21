/*
 * Copyright (c) 2015 – The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * A client that talks with a Java program which is emitting a simple JSON based 
 * RPC protocol. 
 * 
 * Adapted from https://github.com/bspotswood/java-gson-rpc-example
 * 
 * created 2013
 * gertner@mitre.org
 * lubar@mitre.org
 * 
 */

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
