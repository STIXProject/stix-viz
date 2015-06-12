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