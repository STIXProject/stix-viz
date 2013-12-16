/*
 * Copyright (c) 2013 – The MITRE Corporation
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

import org.mitre.node_rpc.NodeRpc;
import org.mitre.node_rpc.ResponseMessage;

/**
 * This message is sent out as soon as the java app is started. It informs the
 * client of the version and helps the client verify that it is indeed
 * talking to the expected host.
 */
public class Hello extends ResponseMessage
{
    private String appName = NodeRpc.class.getSimpleName();
    private String version = NodeRpc.APP_VERSION;
}