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