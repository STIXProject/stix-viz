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

package org.mitre.node_rpc;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class is a helper for outputting response messages as JSON text to the
 * client over standard send.
 */
public class ResponseMessage extends Message {

    /**
     * An internal wrapper around standard send so that we can pump our JSON
     * messages out over it.
     */
    private static DataOutputStream _out = new DataOutputStream(System.out);
    

    /**
     * Use GSON to convert the message into a JSON string and then send the
     * 32-bit length of the string bytes followed by the bytes.
     */
    public void send() {
        try {
            String message = _gson.toJson(this);
            byte[] bytes = message.getBytes("UTF-8");
            int length = bytes.length;

            _out.writeInt(length);
            _out.write(bytes);
            
        } catch (IOException ex) {
            Logger.getLogger(ResponseMessage.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
