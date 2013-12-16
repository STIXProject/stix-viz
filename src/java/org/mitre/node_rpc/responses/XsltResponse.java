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
 * This message is sent in response to a processXslt request
 */
public class XsltResponse extends ResponseMessage
{
    private Integer index;
    private String html;

    public XsltResponse (Integer index,String html) { 
      this.index = index;
      this.html = html;
    }
    
    public String getHtml() {
      return html;
    }

    public void setHtml(String html) {
      this.html = html;
    }

    public Integer getIndex() {
      return index;
    }

    public void setIndex(Integer index) {
      this.index = index;
    }
    
    
    
    
}