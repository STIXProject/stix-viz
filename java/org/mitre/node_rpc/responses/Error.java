package org.mitre.node_rpc.responses;

import org.mitre.node_rpc.ResponseMessage;

/**
 * This class is used to indicate an error occurred on a requested operation.
 * It returns the details based on an exception.
 */
public class Error extends ResponseMessage {
    private String              errorMessage;
    private String              errorType;
    private StackTraceElement[] stackTrace;

    public Error(Exception errorMessage) {
        this.errorMessage = errorMessage.getMessage();
        this.errorType    = errorMessage.getClass().getName();
        this.stackTrace   = errorMessage.getStackTrace();
    }    
    
}
