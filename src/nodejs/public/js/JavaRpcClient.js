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

/**
 * This module is an example of a client that will talk with a Java program
 * which is emitting a simple JSON based RPC protocol. The communication
 * protocol is a simple JSON string with a leading int that indicates the
 * string length. This is implemented in the Java example program by using
 * the Gson library to transcode messages. The client class
 *
 * @seealso http://www.hacksparrow.com/node-js-eventemitter-tutorial.html
 */

var util         = require('util');
var EventEmitter = require('events').EventEmitter;
var cp           = require('child_process');
var path	 = require('path');


/**
 * Expose the Java program functionality in a more convenient to work with
 * class module. In a non-example library, this might expose a lot more
 * useful functionality beyond just marshalling messages.
 */
var JavaRpcClient = function() {
    var _self          = this;

    // The child process object we get when we spawn the java process
    var _javaSpawn     = null;

    // buffer for receiving messages in part and piecing them together later
    var _receiveBuffer = null;


    // The location of java and the jar file - we're making these public because maybe
    // we want to change them in the user of this module.
    _self.javaPath  = './bin/java';
    _self.jarPath   = './dist/NodeRpc.jar';
    _self.verbose   = true;

    // list of events emitted - for informational purposes
    _self.events = [
        'spawn', 'message', 'exception', 'unknown', 'sent', 'java_error',

        // Response messages that then become events themselves
        'Error', 'Hello', 'Info', 'XsltResponse'
    ];


    /**
     * Attach our own event handler to reply to the hello message.
     * This is just a convenience part of the protocol so that clients don't have to do it.
     * Also connects if connection data was supplied.
     */
    _self.on('Hello', function(){
        _self.sendHello();
    });


    /**
     * Executes the java process to begin sending and receiving communication
     */
    _self.run = function() {
        // Invoke the process
        _javaSpawn = cp.spawn(_self.javaPath, ['-jar', _self.jarPath]);

        // Wire up events
        _javaSpawn.stdout.on('data', onData);
        _javaSpawn.stderr.on('data', onJavaError);
        _javaSpawn.on('exit', function(code){
            console.log("The java program exited with code " + code + ".");
            
            // 127 means that the program/command couldn't be found
            if(127 == code) {
                console.log( "It looks like you might need to add the path to "
                           + "java.exe to your environment variables or specify "
                           + "the full path to it in the javaPath variable.");
            }
            
            // 1 likely means that the JAR cannot be found
            if(1 == code) { 
                console.log( "Java was executed, but it seems like the .jar file "
                           + "cannot be found. You might need to build the java "
                           + "program if you have only checked out the source; "
                           + "otherwise, you may need to check the path to the "
                           + "jar in the node script.")
            }
        });

        // Emit our own event to indicate to others that we have spawned
        _self.emit('spawn', _javaSpawn);
    }


    // sends the hello request message
    _self.sendHello = function() {
        sendMessage({
            messageName : 'Hello',
            version     : '0.1'
        });
    }

    // sends a message that will be echoed back as an Info message
    _self.sendEcho = function(message) {
        sendMessage({
            messageName : "Echo",
            message     : message
        });
    }


    // sends a message telling the java app to exit
    _self.sendGoodbye = function() {
        sendMessage({
           "messageName" : "Goodbye"
        });
    }
    
    // send a request to process an XSLT transform
    _self.sendXsltRequest = function (index,xmlPath,xsltPath) { 
    	sendMessage({
    		"messageName" : "ProcessXslt",
    		"index" : index,
    		"xmlFilePath" : xmlPath,
    		"xsltFilePath" : xsltPath
    	});
    }


    /**
     * Sends a message object as a JSON encoded string to the java application for processing.
     */
    function sendMessage(msg) {
        // convert to json and prepare buffer
        var json      = JSON.stringify(msg);
        var byteLen   = Buffer.byteLength(json);
        var msgBuffer = new Buffer(4 + byteLen);

        // Write 4-byte length, followed by json, to buffer
        msgBuffer.writeUInt32BE(byteLen, 0);
        msgBuffer.write(json, 4, json.length, 'utf8');

        // send buffer to standard input on the java application
        _javaSpawn.stdin.write(msgBuffer);

        _self.emit('sent', msg);
    }


    /**
     * Receive data over standard input
     */
    function onData(data) {

        // Attach or extend receive buffer
        _receiveBuffer = (null == _receiveBuffer) ? data : Buffer.concat([_receiveBuffer, data]);

        // Pop all messages until the buffer is exhausted
        while(null != _receiveBuffer && _receiveBuffer.length > 3) {
            var size = _receiveBuffer.readInt32BE(0);

            // Early exit processing if we don't have enough data yet
            if((size + 4) > _receiveBuffer.length) {
                break;
            }

            // Pull out the message
            var json = _receiveBuffer.toString('utf8', 4, (size + 4));

            // Resize the receive buffer
            _receiveBuffer = ((size + 4) == _receiveBuffer.length) ? null : _receiveBuffer.slice((size + 4));

            // Parse the message as a JSON object
            try {
                var msgObj = JSON.parse(json);

                // emit the generic message received event
                _self.emit('message', msgObj);

                // emit an object-type specific event
                if((typeof msgObj.messageName) == 'undefined') {
                    _self.emit('unknown', msgObj);
                } else {
                    _self.emit(msgObj.messageName, msgObj);
                }
            }
            catch(ex) {
                _self.emit('exception', ex);
            }
        }
    }


    /**
     * Receive error output from the java process
     */
    function onJavaError(data)
    {
        _self.emit('java_error', data.toString());
    }

}

// Make our JavaRpcClient class an EventEmitter
util.inherits(JavaRpcClient, EventEmitter);

// export our class
module.exports = JavaRpcClient;