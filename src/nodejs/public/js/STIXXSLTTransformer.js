/*
 * Copyright (c) 2013 � The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 *
 * The STIXXSLTTransformer uses a simple Java RPC protocol to spawn requests
 * for the XSLT Transform to be performed by the Java library using Saxon HE. 
 * 
 * 
 * created 2013
 * gertner@mitre.org
 * lubar@mitre.org
 * 
 */

var client = require('./public/js/JavaRpcClient');


var instance = new client();


$(function () { 
	
	/** 
	 * Start the java RPC processor
	 */
	try {
		instance.run();
	} catch (error) {
		console.log("Error starting java process. Make sure java.exe is on your path if you would like to access the STIX to HTML transform.");
	}

});


	


instance.on('message', function(msg){
    console.log('Received a message...');
    //console.log(msg);
    console.log("");

});

instance.on('sent', function(msg){
    console.log('Sent a message...');
    //console.log(msg);
    console.log("");
});

instance.on('Error', function(msg){
    console.log("Oh no! An error was received!");
    console.log(msg.errorMessage);
    console.log(msg.stackTrace);
    console.log('');
    
    // The error was in processing a file so reduce the number of files we are waiting for by one. 
    working--;
    
});

instance.on('Hello', function(msg) {
    console.log("Look at that! The server says hi!");
    console.log(msg);
    console.log("");
});


instance.on('Info', function(msg){
    console.log("I received some special info ...");
    alert(msg.message);
    console.log(msg.message);
    console.log("");
});

instance.on('XsltResponse', function(msg) { 

	working--;
	
	console.log("Got XsltResponse for file " + xmlDocs[msg.index].name);
	console.log("");
	
	var el = $('<div></div>');
	el.html(msg.html);
	xmlDocs[msg.index].html = el;
	
});


