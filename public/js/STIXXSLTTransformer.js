var client = require('./public/js/JavaRpcClient');
var path = require('path');

var instance = new client();

var xmlDocs = {}, docIndex = 0;

var working = 0;

$(function () { 
	
	/** 
	 * Start the java RPC processor
	 */
	instance.run();

});

/**
 * Add an XML document to the list of documents included in the tree display and process the XSLT transform
 * for that document
 * @param f
 * @param xml
 */
function addXmlDoc (f) { 
	
	working++;
	var num = docIndex++;
	
	xmlDocs[num] = {name:f.name};
	
	xmlFilePath = f.path.replace(/\\/g,'\\\\\\\\');
	xslFilePath = path.resolve("public/xslt/stix_to_html.xsl").replace(/\\/g,'\\\\\\\\');
	
	instance.sendXsltRequest(num,xmlFilePath,xslFilePath);
	
	// Construct top level menu for displaying HTML view of XML files
	$('#xmlFileList').append('<li><a id="xmlFile-'+num+'" href="#">'+f.name+'</a></li>');

	$('#xmlFile-'+num).on("click", function () {
		doc = xmlDocs[$(this).attr("id").split("-")[1]];
		if (doc) { 
			showProcessing();
			var waitForXslt = setInterval(function () { // wait until xslt processing is complete
				if (working == 0) { 
					clearInterval(waitForXslt);
					endProcessing();
					showHtml(new XMLSerializer().serializeToString($(doc.html).find('#wrapper').get(0)));
				}
			}, 200);
		} else { 
			showHtml("<div id='wrapper'><h2>Could not convert XML file to HTML</h2></div>");
		}
		$('#htmlView').scrollTop(0);
    });
	
	
}


instance.on('message', function(msg){
    console.log('Received a message...');
    console.log(msg);
    console.log("");

});

instance.on('sent', function(msg){
    console.log('Sent a message...');
    console.log(msg);
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


