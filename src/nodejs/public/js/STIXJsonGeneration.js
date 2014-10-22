/*
 * Copyright (c) 2014 – The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * This file contains the functionality for determining relationships specified in the xml
 * files loaded.  The top level function is generateTreeJson(inputXMLFiles)
 * 
 * Json is created representing the nodes and links in the tree.   This is passed to 
 * displayTree(json) for display in STIXViz.
 * 
 */

var doc = null;
var jsonObj = {};
var jsonRelationshipObj = {"type": "top",
	       "name": "",
	       "children": []};
var jsonTimelineObj = {};

/** 
 * main function for creating JSON to be displayed in each of the 
 * views.  For the tree view, top level entities are gathered from each xml file
 * via the call to gatherRelationshipTopLevelObjs.
 * Then json nodes are created for each entity and bottom up references are added to the nodes
 * via the call to processTopLevelObjects.  Finally, the relationship json is put together
 * by createTreeJson.   The result is added to jsonObj, which contains json for all views 
 * and the callback function is called with jsonObj and the viewType currently selected.
 * 
 * Json for the views are gathered in a single Json obj
 * Callback is a function that takes a JSON obj as an argument
*/
function generateJsonForFiles(inputFiles, viewType, callback) {
	var relTopLevelObjects = null;
	var relTopLevelNodes = null;
	var timeTopLevelObjects = null;
	var killChainObjects = null;
	var killChainInfo = {};
	
	var relTopNodeName = $.map(inputFiles,function (f) {
		return f.name;
	}).join('\n');
	
	function readFile(file) {
	    var reader = new FileReader();
	    var deferred = $.Deferred();
	 
	    reader.onload = function(event) {
	    	
	        var xml = new DOMParser().parseFromString(this.result, "text/xml"); 

	        // global copy of xml to use for searching via xpFind
	        doc = xml;
	        
	        // gather top level objects from xml
	        relTopLevelObjects = gatherRelationshipTopLevelObjs(xml, relTopLevelObjects);
	        killChainObjects = gatherKillChainObjs(xml, killChainObjects);
	        timeTopLevelObjects = gatherTimelineTopLevelObjs(xml, timeTopLevelObjects);
	        
	        deferred.resolve();
	    };
	 
	    reader.onerror = function() {
	        deferred.reject(this);
	    };
	 
	    reader.readAsText(file);
	 
	    return deferred.promise();
	}
	
	// Create a deferred object for each input file
	var deferreds = $.map(inputFiles, function (f) {
		return readFile(f);
	});
	
	// When all of the files have been read, this will happen
	$.when.apply(null, deferreds)
		.then(
			function () {
                killChainInfo = processKillChainObjs(killChainObjects);
				
                // done collecting from files, start processing objects
				relTopLevelNodes = processTopLevelObjects(relTopLevelObjects, relTopLevelNodes);

				// create the json for the relationship views (tree and graph)
				jsonRelationshipObj = createRelationshipJson(jsonRelationshipObj, relTopLevelNodes, relTopNodeName, killChainInfo);
				jsonTimelineObj = createTimelineJson(timeTopLevelObjects);
				
				jsonObj["relationshipData"] = jsonRelationshipObj;
				jsonObj["timelineData"] = jsonTimelineObj;
				
				// displays Json to web page for debugging
				//$('#jsonOutput').text(JSON.stringify(jsonRelationshipObj, null, 2));  

				// Do something with the Json String
				callback(jsonObj, viewType);
		})
		.fail(function (f) { 
			console.log("Error reading input file: " + f.name);
		});
}
	