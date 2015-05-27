/*
 * Copyright (c) 2015, The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * This file contains utilities used to extract relationships from the xml files
 * being processed, and to create the Json tree representation.
 * 
 */

// set up namespace resolver for xpath searches
function vizNSResolver(prefix) {
    var nsMap =  {
    		'stix': 'http://stix.mitre.org/stix-1', 
    		'stixVocabs': 'http://stix.mitre.org/default_vocabularies-1', 
    		'stix-ciq': 'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1', 
    		'stixCommon': 'http://stix.mitre.org/common-1', 
    		'cybox': 'http://cybox.mitre.org/cybox-2', 
    		'cyboxCommon': 'http://cybox.mitre.org/common-2', 
    		'cyboxVocabs': 'http://cybox.mitre.org/default_vocabularies-2', 
    		'AddressObject': 'http://cybox.mitre.org/objects#AddressObject-2',
    		'FileObject': 'http://cybox.mitre.org/objects#FileObject-2',
    		'LinkObject': 'http://cybox.mitre.org/objects#LinkObject-1', 
    		'URIObject': 'http://cybox.mitre.org/objects#URIObject-2', 
    		'marking': 'http://data-marking.mitre.org/Marking-1',
    		'simpleMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1', 
    		'xal': 'urn:oasis:names:tc:ciq:xal:3', 
    		'xpil': 'urn:oasis:names:tc:ciq:xpil:3', 
    		'xnl': 'urn:oasis:names:tc:ciq:xnl:3',
    		'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    		'campaign': 'http://stix.mitre.org/Campaign-1', 
    		'coa': 'http://stix.mitre.org/CourseOfAction-1',
    		'et': 'http://stix.mitre.org/ExploitTarget-1',
    		'incident': 'http://stix.mitre.org/Incident-1',
    		'indicator': 'http://stix.mitre.org/Indicator-2', 
    		'report': 'http://stix.mitre.org/Report-1',
    		'threat-actor': 'http://stix.mitre.org/ThreatActor-1',
    		'ttp': 'http://stix.mitre.org/TTP-1' 
    	};
    return nsMap[prefix] || null;
}


//single node types
var STIXType = {
		'ca' : 'Campaign', 
		'coa' : 'Course_Of_Action',
		'et' : 'Exploit_Target',
		'incident' : 'Incident',
		'indi': 'Indicator',
		'obs' : 'Observable',
		'rpt' : 'Report',
		'ta' : 'Threat_Actor',
		'ttp' : 'TTP'
};

//  Same as STIXTypes, with 's' on the end
var STIXGroupings = {
	'ca' : 'Campaigns',
	'coa' : 'Course_Of_Actions',
	'et' : 'Exploit_Targets',
	'incident' : 'Incidents',
	'indi' : 'Indicators',
	'obs' : 'Observables',
	'rpt': 'Reports',
	'ta' : 'Threat_Actors',
	'ttp' : 'TTPs'
};

var entityRelationshipMap = {
		'Campaign' : ['Associated_Campaign', 'Attributed_Threat_Actor', 'Related_TTP', 'Related_Incident', 'Related_Indicator'],
		'Course_Of_Action' : ['Related_COA'],
		'Exploit_Target' : ['Potential_COA', 'Related_Exploit_Target'],
		'Incident' : ['COA_Requested', 'COA_Taken', 'Leveraged_TTP', 'Related_Incident', 'Related_Indicator', 'Related_Observable', 'Threat_Actor'],
		'Indicator' : ['Indicated_TTP', 'Observable', 'Related_Indicator', 'Suggested_COA'],
		'Observable' : [],
		'Report' : ['Observable','Indicator','TTP', 'Exploit_Target', 'Incident', 'Course_Of_Action', 'Campaign', 'Threat_Actor', 'Related_Report'], 	
		'Threat_Actor' : ['Associated_Actor', 'Associated_Campaign', 'Observed_TTP'],
		'TTP' : ['Attack_Pattern', 'Exploit_Target', 'Malware', 'Observable', 'Related_TTP', 'Tool', 'Victim_Targeting']
}

/**
 * Mapping from node type to sections headings in the HTML rendering
 */

var htmlSectionMap = { 
		"Threat_Actors":"Threat Actors",
		"TTPs":"TTPs",
		"Indicators":"Indicators",
		"Campaigns":"Campaigns",
		"Course_Of_Actions":"Courses of Action",
		"Incidents":"Incidents",
		"Exploit_Targets":"Exploit Targets",
		"Observables":"Observables",
		"Indicator-Sighting" :"Indicator Sighting",
		"Incident-First_Malicious_Action" :"Incident: First Malicious Action",
		"Incident-Initial_Compromise" :"Incident: Initial Compromise",
		"Incident-First_Data_Exfiltration" :"Incident: First Data Exfiltration",
		"Incident-Incident_Discovery" :"Incident: Incident Discovery",
		"Incident-Incident_Opened" :"Incident: Incident Opened",
		"Incident-Containment_Achieved" :"Incident: Containment Achieved",
		"Incident-Restoration_Achieved" :"Incident: Restoration Achieved",
		"Incident-Incident_Reported" :"Incident: Incident Reported",
		"Incident-Incident_Closed" :"Incident: Incident Closed",
		"Incident-COATaken" :"Incident: COATaken"
	};

/**
 * Mapping from node type to icon names to be used in the tree display
 */

var nodeTypeMap = {

		"Campaigns" : "campaign",
		"Campaign" : "campaign",
		"Course_Of_Action" : "course_of_action",
		"Course_Of_Actions" : "course_of_action",
		"Exploit" : "exploit_target",
		"Exploit_Target" : "exploit_target",
		"Exploit_Targets" :  "exploit_target",
		"Incident" : "incident",
		"Incidents" : "incident",
		"Indicator" : "indicator",
		"Indicators" : "indicator",
		"Indicator-Utility" : "indicator",
		"Indicator-Composite" : "indicator",
		"Indicator-Backdoor" : "indicator",
		"Indicator-Downloader" : "indicator",
		"Observable" : "observable",
		"Observables" : "observable",
		"AttackPattern" : "attack_patterns",
		"MalwareBehavior" : "malware",
		"Observable" : "observable",
		"Observable-ElectronicAddress" : "observable",
		"Observable-Email" : "observable",
		"Observable-IPRange" : "observable",
		"Observable-MD5" : "observable",
		"Observable-URI" : "observable",
		"Report" : "report",
		"Reports" : "report",
		"UsesTool" : "tool",
		"Tools" : "tool",
		"VictimTargeting" : "victim_targeting",
		"Threat_Actor" : "threat_actor",
		"Threat_Actors" : "threat_actor",
		"TTP" : "ttp",
		"TTPs" : "ttp",
		"top" : "report"
	};

var STIXPattern = {
		'ca' : './/stixCommon:Campaign', 
		'coa' : './/stixCommon:Course_Of_Action',
		'et' : './/stixCommon:Exploit_Target',
		'incident' : './/stixCommon:Incident',
		'indi': './/stixCommon:Indicator',
		'obs': './/stixCommon:Observable',
		'rpt' : './/stixCommon:Report',
		'ta' : './/stixCommon:Threat_Actor',
		'ttp' : './/stixCommon:TTP'	
};

// use xpath for searching to deal with default namespaces
// returns a list of objects found, or an empty list
function xpFind(path, startNode) {
    var newNodes = [];
    var xpathResult = doc.evaluate(path, startNode, vizNSResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
    for (var i=0; i< xpathResult.snapshotLength; i++) {
        newNodes.push(xpathResult.snapshotItem(i));
    }	
    return newNodes;
}

// search for a single object
// returns single object or null if not found
function xpFindSingle(path, startNode) {
    var descendants = xpFind(path, startNode);
    var singleDescendant = null;
    if (descendants.length == 1) {
        singleDescendant =  descendants[0];
    }
    return singleDescendant;
}

// returns value of idRef attribute, or empty string if not found
function getObjIdRefStr(obj) {
	var idRef = $(obj).attr('idref');
	if (typeof(idRef) != 'undefined') {
		return idRef;
	}
	else {
		return "";
	}
}

//returns value of id attribute, or empty string if not found
function getObjIdStr(obj) {
	var id = $(obj).attr('id');
	if (typeof(id) != 'undefined') {
		return id;
	}
	else {
		return "";
	}
}

// basic json object
function createNode(id, type, name, direction, relationship) {
	var json = {"type": type};
	if (id != null) {
		json["nodeId"] = id;
	}
	json["name"] = name;
	json["linkType"] = direction;	
	json["relationship"] = relationship;
	return json;	
}

// json object with linkType sibling
function createSiblingNode(id, type, name, relationship) {
	return createNode(id, type, name, "sibling", relationship);	
}

// json object with linkType topDown
function createTopDownNode(id, type, name, relationship) {
	return createNode(id, type, name, "topDown", relationship);	
}

// json object with linkType bottomUp
function createBottomUpNode(id, type, name) {
	return createNode(id, type, name, "bottomUp");
}

// json for sibling idRef
function createSiblingIdRef(type, idRef, relationship) {
	return {"type": type, "nodeIdRef":idRef, "linkType":"sibling", "relationship":relationship};
}

// json for topDown idRef
function createTopDownIdRef(type, idRef, relationship) {
	return {"type": type, "nodeIdRef":idRef, "linkType":"topDown", "relationship":relationship};
}

// json for bottomUp idRef
function createBottomUpIdRef(type, idRef) {
	return {"type": type, "nodeIdRef":idRef, "linkType":"bottomUp"};
}

// gather bottom up info from indicators
// handled differently from other bottom up info because indicators are grouped 
// under types
function addIndicatorToBottomUpInfo(bottomUpInfo, aNode, subType, indiId) {
	var indiTypeMap = {};
	var indiGroup = STIXGroupings.indi;
	var nodeId = "";
	if (aNode != null) {
		nodeId = getObjIdRefStr(aNode);
	}
	if (nodeId != "") {  // track indicator child info for this ttp
		if (typeof(bottomUpInfo[nodeId]) == 'undefined') {
			indiTypeMap[subType] = [indiId];
			bottomUpInfo[nodeId] = {};
			(bottomUpInfo[nodeId])[indiGroup] =	indiTypeMap;
		}
		else {
			//indiTypeMap = (bottomUpInfo[nodeId]).indicators;
			indiTypeMap = (bottomUpInfo[nodeId])[indiGroup];
			if (typeof(indiTypeMap) == 'undefined') {
				indiTypeMap = {};
			}
			if (typeof(indiTypeMap[subType]) == 'undefined') {
				indiTypeMap[subType] = [indiId];
			}
			else {
				(indiTypeMap[subType]).push(indiId);
			}
			(bottomUpInfo[nodeId])[indiGroup] = indiTypeMap;
		}
	}
}

// gather all kinds of bottom up info except indicators
function addToBottomUpInfo(bottomUpInfo, aNode, parentType, parentId) {
	var parentTypeMap = null;
	var id = "";
	if (aNode != null) {
		id = getObjIdRefStr(aNode);
	}
	if (id != "") {
		if (typeof(bottomUpInfo[id]) == 'undefined') {  // first time seeing id
			parentTypeMap = {};
		}
		else {
			parentTypeMap = bottomUpInfo[id];
		}
		if (typeof(parentTypeMap[parentType]) == 'undefined') {
			parentTypeMap[parentType] = [parentId];
		}
		else {
			(parentTypeMap[parentType]).push(parentId);
		}
		bottomUpInfo[id] = parentTypeMap;
	}
}

// create list of json objs for bottomUp idRefs of a specific node type
function createBottomUpChildren(type, refs) {
	children = [];
	if (typeof(refs) != 'undefined') {
		$(refs).each(function (index, refId) {
			children.push(createBottomUpIdRef(type, refId));
		});
	}
	return children;
}

// create list of json objs for bottomUp idRefs of all possible types to a particular node 
function addBottomUpInfoToChildren(json, bottomUpInfo) {
	var nodeId = json.nodeId;
	var info = bottomUpInfo[nodeId];
	if (typeof(json["children"]) == 'undefined') {
		json["children"] = [];
	}
	if (typeof(info) != 'undefined') {
		var cas = info[STIXGroupings.ca];
		$.merge(json.children, createBottomUpChildren(STIXType.ca, cas));
		var coas = info[STIXGroupings.coa];
		$.merge(json.children, createBottomUpChildren(STIXType.coa, coas));
		var ets = info[STIXGroupings.et];
		$.merge(json.children, createBottomUpChildren(STIXType.et, ets));
		var incidents = info[STIXGroupings.incident];
		$.merge(json.children, createBottomUpChildren(STIXType.incident, incidents));
		var tas = info[STIXGroupings.ta];
		$.merge(json.children, createBottomUpChildren(STIXType.ta, tas));
		var ttps = info[STIXGroupings.ttp];
		$.merge(json.children, createBottomUpChildren(STIXType.ttp, ttps));
		
		// indicators get handled differently because they are grouped under type nodes
		var indiTypeMap = info[STIXGroupings.indi];
		if (typeof(indiTypeMap) != 'undefined') {
			$.map(indiTypeMap, function(indiList, subType) {
				var subTypeNode = createBottomUpNode(null, STIXType.indi, subType);
				var children = [];
				$(indiList).each(function (index, indiId) {
					children.push(createBottomUpIdRef(STIXType.indi, indiId));
				});
				subTypeNode["children"] = children;
				(json.children).push(subTypeNode);
			});
		}
	}
	return json;
}

// add bottom up info for each of a list of nodes
function addBottomUpInfoForNodes(nodes, bottomUpInfo) {
	$(nodes).each(function(index, node) {
		addBottomUpInfoToChildren(node, bottomUpInfo);
	});
}

// takes an array of name strings and merges them
// into a single string separated by "\n"
function concatenateNames(names) {
    var nameStr = "";
    $(names).each(function (index, name) {
            nameStr = nameStr + $(name).text();
            if (index < names.length - 1) {
                nameStr = nameStr + "\n";
            }
        });
    return nameStr;
}
