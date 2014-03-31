/*
 * Copyright (c) 2013 – The MITRE Corporation
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
    		'threat-actor': 'http://stix.mitre.org/ThreatActor-1',
    		'ttp': 'http://stix.mitre.org/TTP-1' 
    	};
    return nsMap[prefix] || null;
}

var entityRelationshipMap = {
		'Campaign' : ['Associated_Campaign', 'Attributed_Threat_Actor', 'Related_TTP', 'Related_Incident', 'Related_Indicator'],
		'Course_Of_Action' : ['Related_COA'],
		'Exploit_Target' : ['Potential_COA', 'Related_Exploit_Target'],
		'Incident' : ['COA_Requested', 'COA_Taken', 'Leveraged_TTP', 'Related_Incident', 'Related_Indicator', 'Related_Observable', 'Threat_Actor'],
		'Indicator' : ['Indicated_TTP', 'Observable', 'Related_Indicator', 'Suggested_COA'],
		'Observable' : [],
		'Threat_Actor' : ['Associated_Actor', 'Associated_Campaign', 'Observed_TTP'],
		'TTP' : ['Attack_Pattern', 'Exploit_Targets', 'Malware', 'Observable', 'Related_TTP', 'Tool', 'Victim_Targeting']
}

// single node types
var STIXType = {
		'ca' : 'campaign', 
		'coa' : 'CourseOfAction',
		'et' : 'ExploitTarget',
		'incident' : 'Incident',
		'indi': 'Indicator',
		'obs' : 'Observable',
		'ta' : 'threatActor',
		'ttp' : 'ObservedTTP'
};


//this is ugly - getting from entity name to STIXType, think of a better way later
function getEntityStixType(entity) {
	var typeStr = "";
	if (entity === 'Campaign') {
		typeStr = STIXType.ca;
	}
	else if (entity === 'Course_Of_Action') {
		typeStr = STIXType.coa;
	}
	else if (entity === 'Exploit_Target') {
		typeStr = STIXType.et;
	}
	else if (entity === 'Incident') {
		typeStr = STIXType.incident;
	}
	else if (entity === 'Indicator') {
		typeStr = STIXType.indi;
	}
	else if (entity === 'Observable') {
		typeStr = STIXType.obs;
	}
	else if (entity === 'Threat_Actor') {
		typeStr = STIXType.ta;
	}
	else if (entity === 'TTP') {
		typeStr = STIXType.ttp;
	}
	return typeStr; 
}

// grouping node types
var STIXGroupings = {
	'ca' : 'Campaigns',
	'coa' : 'CoursesOfAction',
	'et' : 'ExploitTargets',
	'incident' : 'Incidents',
	'indi' : 'Indicators',
	'obs' : 'Observables',
	'ta' : 'ThreatActors',
	'ttp' : 'TTPs'
};

var STIXPattern = {
		'ca' : './/stixCommon:Campaign', 
		'coa' : './/stixCommon:Course_Of_Action',
		'et' : './/stixCommon:Exploit_Target',
		'incident' : './/stixCommon:Incident',
		'indi': './/stixCommon:Indicator',
		'obs': './/stixCommon:Observable',
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
