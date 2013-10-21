function nsResolver(prefix) {
    var nsMap =  {
    		'stix': 'http://stix.mitre.org/stix-1', 
    		'stixVocabs': 'http://stix.mitre.org/default_vocabularies-1', 
    		'stix-ciq': 'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1', 
    		'stixCommon': 'http://stix.mitre.org/common-1', 
    		'cybox': 'http://cybox.mitre.org/cybox-2', 
    		'cyboxCommon': 'http://cybox.mitre.org/common-2', 
    		'cyboxVocabs': 'http://cybox.mitre.org/default_vocabularies-2', 
    		'AddressObject': 'http://cybox.mitre.org/objects#AddressObject-2',
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

// use xpath to deal with default namespaces
function xpFind(path, startNode) {
    var newNodes = [];
    var xpathResult = doc.evaluate(path, startNode, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
    for (var i=0; i< xpathResult.snapshotLength; i++) {
        newNodes.push(xpathResult.snapshotItem(i));
    }	
    return newNodes;
}

function xpFindSingle(path, startNode) {
    var descendants = xpFind(path, startNode);
    var singleDescendant = null;
    if (descendants.length == 1) {
        singleDescendant =  descendants[0];
    }
    return singleDescendant;
}

function getObjIdRefStr(obj) {
	var idRef = $(obj).attr('idref');
	if (typeof(idRef) != 'undefined') {
		return idRef;
	}
	else {
		return "";
	}
}

function getObjIdStr(obj) {
	var id = $(obj).attr('id');
	if (typeof(id) != 'undefined') {
		return id;
	}
	else {
		return "";
	}
}

function createNode(id, type, name, direction) {
	var json = {"type": type};
	if (id != null) {
		json["nodeId"] = id;
	}
	json["name"] = name;
	json["linkType"] = direction;	
	return json;	
}

function createTopDownNode(id, type, name) {
	return createNode(id, type, name, "topDown");	
}

function createBottomUpNode(id, type, name) {
	return createNode(id, type, name, "bottomUp");
}

function createTopDownIdRef(type, idRef) {
	return {"type": type, "nodeIdRef":idRef, "linkType":"topDown"};
}

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
		parentTypeMap = addToParentTypeMap(parentTypeMap, parentType, parentId);
		bottomUpInfo[id] = parentTypeMap;
	}
}

function createBottomUpChildren(type, refs) {
	children = [];
	if (typeof(refs) != 'undefined') {
		$(refs).each(function (index, refId) {
			children.push(createBottomUpIdRef(type, refId));
		});
	}
	return children;
}
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

// add children to each of a list of nodes
function addBottomUpInfoForNodes(nodes, bottomUpInfo) {
	$(nodes).each(function(index, node) {
		addBottomUpInfoToChildren(node, bottomUpInfo);
	});
}

function addToParentTypeMap(parentTypeMap, parentType, parentId) {
	if (typeof(parentTypeMap[parentType]) == 'undefined') {
		parentTypeMap[parentType] = [parentId];
	}
	else {
		(parentTypeMap[parentType]).push(parentId);
	}
	return parentTypeMap;
}

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
