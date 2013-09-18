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
    		'et': '"http://stix.mitre.org/ExploitTarget-1',
    		'incident': 'http://stix.mitre.org/Incident-1',
    		'indicator': 'http://stix.mitre.org/Indicator-2', 
    		'threat-actor': 'http://stix.mitre.org/ThreatActor-1',
    		'ttp': 'http://stix.mitre.org/TTP-1' 
    	};
    return nsMap[prefix] || null;
}

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

function getObjIdStr(obj) {
	var id = $(obj).attr('id');
	if (typeof(id) != 'undefined') {
		return id;
	}
	else {
		return "";
	}
}