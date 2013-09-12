// for each xml file 
//  gather TTPs from stix:TTPs
//    threat actors from stix:Threat_Actor
//    indicators from stix:Indicators - map<ttpId, [indictorObj]
//    observables from stix:Observables - map<id, obsJson>


// generate ttpMap => <id, ttpJson> using indicators
// add child Json to TTPs (including indicators), indicators can have observables

// generate threat actors from stix:Threat_Actors  taMap <id, taJson> using ttpMap
// add idref'd TTPs to threat_actors
//
// create report node w/children: TTPs, Threat_Actors
//   

function nsResolver(prefix) {
    var nsMap =  {'campaign': 'http://stix.mitre.org/Campaign-1', 'ttp': 'http://stix.mitre.org/TTP-1', 'stixVocabs': 'http://stix.mitre.org/default_vocabularies-1', 'marking': 'http://data-marking.mitre.org/Marking-1', 'stix-ciq': 'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1', 'stixCommon': 'http://stix.mitre.org/common-1', 'mandiant': 'http://www.mandiant.com', 'xal': 'urn:oasis:names:tc:ciq:xal:3', 'stix': 'http://stix.mitre.org/stix-1', 'mitre': 'http://www.mitre.org', 'threat-actor': 'http://stix.mitre.org/ThreatActor-1', 'cyboxCommon': 'http://cybox.mitre.org/common-2', 'xpil': 'urn:oasis:names:tc:ciq:xpil:3', 'indicator': 'http://stix.mitre.org/Indicator-2', 'URIObject': 'http://cybox.mitre.org/objects#URIObject-2', 'simpleMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1', 'cyboxVocabs': 'http://cybox.mitre.org/default_vocabularies-2', 'lmco': 'lockheedmartin.com', 'AddressObject': 'http://cybox.mitre.org/objects#AddressObject-2', 'cybox': 'http://cybox.mitre.org/cybox-2', 'LinkObject': 'http://cybox.mitre.org/objects#LinkObject-1', 'xsi': 'http://www.w3.org/2001/XMLSchema-instance', 'xnl': 'urn:oasis:names:tc:ciq:xnl:3'};
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

function addReportChildren(reportChildren, objMap, parentName) {
    var allObjJson = [];
    $.map(objMap, function (objJson, objId) {
	    allObjJson.push(objJson);
	});
    if (allObjJson.length > 0) {
	reportChildren.push({"type":parentName, "children":allObjJson});
    }
}

// top level nodes: Threat Actor, TTP, Campaign, Incident, Indicator, Exploit, Course of Action,
//   Observable is not at top level because it has no outgoing relationships - it will appear under
//   other branches since it has incoming relationships.
function createReport(jsonObj, taMap, ttpMap, campaignMap, indicatorMap) {
    var reportChildren = [];
    var mergedIndicatorList = [];
    addReportChildren(reportChildren, campaignMap, 'Campaigns');
    addReportChildren(reportChildren, taMap, 'ThreatActors');
    addReportChildren(reportChildren, ttpMap, 'TTPs');
    $.map(indicatorMap, function(indicators, ttpId) {
            $(indicators).each(function(index, indi) {
                    if (indi.type == 'Indicator') {
                        mergedIndicatorList.push(indi);
                    }
                });
	});
    if (mergedIndicatorList.length > 0) {
	reportChildren.push({"type":'Indicators', "children":mergedIndicatorList});
    }

    // SRL - add Incident, Exploit, Course of Action
    jsonObj['children'] = reportChildren;
    return jsonObj;
}

// create a name for a threat_actor based on it's Identity Specification if there
// is one.  Otherwise use it's common name
function getBestActorName(xmlNode) {
    var nameStr = "";
    if (xmlNode.nodeName == 'stix:Threat_Actor') {
	var specification = xpFindSingle('.//stix-ciq:Specification', xmlNode);
	if (specification != null) {
	    var orgNames = xpFind('.//xpil:PartyName//xnl:OrganisationName', specification)
		if (orgNames.length > 0) { // PartyName is an organisation
		    $(orgNames).each(function (index, org) {
			    var nameElt = xpFindSingle('.//xnl:NameElement', org);
			    nameStr = nameStr + $(nameElt).text();
			    var subdivElt = xpFindSingle('.//xnl:SubDivisionName', org);
			    if (subdivElt != null) {
				nameStr = nameStr + "\n" + $(subdivElt).text();
			    }
			    if (index < orgNames.length-1) {
				nameStr = nameStr + "\n";
			    }
			});
		}
		else {
		    var personNames = xpFind('.//xnl:PersonName', specification);
		    if (personNames.length > 0) {
			$(personNames).each(function (index, person) {
				var nameElt = xpFindSingle('.//xnl:NameElement', person);
				nameStr = nameStr + $(nameElt).text();
				if (index < personNames.length-1) {
				    nameStr = nameStr + "\n";
				}
			    });
		    }
		}
	}
	else {
	    var commonName = xpFindSingle('.//stixCommon:Name', xmlNode);
	    nameStr = $(commonName).text();
	}
    }
    return nameStr;
}

function createSingleThreatActorJson(ta, id, indicatorMap, ttpMap) {
    var actorJson = {"type":"threatActor"};
    actorJson["name"] = getBestActorName(ta);
    var obsTTPs = xpFind('.//threat-actor:Observed_TTP', ta);
    var actorChildren = [];
    // add observed ttps as children of the threat_actor node
    $(obsTTPs).each(function (index, ttp) {
	    addTTPChildJson(actorChildren, ttp, ttpMap, indicatorMap);
	});
    // only add children if there are some
    if (actorChildren.length > 0) {
	actorJson["children"] = actorChildren;
    }
    return actorJson;
}

function createSingleTTPJson(ttp, id, indicatorMap) {
    var ttpName = $(xpFindSingle('.//ttp:Title', ttp)).text();
    if (typeof(ttpName) === 'undefined') {
	ttpName = "";
    }
    var ttpChildren = getTTPChildren(ttp, indicatorMap[id]);
    var ttpJson = {"type": "ObservedTTP",
		   "name": ttpName};
    if (ttpChildren.length > 0) {
	ttpJson["children"] = ttpChildren;
    }
    return ttpJson;
}

function createSingleCampaignJson(ca, id, indicatorMap, ttpMap, taMap) {
    var campaignJson = {"type":"campaign"};
    campaignJson["name"] = $(xpFindSingle('.//campaign:Title', ca)).text();
    var relatedTTPs = xpFind('.//campaign:Related_TTPs//campaign:Related_TTP', ca);
    var campaignChildren = [];
    $(relatedTTPs).each(function (index, ttp) {
	    addTTPChildJson(campaignChildren, ttp, ttpMap, indicatorMap);
	});
    var attributedActors = xpFind('.//campaign:Attribution//campaign:Attributed_Threat_Actor', ca);
    $(attributedActors).each(function (index, actor) {
	    var idRef = $(xpFindSingle('.//stixCommon:Threat_Actor', actor)).attr('idref');
	    if (typeof(idRef) != 'undefined') {
		campaignChildren.push(taMap[idRef]);
	    }
	});
    if (campaignChildren.length > 0) {
	campaignJson["children"] = campaignChildren;
    }
    return campaignJson;
}

function addTTPChildJson(childList, ttp, ttpMap, indicatorMap) {
    var idRef = $(xpFindSingle('.//stixCommon:TTP', ttp)).attr('idref');
    if (typeof(idRef) != 'undefined') {   // TTP info is in the TTP section
	childList.push(ttpMap[idRef]);
    }
    else {  // TTP info is inline, need to process
	var id = $(ttp).attr('id');
	var inlineTTP = createSingleTTPJson(ttp, id, indicatorMap);
	if (typeof(inlineTTP) != 'undefined') {
	    childList.push(inlineTTP);
	}
    }
}

			    /* don't do this for now
function getCyboxObservableJson(obs) {
    var obsName = "";
    var subType = "";
    var uri = $(obs).nsFind('URIObject:Value');
    if (uri.length > 0) {
        obsName = $(uri).first().text();
	subType = 'URI';
    }
    else {
	var address = $(obs).nsFind('AddressObject:Address_Value');
	if (address.length > 0) {
	    obsName = $(address).text();
	    subType = 'IPRange';
	}
    }
    return {"type":"Observable", "subType":subType, "name":obsName};
}
			    */

// RESOURCES (cybox observables (URI, ip addresses, ttp:Tool), 
// SRL - need to add more child types
function findTTPResources(ttp) {
    resources = [];
    resourceObj = xpFindSingle('.//ttp:Resources', ttp);
    if (resourceObj != null) {
	var resourceName = $(xpFindSingle('.//ttp:Type', resourceObj)).text();
	if (typeof(name) == 'undefined') {
	    resourceName = "";
	}

	// see if there are Observables
	var observable = xpFind('.//cybox:Observable', resourceObj);
	if (observable.length > 0) {   // found at least one
	    // don't go to next level right now
	    // call this for an observable such as a URI or Address_Value (IPRange)
	    //resources.push(getCyboxObservableJson($(observable).get(0)));
	    resources.push({"type":"Observable", "name":resourceName});
	}
	else {
	    var tools = xpFind('.//ttp:Tool', resourceObj);
	    var toolString = "";
	    $(tools).each(function (index, tool) {
		    var toolName = $(xpFindSingle('.//cyboxCommon:Name', tool)).text();
		    if (typeof(toolName) != 'undefined') {
			if (toolString.length > 0) {
			    toolString = toolString + "\n" + toolName;
			}
			else {
			    toolString = toolName;
			}
		    }
		});
	    if (toolString.length>0) {
		resources.push({"type":"Tools", "name":toolString});
	    }
	}
    }
    return resources;
}

// BEHAVIORS (malware, attack pattern, exploit)
// SRL - need to add more child types
function findTTPBehaviors(ttp) {
    behaviors = [];
    var malware = xpFindSingle('.//ttp:Behavior//ttp:Malware', ttp);
    var mName = "";
    if (malware != null) {
	malware = $(malware).get(0);
	var instance = $(malware).children('ttp\\:Malware_Instance, Malware_Instance');
	if (instance.length > 0) {
	    mName = $(instance).children('ttp\\:Name, Name').text();
	}
	behaviors.push({"type":'MalwareBehavior', "name":mName});
    }
    var attackPats = xpFind('.//ttp:Behavior//ttp:Attack_Pattern', ttp);
    $(attackPats).each(function (index, pat) {
            behaviors.push({"type":'AttackPattern', "name":""});
        });
    var exploits = xpFind('.//ttp:Behavior//ttp:Exploits', ttp);
    $(exploits).each(function (index, exploit) {
            behaviors.push({"type":'Exploit', "name":""});
        });
    return behaviors;
}

// children can be INDICATORS (from indicator file), RESOURCES, 
// BEHAVIORS, or Victim_Targeting
function getTTPChildren(ttp, indicators) {
    // first add any indicator json of the ttp as children
    var children = indicators;
    if (typeof(children) == 'undefined') {
	children = [];
    }
    $.merge(children, findTTPBehaviors(ttp));
    $.merge(children, findTTPResources(ttp));
    var nameStr = "";
    // Victim_Targeting
    var victimTargets = xpFindSingle('.//ttp:Victim_Targeting', ttp);
    if (victimTargets != null) {
	var nameElts = xpFind('.//xal:NameElement', victimTargets);
	$(nameElts).each(function (index, thisElt) {
		nameStr = nameStr + $(thisElt).text();
		if (index < nameElts.length-1) {
		    nameStr = nameStr + "\n";
		}
	    });
	children.push({"type":"VictimTargeting", "name":nameStr});
    }
    return children;
}

function createJsonMapForObjs(objs, singleJsonFnName, indicatorMap, ttpMap, taMap) {
    var objMap = {};
    //Create the function
    var singleJsonfn = window[singleJsonFnName];

    $(objs).each(function(index, obj) {
	    var id = $(obj).attr('id');
	    objMap[id] = singleJsonfn(obj, id, indicatorMap, ttpMap, taMap);
	});
    return objMap;
}

/* *** SRL - don't process observables for now
// return map<obsId, obsJson>
function processStixObservables(observables) {
    var obsMap = {};
    observables.each(function (index, obs) {
	    var id = obs.attr('id');
	    var 
	});
    return obsMap;
}
*/

// return map<ttpId, [indiJson]>
// first sort indicators by indicated_ttp
// then for each ttp, sort indicators by subtype
//   create a json node for each subtype
//   add list of nodes for ttp to the map
function processStixIndicators(indicators) {
    var indicatorMap = {};
    var ttpIndiMap = {};
    //first sort indis by indicated ttp
    $(indicators).each(function (index, indi) {
	    var ttpId = "";
            var ttpIdObj = null;
	    var ttp = xpFindSingle('.//indicator:Indicated_TTP', indi);
            ttpObj = xpFindSingle('.//stixCommon:TTP', ttp);
            if (ttpObj != null) {
                ttpId = $(ttpObj).attr('idref');
            }
	    if (typeof(ttpIndiMap[ttpId]) == 'undefined') {
		ttpIndiMap[ttpId] = [indi];
	    }
	    else {
		ttpIndiMap[ttpId].push(indi);
	    }
	});

    // now create indicator Json for each ttp - one entry per subType
    //  combining indicator names for each subType
    $.map(ttpIndiMap, function(indiObjs, ttpId) {
	    var ttpJsonMap = {};
	    var subType = "";
	    indicatorMap[ttpId] = [];
	    // sort indiObjs by subtype
	    $(indiObjs).each(function(index, indi) {
                    var indiName = $(xpFindSingle('.//indicator:Title', indi)).text();
		    var typeNode = xpFindSingle('.//indicator:Type', indi);
		    if (typeNode != null) {
			subType = $(typeNode).text();
		    }
		    if (typeof(ttpJsonMap[subType]) == 'undefined') {
			ttpJsonMap[subType] = indiName;
		    }
		    else {
			ttpJsonMap[subType] = ttpJsonMap[subType] + "\n" + indiName;
		    }
		});
	    // for each subtype add a child indicator node
	    $.map(ttpJsonMap, function(indiName, subType) {
		    var indiJson = {"type":"Indicator", "subtype":subType, "name":indiName};
		    (indicatorMap[ttpId]).push(indiJson);
		});
	});

    return indicatorMap;
}

var doc = null;

var jsonObj = {"type": "top",
	       "name": "APT1",
	       "children": []};

// hack for development, switch to selecting from web page instead
//var inputFiles = ["http://ape.mitre.org:8080/stixdev/data/apt1-indicators-no-observables.xml", 
//		  "http://ape.mitre.org:8080/stixdev/data/APT1 with campaign - STIX 1.0.xml"];
    
// jsonObj will contain the whole tree structure
// indicatorMap is a map from ttp idref to json for the indicator
// ttpMap is a map from ttp id to the json for the ttp
function generateTreeJson(inputFiles) {
	var taObjs = [];
	var ttpObjs = [];
	var indiObjs = [];
	var obsObjs = [];
	var campaignObjs = [];
	var incidentObjs = [];

	var taMap = {};
	var ttpMap = {};
	var indicatorMap = {};
	var obsMap = {};
	var campaignMap = {};
	var incidentMap = {};
	
	var numFiles = 0;

	$(inputFiles).each(function (index, f) {
                var xml = null;
                var reader = new FileReader();
                reader.onload = (function(theFile) {
                        return function(e) {
                            xml = new DOMParser().parseFromString(this.result, "text/xml"); 
                            doc = xml;
                            $.merge(taObjs, xpFind('//stix:Threat_Actors/stix:Threat_Actor', xml));
                            $.merge(ttpObjs, xpFind('//stix:TTPs/stix:TTP', xml));
                            $.merge(indiObjs, xpFind('//stix:Indicators/stix:Indicator', xml));
                            $.merge(campaignObjs, xpFind('//stix:Campaigns/stix:Campaign', xml));

                            numFiles++;
                            if (numFiles == inputFiles.length) {  // finished last file
                                indicatorMap = processStixIndicators(indiObjs);
                                //obsMap = processStixObservables(obsObjs);
                                ttpMap = createJsonMapForObjs(ttpObjs, 'createSingleTTPJson', indicatorMap);
                                taMap = createJsonMapForObjs(taObjs, 'createSingleThreatActorJson', indicatorMap, ttpMap);
                                campaignMap = createJsonMapForObjs(campaignObjs, 'createSingleCampaignJson', indicatorMap, ttpMap, taMap);
                                jsonObj = createReport(jsonObj, taMap, ttpMap, campaignMap, indicatorMap);
                                // displays to web page
                                // $('#jsonOutput').text(JSON.stringify(jsonObj, null, 2));  
                                displayTree(JSON.stringify(jsonObj, null, 2));
                            }
                        };
                    }) (f);
                reader.readAsText(f);
	    });
}

