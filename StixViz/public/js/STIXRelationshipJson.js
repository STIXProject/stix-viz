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

function createStixChildren(objNodes, parentName) {
    var allObjJson = [];
    var topChildJson = null;
    $(objNodes).each(function (index, objJson) {
	    allObjJson.push(objJson);
	});
    if (allObjJson.length > 0) {
    	topChildJson = {"type":parentName, "children":allObjJson};
    }
    return topChildJson;
}

// top level nodes: Threat Actor, TTP, Campaign, Incident, Indicator, Exploit, Course of Action,
//   Observable is not at top level because it has no outgoing relationships - it will appear under
//   other branches since it has incoming relationships.
function createTreeJson(jsonObj, campaignNodes, incidentNodes, indiNodes, taNodes, ttpNodes) {
    var reportChildren = [];
    var topLevelChild = null;

    topLevelChild = createStixChildren(campaignNodes, 'Campaigns');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(incidentNodes, 'Incidents');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(indiNodes, 'Indicators');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(taNodes, 'ThreatActors');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(ttpNodes, 'TTPs');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }

    // TODO - add other top level nodes
    jsonObj['children'] = reportChildren;
    return jsonObj;
}

//TODO add associated campaigns
function processCampaignObjs(caObjs, taBottomUpInfo, ttpBottomUpInfo) {
    var campaignNodes = [];
    var caJson = null;
    var caChildren = null;
    var caId = "";
    $(caObjs).each(function (index, ca) {
            caJson = {"type":"campaign"};
            caId = getObjIdStr(ca);
            caJson["nodeId"] = caId;
            caJson["name"] = getBestCampaignName(ca);
            // children are related_ttps, related_incidents, related_indicators, attribution(threat actors)
            caChildren = [];
            var relatedTTPs = xpFind('.//campaign:Related_TTPs//campaign:Related_TTP', ca);
            $(relatedTTPs).each(function (index, ttp) {
            	if (caId != "") {
            		addToTTPBottomInfo(ttpBottomUpInfo, ttp, 'campaigns', caId);
            	}
            });
            $.merge(caChildren, processChildTTPs(relatedTTPs));
            $.merge(caChildren, processChildIncidents(xpFind('.//campaign:Related_Incidents//campaign:Related_Incident', ca)));
            $.merge(caChildren, processChildIndicators(xpFind('.//campaign:Related_Indicators//campaign:Related_Indicator', ca)));
            var attributedActors = xpFind('.//campaign:Attribution//campaign:Attributed_Threat_Actor', ca);
            $(attributedActors).each(function (index, actor) {
            	if (caId != "") {
            		addToThreatActorBottomUpInfo(taBottomUpInfo, actor, 'campaigns', caId);
            	}
            });
            $.merge(caChildren, processChildThreatActors(attributedActors));
            if (caChildren.length > 0) {
                caJson["children"] = caChildren;
            }
            campaignNodes.push(caJson);
        });
    return campaignNodes;
}

function addToThreatActorBottomUpInfo(taBottomUpInfo, taParent, parentType, parentId) {
	var parentTypeMap = null;
	var taId = "";
	var ta = $(xpFindSingle('.//stixCommon:Threat_Actor', taParent));
	if (ta != null) {
		taId = getObjIdRefStr(ta);
	}
	if (taId != "") {
		if (typeof(taBottomUpInfo[taId]) == 'undefined') {  // first time seeing taId
			parentTypeMap = {};
		}
		else {
			parentTypeMap = taBottomUpInfo[taId];
		}
		parentTypeMap = addToParentTypeMap(parentTypeMap, parentType, parentId);
		taBottomUpInfo[taId] = parentTypeMap;
	}
}

//TODO add <Campaigns>
function processIncidentObjs(incidentObjs, ttpBottomUpInfo) {
    var incidentNodes = [];
    var incidentJson = null;
    var incidentChildren = null;
    $(incidentObjs).each(function (index, incident) {
            incidentJson = {"type":"Incident"};
            incidentJson["nodeId"] = getObjIdStr(incident);
            incidentJson["name"] = getBestIncidentName(incident);
            // children are related_indicators, related_observables, leverage_TTPs, Attributed_Threat_Actors
            incidentChildren = [];
            $.merge(incidentChildren, processChildIndicators(xpFind('.//incident:Related_Indicators//incident:Related_Indicator', incident)));
            $.merge(incidentChildren, processChildObservables(xpFind('.//incident:Related_Observables//incident:Related_Observable', incident)));
            $.merge(incidentChildren, processChildTTPs(xpFind('.//incident:Leveraged_TTPs//incident:Leveraged_TTP', incident)));
            $.merge(incidentChildren, processChildThreatActors(xpFind('./incident:Attributed_Threat_Actors//incident:Threat_Actor', incident)));
            if (incidentChildren.length > 0) {
                incidentJson["children"] = incidentChildren;
            }
            incidentNodes.push(incidentJson);
        });
    return incidentNodes;
}

// TODO - add <Campaigns>, <COAs>, <Incidents>
function processIndicatorObjs(indiObjs, ttpBottomUpInfo) {
	var subTypeMap = {};
	var subType = "not specified";
	var indiNodes = [];
	var indiJson = null;
	var indiChildren = null;
	// first, group indicators by indicator type
	$(indiObjs).each(function (index, indi) {	
	    var childNode = {"type":"Indicator"};
	    var indiId = getObjIdStr(indi);
    	childNode["nodeId"] = indiId;
    	childNode["name"] = getBestIndicatorName(indi);
	    var typeNode = xpFindSingle('.//indicator:Type', indi);
	    if (typeNode != null) {
	    	subType = $(typeNode).text();
	    }

		// children are Indicated_TTP, Observables
	    var indicatedTTP = xpFindSingle('.//indicator:Indicated_TTP', indi);
	    var indiTypeMap = null;
		indiChildren = [];
		if (indicatedTTP != null) {
				var ttpId = "";
				$.merge(indiChildren, processChildTTPs([indicatedTTP]));
				indicatedTTP = $(xpFindSingle('.//stixCommon:TTP', indicatedTTP));
				if (indicatedTTP != null) {
					ttpId = getObjIdRefStr(indicatedTTP);
				}
				if (ttpId != "") {  // track indicator child info for this ttp
					if (typeof(ttpBottomUpInfo[ttpId]) == 'undefined') {
						indiTypeMap = {};
						indiTypeMap[subType] = [indiId];
						ttpBottomUpInfo[ttpId] = {"indicators":indiTypeMap};
					}
					else {
						indiTypeMap = (ttpBottomUpInfo[ttpId]).indicators;
						if (typeof(indiTypeMap) == 'undefined') {
							indiTypeMap = {};
						}
						if (typeof(indiTypeMap[subType]) == 'undefined') {
							indiTypeMap[subType] = [indiId];
						}
						else {
							(indiTypeMap[subType]).push(indiId);
						}
						(ttpBottomUpInfo[ttpId]).indicators = indiTypeMap;
					}
				}
		}
		$.merge(indiChildren, processChildObservables(xpFind('.//indicator:Observable', indi)));
		if (indiChildren.length > 0) {
			childNode["children"] = indiChildren;
		}
	    if (typeof(subTypeMap[subType]) == 'undefined') {
	    	subTypeMap[subType] = [childNode];
	    }
	    else {
	    	subTypeMap[subType].push(childNode);
	    }
	});
    // for each subtype add a child indicator node
    $.map(subTypeMap, function(children, subType) {
	    indiJson = {"type":"Indicator", "subtype":subType, "children":children};
	    indiNodes.push(indiJson);
	});
    return indiNodes;
}

function processCoaObjs(coaObjs) {
	var coaNodes = [];
	var coaJson = null;
	var coaId = null;
	$(coaObjs).each(function (index, coa) {
		coaJson = {"type":"CourseOfAction"};
		coaId = getObjIdStr(coa);
		coaJson["nodeId"] = coaId;
		coaJson["name"] = getBestCourseOfActionName(coa);
		coaNodes.push(coaJson);
	});
	return coaNodes;
}

// TODO - add associated actors
// TODO - if a threat actor is specified via Attribution in a campaign, and 
//     the campaign is specified as an associated_campaign in the threat actor,
//     the campaign node will appear twice in the tree under the threat actor
function processThreatActorObjs(taObjs, taBottomUpInfo, ttpBottomUpInfo) {
    var taNodes = [];
    var taJson = null;
    var taChildren = null;
    var taId = null;
    $(taObjs).each(function (index, ta) {
            taJson = {"type":"threatActor"};
            taId = getObjIdStr(ta);
            taJson["nodeId"] = taId;
            taJson["name"] = getBestThreatActorName(ta);
            // children are observed_ttps, associated_campaigns, <Incidents>
            taChildren = [];
            var relatedTTPs = xpFind('.//threat-actor:Observed_TTP', ta);
            $(relatedTTPs).each(function (index, ttp) {
        		if (taId != "") {
        			addToTTPBottomInfo(ttpBottomUpInfo, ttp, 'threatActors', taId);
        		}
            });
            $.merge(taChildren, processChildTTPs(relatedTTPs));
            $.merge(taChildren, processChildCampaigns(xpFind('.//threat-actor:Associated_Campaign', ta)));
            //TODO add <Incidents>
            if (taChildren.length > 0) {
                taJson["children"] = taChildren;
            }
    		taJson = addThreatActorBottomUpInfo(taJson, taBottomUpInfo);
            taNodes.push(taJson);
        });
    return taNodes;
}


function addThreatActorBottomUpInfo(taJson, bottomUpInfo) {
	var nodeId = taJson.nodeId;
	var info = bottomUpInfo[nodeId];
	if (typeof(taJson["children"]) == 'undefined') {
		taJson["children"] = [];
	}
	if (typeof(info) != 'undefined') {
		var cas = info.campaigns;
		if (typeof(cas) != 'undefined') {
			$(cas).each(function (index, caId) {
				(taJson.children).push({"type":"campaign", "nodeIdRef":caId});		
			});
		}
	}
	return taJson;
}

//  TODO add <Incidents>, <ThreatActors>
function processTTPObjs(ttpObjs, ttpBottomUpInfo) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttpObjs).each(function (index, ttp) {
    		ttpJson = createSingleTTPJson(ttp);
    		ttpJson = addTTPBottomUpInfo(ttpJson, ttpBottomUpInfo);
            ttpNodes.push(ttpJson);
        });
    return ttpNodes;
}



// TODO first just handle idRefs, need to add inline ttp processing
function processChildTTPs(ttps) {
    var ttpNodes = [];
    $(ttps).each(function (index, ttp) {
	    var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:TTP', ttp)));
            if (idRef != "") {
                ttpNodes.push({"type":"ObservedTTP", "nodeIdRef":idRef});
            }
            else {  // inline TTP
            	ttpNodes.push(createSingleTTPJson(ttp));
            }
	});
    return ttpNodes;
}

// TODO first just handle idRefs, need to add inline ttp processing
function processChildCampaigns(cas) {
    var caNodes = [];
    $(cas).each(function (index, ca) {
	    var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Campaign', ca)));
            if (idRef != "") {
                caNodes.push({"type":"campaign", "nodeIdRef":idRef});
            }
	});
    return caNodes;
}

// TODO first just handle idRefs, need to add inline ttp processing
function processChildThreatActors(actors) {
    var actorNodes = [];
    $(actors).each(function (index, actor) {
	    var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Threat_Actor', actor)));
	    if (idRef != "") {
	    	actorNodes.push({"type":"threatActor", "nodeIdRef":idRef});
	    }
	});
    return actorNodes;
}

function processChildIncidents(incidents) {
    var incidentNodes = [];
    $(incidents).each(function (index, incident) {
    	var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Incident', incident)));
		if (idRef != "") {
			incidentNodes.push({"type":"Indicator", "nodeIdRef":idRef});
		}
    });
    return incidentNodes;
}

function processChildIndicators(indis) {
	var indiNodes = [];
	$(indis).each(function (index, indi) {
		var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Indicator', indi)));
		if (idRef != "") {
			indiNodes.push({"type":"Indicator", "nodeIdRef":idRef});
		}
	});
    return indiNodes;
}

// TODO implement!
function processChildObservables(obs) {
    return [];
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
	var campaignObjs = [];
	var coaObjs = [];
	var etObjs = [];
	var incidentObjs = [];
	var indiObjs = [];
	// var obsObjs = [];
	var taObjs = [];
	var ttpObjs = [];

	var campaignNodes = [];
	var coaNodes = [];
	var etNodes = [];
	var incidentNodes = [];
	var indiNodes = [];
	var taNodes = [];
	var ttpNodes = [];
	
	var taBottomUpInfo = {};
	var ttpBottomUpInfo = {};
	
	var numFiles = 0;

	$(inputFiles).each(function (index, f) {
                var xml = null;
                var reader = new FileReader();
                reader.onload = (function(theFile) {
                        return function(e) {
                            xml = new DOMParser().parseFromString(this.result, "text/xml"); 
                            addXmlDoc(f.name,xml);  // adds the new XML file to the drop down menu in the UI
                            doc = xml;
                            $.merge(campaignObjs, xpFind('//stix:Campaigns/stix:Campaign', xml));
                            $.merge(coaObjs, xpFind('//stix:Courses_Of_Action/stix:Course_Of_Action', xml));
                            $.merge(etObjs, xpFind('//stix:Exploit_Targets/stix:Exploit_Target', xml));
                            $.merge(incidentObjs, xpFind('//stix:Incidents/stix:Incident', xml));
                            $.merge(indiObjs, xpFind('//stix:Indicators/stix:Indicator', xml));
                            // $.merge(obsObjs, xpFind('//stix:Observables/stix:Observable', xml));
                            $.merge(taObjs, xpFind('//stix:Threat_Actors/stix:Threat_Actor', xml));
                            $.merge(ttpObjs, xpFind('//stix:TTPs/stix:TTP', xml));
                            
                            numFiles++;
                            if (numFiles == inputFiles.length) {  // finished last file
                                campaignNodes = processCampaignObjs(campaignObjs, taBottomUpInfo, ttpBottomUpInfo);
                                coaNodes = processCoaObjs(coaObjs);
                                incidentNodes = processIncidentObjs(incidentObjs, ttpBottomUpInfo);
                                indiNodes = processIndicatorObjs(indiObjs, ttpBottomUpInfo);
                                taNodes = processThreatActorObjs(taObjs, taBottomUpInfo, ttpBottomUpInfo);
                                ttpNodes = processTTPObjs(ttpObjs, ttpBottomUpInfo);

                                //obsMap = processStixObservables(obsObjs);
                                jsonObj = createTreeJson(jsonObj, campaignNodes, incidentNodes, indiNodes, taNodes, ttpNodes);
                                // displays Json to web page for debugging
                                //$('#jsonOutput').text(JSON.stringify(jsonObj, null, 2));  
                                // displays tree
                                displayTree(JSON.stringify(jsonObj, null, 2));
                            }
                        };
                    }) (f);
                reader.readAsText(f);
	    });
}

