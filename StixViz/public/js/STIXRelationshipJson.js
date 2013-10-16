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
    	topChildJson = {"type":parentName, "children":allObjJson, "linkType":"topDown"};
    }
    return topChildJson;
}

// top level nodes: Threat Actor, TTP, Campaign, Incident, Indicator, Exploit, Course of Action,
//   Observable is not at top level because it has no outgoing relationships - it will appear under
//   other branches since it has incoming relationships.
function createTreeJson(jsonObj, campaignNodes, coaNodes, etNodes, incidentNodes, indiNodes, taNodes, ttpNodes) {
    var reportChildren = [];
    var topLevelChild = null;

    topLevelChild = createStixChildren(campaignNodes, 'Campaigns');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(coaNodes, 'CoursesOfAction');
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(etNodes, 'ExploitTargets');
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

    // TODO - add observables?
    jsonObj['children'] = reportChildren;
    return jsonObj;
}

//TODO add associated campaigns
function processCampaignObjs(caObjs, incidentBottomUpInfo, indiBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo) {
    var campaignNodes = [];
    var caJson = null;
    var caChildren = null;
    var caId = "";
    $(caObjs).each(function (index, ca) {
            caJson = {"type":STIXType.ca};
            caId = getObjIdStr(ca);
            caJson["nodeId"] = caId;
            caJson["name"] = getBestCampaignName(ca);
            caJson["linkType"] = "topDown";
            // children are related_ttps, related_incidents, related_indicators, attribution(threat actors)
            caChildren = [];
            var relatedTTPs = xpFind('.//campaign:Related_TTPs//campaign:Related_TTP', ca);
        	if (caId != "") {
	            $(relatedTTPs).each(function (index, ttp) {
	            	addToBottomUpInfo(ttpBottomUpInfo, $(xpFindSingle('.//stixCommon:TTP', ttp)), 'campaigns', caId);
	            });
        	}
            $.merge(caChildren, processChildTTPs(relatedTTPs));
            var incidents = xpFind('.//campaign:Related_Incidents//campaign:Related_Incident', ca);
        	if (caId != "") {
	            $(incidents).each(function (index, incident) {
	            	addToBottomUpInfo(incidentBottomUpInfo, $(xpFindSingle('.//stixCommon:Incident', incident)), 'campaigns', caId);
	            });
        	}
            $.merge(caChildren, processChildIncidents(incidents));
            var indicators = xpFind('.//campaign:Related_Indicators//campaign:Related_Indicator', ca);
        	if (caId != "") {
	            $(indicators).each(function (index, indi) {
	            	addToBottomUpInfo(indiBottomUpInfo, $(xpFindSingle('.//stixCommon:Indicator', indi)), 'campaigns', caId);
	            });
        	}
            $.merge(caChildren, processChildIndicators(indicators));
            var attributedActors = xpFind('.//campaign:Attribution//campaign:Attributed_Threat_Actor', ca);
        	if (caId != "") {
	            $(attributedActors).each(function (index, actor) {
	            	addToBottomUpInfo(taBottomUpInfo, $(xpFindSingle('.//stixCommon:Threat_Actor', actor)), 'campaigns', caId);
	            });
        	}
            $.merge(caChildren, processChildThreatActors(attributedActors));
            if (caChildren.length > 0) {
                caJson["children"] = caChildren;
            }
            campaignNodes.push(caJson);
        });
    return campaignNodes;
}

function processCoaObjs(coaObjs) {
	var coaNodes = [];
	var coaJson = null;
	var coaId = null;
	$(coaObjs).each(function (index, coa) {
		coaJson = {"type":STIXType.coa};
		coaId = getObjIdStr(coa);
		coaJson["nodeId"] = coaId;
		coaJson["name"] = getBestCourseOfActionName(coa);
        coaJson["linkType"] = "topDown";
		coaNodes.push(coaJson);
	});
	return coaNodes;
}

function processETObjs(etObjs) {
	var etNodes = [];
	var etJson = null;
	var etId = null;
	var etChildren = null;
	$(etObjs).each(function (index, et) {
		etJson = {"type": STIXType.et};
		etId = getObjIdStr(et);
		etJson["nodeId"] = etId;
		etJson["name"] = getBestExploitTargetName(et);
        etJson["linkType"] = "topDown";
		etChildren = processChildCoas(xpFind('.//et:Potential_COA', et));
		if (etChildren.length > 0) {
			etJson["children"] = etChildren;
		}
		etNodes.push(etJson);
	});
	return etNodes;
}

//TODO add <Campaigns>
function processIncidentObjs(incidentObjs, ttpBottomUpInfo) {
    var incidentNodes = [];
    var incidentJson = null;
    var incidentChildren = null;
    $(incidentObjs).each(function (index, incident) {
            incidentJson = {"type":STIXType.incident};
            incidentJson["nodeId"] = getObjIdStr(incident);
            incidentJson["name"] = getBestIncidentName(incident);
            incidentJson["linkType"] = "topDown";
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
function processIndicatorObjs(indiObjs, indiBottomUpInfo, ttpBottomUpInfo) {
	var subTypeMap = {};
	var subType = "not specified";
	var indiNodes = [];
	var indiJson = null;
	var indiChildren = [];
	// first, group indicators by indicator type
	$(indiObjs).each(function (index, indi) {	
	    var childJson = {"type": STIXType.indi};
	    var indiId = getObjIdStr(indi);
    	childJson["nodeId"] = indiId;
    	childJson["name"] = getBestIndicatorName(indi);
        childJson["linkType"] = "topDown";
	    var typeNode = xpFindSingle('.//indicator:Type', indi);
	    if (typeNode != null) {
	    	subType = $(typeNode).text();
	    }
	    addBottomUpInfoToChildren(childJson, indiBottomUpInfo);
		indiChildren = childJson["children"];
		$.merge(indiChildren, processChildCoas(xpFind('.//indicator:Suggested_COA', indi)));
		// children are Indicated_TTP, Observables
	    var indicatedTTP = xpFindSingle('.//indicator:Indicated_TTP', indi);
	    var indiTypeMap = null;
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
			childJson["children"] = indiChildren;
		}
	    if (typeof(subTypeMap[subType]) == 'undefined') {
	    	subTypeMap[subType] = [childJson];
	    }
	    else {
	    	subTypeMap[subType].push(childJson);
	    }
	});
    // for each subtype add a child indicator node
    $.map(subTypeMap, function(children, subType) {
	    indiJson = {"type": STIXType.indi, "subtype":subType, "children":children, "linkType":"topDown"};
	    indiNodes.push(indiJson);
	});
    return indiNodes;
}

// TODO - add associated actors
// TODO - if a threat actor is specified via Attribution in a campaign, and 
//     the campaign is specified as an associated_campaign in the threat actor,
//     the campaign node will appear twice in the tree under the threat actor
function processThreatActorObjs(taObjs, campaignBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo) {
    var taNodes = [];
    var taJson = null;
    var taChildren = null;
    var taId = null;
    $(taObjs).each(function (index, ta) {
            taJson = {"type": STIXType.ta};
            taId = getObjIdStr(ta);
            taJson["nodeId"] = taId;
            taJson["name"] = getBestThreatActorName(ta);
            taJson["linkType"] = "topDown";
            // children are observed_ttps, associated_campaigns, <Incidents>
            taChildren = [];
            var relatedTTPs = xpFind('.//threat-actor:Observed_TTP', ta);
    		if (taId != "") {
	            $(relatedTTPs).each(function (index, ttp) {
	            	addToBottomUpInfo(ttpBottomUpInfo, $(xpFindSingle('.//stixCommon:TTP', ttp)), 'threatActors', taId);
	            });
    		}
            $.merge(taChildren, processChildTTPs(relatedTTPs));
            var campaigns = xpFind('.//threat-actor:Associated_Campaign', ta);
            if (taId != null) {
	            $(campaigns).each(function (index, ca) {
	            	addToBottomUpInfo(campaignBottomUpInfo, ca, 'threatActors', taId);
	            });
            }
            $.merge(taChildren, processChildCampaigns(campaigns));
            //TODO add <Incidents>
            if (taChildren.length > 0) {
                taJson["children"] = taChildren;
            }
            taNodes.push(taJson);
        });
    return taNodes;
}

//  TODO add <Incidents>, <ThreatActors>
function processTTPObjs(ttpObjs, ttpBottomUpInfo) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttpObjs).each(function (index, ttp) {
    		ttpJson = createSingleTTPJson(ttp);
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
                ttpNodes.push({"type": STIXType.ttp, "nodeIdRef":idRef, "linkType":"topDown"});
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
                caNodes.push({"type": STIXType.ca, "nodeIdRef":idRef, "linkType":"topDown"});
            }
	});
    return caNodes;
}

function processChildCoas(coas) {
	var coaNodes = [];
	var coa = null;
	var coaJson = null;
	$(coas).each(function(index, coaObj) {
		coa = $(xpFindSingle('.//stixCommon:Course_Of_Action', coaObj));
		if (coa != null) {
			coaJson = {"type": STIXType.coa};
		    var idRef = getObjIdRefStr(coa);
	        if (idRef != "") {
	        	coaJson["nodeIdRef"] = idRef;
	        }	
	        else {
	        	coaJson["name"] = getBestCourseOfActionName(coa[0]);
	        }
	        coaJson["linkType"] = "topDown";
	        coaNodes.push(coaJson);
		}
	});
	return coaNodes;
}

// TODO first just handle idRefs, need to add inline ttp processing
function processChildThreatActors(actors) {
    var actorNodes = [];
    $(actors).each(function (index, actor) {
	    var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Threat_Actor', actor)));
	    if (idRef != "") {
	    	actorNodes.push({"type": STIXType.ta, "nodeIdRef":idRef, "linkType":"topDown"});
	    }
	});
    return actorNodes;
}

function processChildIncidents(incidents) {
    var incidentNodes = [];
    $(incidents).each(function (index, incident) {
    	var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Incident', incident)));
		if (idRef != "") {
			incidentNodes.push({"type": STIXType.incident, "nodeIdRef":idRef, "linkType":"topDown"});
		}
    });
    return incidentNodes;
}

function processChildIndicators(indis) {
	var indiNodes = [];
	$(indis).each(function (index, indi) {
		var idRef = getObjIdRefStr($(xpFindSingle('.//stixCommon:Indicator', indi)));
		if (idRef != "") {
			indiNodes.push({"type": STIXType.indi, "nodeIdRef":idRef, "linkType":"topDown"});
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
	
	var campaignBottomUpInfo = {};
	var incidentBottomUpInfo = {};
	var indiBottomUpInfo = {};
	var taBottomUpInfo = {};
	var ttpBottomUpInfo = {};
	
	var numFiles = 0;

	$(inputFiles).each(function (index, f) {
                var xml = null;
                var reader = new FileReader();
                reader.onload = (function(theFile) {
                        return function(e) {
                            xml = new DOMParser().parseFromString(this.result, "text/xml"); 
                            addXmlDoc(theFile.name,xml);  // adds the new XML file to the drop down menu in the UI
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
                                campaignNodes = processCampaignObjs(campaignObjs, incidentBottomUpInfo, indiBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo);
                                coaNodes = processCoaObjs(coaObjs);
                                etNodes = processETObjs(etObjs);
                                incidentNodes = processIncidentObjs(incidentObjs, ttpBottomUpInfo);
                                indiNodes = processIndicatorObjs(indiObjs, indiBottomUpInfo, ttpBottomUpInfo);
                                taNodes = processThreatActorObjs(taObjs, campaignBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo);
                                ttpNodes = processTTPObjs(ttpObjs, ttpBottomUpInfo);

                                addBottomUpInfoForNodes(campaignNodes, campaignBottomUpInfo);
                                addBottomUpInfoForNodes(incidentNodes, incidentBottomUpInfo);
                                addBottomUpInfoForNodes(taNodes, taBottomUpInfo);
                                addBottomUpInfoForNodes(ttpNodes, ttpBottomUpInfo);
                                //obsMap = processStixObservables(obsObjs);
                                jsonObj = createTreeJson(jsonObj, campaignNodes, coaNodes, etNodes, incidentNodes, indiNodes, taNodes, ttpNodes);
                                // displays Json to web page for debugging
                               // $('#jsonOutput').text(JSON.stringify(jsonObj, null, 2));  
                                // displays tree
                                displayTree(JSON.stringify(jsonObj, null, 2));
                            }
                        };
                    }) (f);
                reader.readAsText(f);
	    });
}

