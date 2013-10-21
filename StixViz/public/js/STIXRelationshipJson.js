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
function createTreeJson(jsonObj, campaignNodes, coaNodes, etNodes, incidentNodes, indiNodes, obsNodes, taNodes, ttpNodes) {
    var reportChildren = [];
    var topLevelChild = null;

    topLevelChild = createStixChildren(campaignNodes, STIXGroupings.ca);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(coaNodes, STIXGroupings.coa);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(etNodes, STIXGroupings.et);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(incidentNodes, STIXGroupings.incident);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(indiNodes, STIXGroupings.indi);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(obsNodes, STIXGroupings.obs);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }    
    topLevelChild = createStixChildren(taNodes, STIXGroupings.ta);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(ttpNodes, STIXGroupings.ttp);
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
    		caId = getObjIdStr(ca);
            caJson = createTopDownNode(caId, STIXType.ca, getBestCampaignName(ca));
            // children are related_ttps, related_incidents, related_indicators, attribution(threat actors)
            caChildren = [];
            var relatedTTPs = xpFind('.//campaign:Related_TTPs//campaign:Related_TTP', ca);
            $.merge(caChildren, processChildTTPs(relatedTTPs));
            var incidents = xpFind('.//campaign:Related_Incidents//campaign:Related_Incident', ca);
            $.merge(caChildren, processChildIncidents(incidents));
            var indicators = xpFind('.//campaign:Related_Indicators//campaign:Related_Indicator', ca);
            $.merge(caChildren, processChildIndicators(indicators));
            var attributedActors = xpFind('.//campaign:Attribution//campaign:Attributed_Threat_Actor', ca);
            $.merge(caChildren, processChildThreatActors(attributedActors));
            if (caChildren.length > 0) {
                caJson["children"] = caChildren;
            }
        	if (caId != "") {
	            $(relatedTTPs).each(function (index, ttp) {
	            	addToBottomUpInfo(ttpBottomUpInfo, $(xpFindSingle(STIXPattern.ttp, ttp)), STIXGroupings.ca, caId);
	            });
	            $(incidents).each(function (index, incident) {
	            	addToBottomUpInfo(incidentBottomUpInfo, $(xpFindSingle(STIXPattern.incident, incident)), STIXGroupings.ca, caId);
	            });
	            $(indicators).each(function (index, indi) {
	            	addToBottomUpInfo(indiBottomUpInfo, $(xpFindSingle(STIXPattern.indi, indi)), STIXGroupings.ca, caId);
	            });
	            $(attributedActors).each(function (index, actor) {
	            	addToBottomUpInfo(taBottomUpInfo, $(xpFindSingle(STIXPattern.ta, actor)), STIXGroupings.ca, caId);
	            });
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
		coaId = getObjIdStr(coa);
		coaJson = createTopDownNode(coaId, STIXType.coa, getBestCourseOfActionName(coa));
		coaNodes.push(coaJson);
	});
	return coaNodes;
}

function processETObjs(etObjs, coaBottomUpInfo) {
	var etNodes = [];
	var etJson = null;
	var etId = null;
	var etChildren = null;
	$(etObjs).each(function (index, et) {
		etId = getObjIdStr(et);
		etJson = createTopDownNode(etId, STIXType.et, getBestExploitTargetName(et));
        var coas = xpFind('.//et:Potential_COA', et);
		etChildren = processChildCoas(coas);
		if (etChildren.length > 0) {
			etJson["children"] = etChildren;
		}
        if (etId != "") {
        	$(coas).each(function(index, coa) {
        		addToBottomUpInfo(coaBottomUpInfo, $(xpFindSingle(STIXPattern.coa, coa)), STIXGroupings.et, etId);
        	});
        }
		etNodes.push(etJson);
	});
	return etNodes;
}

function processIncidentObjs(incidentObjs, coaBottomUpInfo, indiBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo) {
    var incidentNodes = [];
    var incidentJson = null;
    var incidentChildren = null;
    var incidentId = null;
    $(incidentObjs).each(function (index, incident) {
    	incidentId = getObjIdStr(incident);
    	incidentJson = createTopDownNode(incidentId, STIXType.incident, getBestIncidentName(incident));
    	// children are related_indicators, related_observables, leverage_TTPs, Attributed_Threat_Actors
    	incidentChildren = [];
    	var indicators = xpFind('.//incident:Related_Indicators//incident:Related_Indicator', incident);
    	$.merge(incidentChildren, processChildIndicators(indicators));
    	$.merge(incidentChildren, processChildObservables(xpFind('.//incident:Related_Observables//incident:Related_Observable', incident)));
    	var ttps = xpFind('.//incident:Leveraged_TTPs//incident:Leveraged_TTP', incident);
    	$.merge(incidentChildren, processChildTTPs(ttps));
    	var tas = xpFind('./incident:Attributed_Threat_Actors//incident:Threat_Actor', incident);
    	$.merge(incidentChildren, processChildThreatActors(tas));
    	var coas = xpFind('./incident:COA_Requested', incident);	
    	$.merge(incidentChildren, processChildCoas(coas));
    	coas = xpFind('./incident:COA_Taken', incident);    	
    	$.merge(incidentChildren, processChildCoas(coas));
    	if (incidentChildren.length > 0) {
    		incidentJson["children"] = incidentChildren;
    	}
		if (incidentId != "") {
			$(indicators).each(function (index, indi) {
				addToBottomUpInfo(indiBottomUpInfo, $(xpFindSingle(STIXPattern.indi, indi)), STIXGroupings.incident, incidentId);
			});
			$(ttps).each(function (index, ttp) {
				addToBottomUpInfo(ttpBottomUpInfo, $(xpFindSingle(STIXPattern.ttp, ttp)), STIXGroupings.incident, incidentId);
			});
			$(tas).each(function (index, ta) {
				addToBottomUpInfo(taBottomUpInfo, $(xpFindSingle(STIXPattern.ta, ta)), STIXGroupings.incident, incidentId);
			});
			$(coas).each(function (index, coa) {
				addToBottomUpInfo(coaBottomUpInfo, $(xpFindSingle('./incident:Course_Of_Action', coa)), STIXGroupings.incident, incidentId);
			});
			$(coas).each(function (index, coa) {
				addToBottomUpInfo(coaBottomUpInfo, $(xpFindSingle('./incident:Course_Of_Action', coa)), incidentId);
			});
		} 
    	incidentNodes.push(incidentJson);
		});
    return incidentNodes;
}

function processIndicatorObjs(indiObjs, coaBottomUpInfo, indiBottomUpInfo, ttpBottomUpInfo) {
	var subTypeMap = {};
	var subType = null;
	var indiNodes = [];
	var indiJson = null;
	var indiChildren = [];
	var indiId = null;
	// first, group indicators by indicator type
	$(indiObjs).each(function (index, indi) {	
		subType = "not specified";
		indiId = getObjIdStr(indi);
	    var childJson = createTopDownNode(indiId, STIXType.indi, getBestIndicatorName(indi));
	    var typeNode = xpFindSingle('.//indicator:Type', indi);
	    if (typeNode != null) {
	    	subType = $(typeNode).text();
	    }
	    addBottomUpInfoToChildren(childJson, indiBottomUpInfo);
		indiChildren = childJson["children"];
		var coas = xpFind('.//indicator:Suggested_COA', indi);
		if (indiId != "") {
			$(coas).each(function (index, coa) {
				addIndicatorToBottomUpInfo(coaBottomUpInfo, $(xpFindSingle(STIXPattern.coa, coa)), subType, indiId);
			});
		}
		$.merge(indiChildren, processChildCoas(coas));
		// children are Indicated_TTP, Observables
	    var indicatedTTP = xpFindSingle('.//indicator:Indicated_TTP', indi);
		if (indicatedTTP != null) {
			$.merge(indiChildren, processChildTTPs([indicatedTTP]));
			addIndicatorToBottomUpInfo(ttpBottomUpInfo, $(xpFindSingle(STIXPattern.ttp, indicatedTTP)), subType, indiId);
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

function processObservableObjs(obsObjs) {
	var obsNodes = [];
	var obsJson = null;
	var obsId = null;
	$(obsObjs).each(function (index, obs) {
		obsId = getObjIdStr(obs);
		obsJson = createTopDownNode(obsId, STIXType.obs, getBestObservableName(obs));
		obsNodes.push(obsJson);
	});
	return obsNodes;
}

// TODO - add associated actors
// Note: if a threat actor is specified via Attribution in a campaign, and 
//     the campaign is specified as an associated_campaign in the threat actor,
//     the campaign node will appear twice in the tree under the threat actor
function processThreatActorObjs(taObjs, campaignBottomUpInfo, ttpBottomUpInfo) {
    var taNodes = [];
    var taJson = null;
    var taChildren = null;
    var taId = null;
    $(taObjs).each(function (index, ta) {
    		taId = getObjIdStr(ta);
            taJson = createTopDownNode(taId, STIXType.ta, getBestThreatActorName(ta));
            // children are observed_ttps, associated_campaigns, <Incidents>
            taChildren = [];
            var relatedTTPs = xpFind('.//threat-actor:Observed_TTP', ta);
            $.merge(taChildren, processChildTTPs(relatedTTPs));
            var campaigns = xpFind('.//threat-actor:Associated_Campaign', ta);
            $.merge(taChildren, processChildCampaigns(campaigns));
            if (taChildren.length > 0) {
                taJson["children"] = taChildren;
            }
    		if (taId != "") {
	            $(relatedTTPs).each(function (index, ttp) {
	            	addToBottomUpInfo(ttpBottomUpInfo, $(xpFindSingle(STIXPattern.ttp, ttp)), STIXGroupings.ta, taId);
	            });
	            $(campaigns).each(function (index, ca) {
	            	addToBottomUpInfo(campaignBottomUpInfo, ca, STIXGroupings.ta, taId);
	            });
    		}
            taNodes.push(taJson);
        });
    return taNodes;
}

function processTTPObjs(ttpObjs, etBottomUpInfo) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttpObjs).each(function (index, ttp) {
    		ttpJson = createSingleTTPJson(ttp, etBottomUpInfo);
            ttpNodes.push(ttpJson);
        });
    return ttpNodes;
}

function processChildTTPs(ttps) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttps).each(function (index, ttp) {
	    var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.ttp, ttp)));
            if (idRef != "") {
                ttpJson = createTopDownIdRef(STIXType.ttp, idRef);
            }
            else {  // inline TTP
            	ttpJson = createSingleTTPJson(ttp);
            }
            ttpNodes.push(ttpJson);
	});
    return ttpNodes;
}

function processChildCampaigns(cas) {
    var caNodes = [];
    var caJson = null;
    var caId = null;
    $(cas).each(function (index, ca) {
	    var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.ca, ca)));
            if (idRef != "") {
                caJson = createTopDownIdRef(STIXType.ca, idRef);
            }
            else {  // inline specification
            	caId = getObjIdStr(ca);
            	caJson = createTopDownNode(caId, STIXType.ca, getBestCampaignName(ca));
            }
            caNodes.push(caJson);
	});
    return caNodes;
}

function processChildCoas(coas) {
	var coaNodes = [];
	var coa = null;
	var coaJson = null;
	var coaId = null;
	$(coas).each(function(index, coaObj) {
		coa = xpFindSingle(STIXPattern.coa, coaObj);   
		if (coa == null) {
			coa = xpFindSingle('incident:Course_Of_Action', coaObj);  // used for incident COA_Taken and COA_Requested
		}
		if (coa != null) {
		    var idRef = getObjIdRefStr($(coa));
	        if (idRef != "") {
	        	coaJson = createTopDownIdRef(STIXType.coa, idRef);
	        }	
	        else {
	        	coaId = getObjIdStr(coa);
	        	coaJson = createTopDownNode(coaId, STIXType.coa,getBestCourseOfActionName(coa));
	        }
	        coaNodes.push(coaJson);
		}
	});
	return coaNodes;
}

// TODO first just handle idRefs, need to add inline processing
function processChildThreatActors(actors) {
    var actorNodes = [];
    $(actors).each(function (index, actor) {
	    var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.ta, actor)));
	    if (idRef != "") {
	    	actorNodes.push(createTopDownIdRef(STIXType.ta, idRef));
	    }
	});
    return actorNodes;
}

//TODO first just handle idRefs, need to add inline processing
function processChildIncidents(incidents) {
    var incidentNodes = [];
    $(incidents).each(function (index, incident) {
    	var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.incident, incident)));
		if (idRef != "") {
			incidentNodes.push(createTopDownIdRef(STIXType.incident, idRef));
		}
    });
    return incidentNodes;
}

//TODO first just handle idRefs, need to add inline processing
function processChildIndicators(indis) {
	var indiNodes = [];
	$(indis).each(function (index, indi) {
		var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.indi, indi)));
		if (idRef != "") {
			indiNodes.push(createTopDownIdRef(STIXType.indi, idRef));
		}
	});
    return indiNodes;
}

//TODO first just handle idRefs, need to add inline processing
function processChildObservables(obs) {
    var obsNodes = [];
    $(obs).each(function (index, anObs) {
    	var idRef = getObjIdRefStr(anObs);  // indicators have idRef on them
    	if (idRef == "") {   // other refs are on Observable
    		idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.obs, anObs)));
    	}
    	if (idRef != "") {
    		obsNodes.push(createTopDownIdRef(STIXType.obs, idRef));
    	}
    });
    return obsNodes;
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

var doc = null;

var jsonObj = {"type": "top",
	       "name": "",
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
	var obsObjs = [];
	var taObjs = [];
	var ttpObjs = [];

	var campaignNodes = [];
	var coaNodes = [];
	var etNodes = [];
	var incidentNodes = [];
	var indiNodes = [];
	var obsNodes = [];
	var taNodes = [];
	var ttpNodes = [];
	
	var campaignBottomUpInfo = {};
	var coaBottomUpInfo = {};
	var etBottomUpInfo = {};
	var incidentBottomUpInfo = {};
	var indiBottomUpInfo = {};
	var obsBottomUpInfo = {};
	var taBottomUpInfo = {};
	var ttpBottomUpInfo = {};
	
	var numFiles = 0;
	var topNodeName = "";

	$(inputFiles).each(function (index, f) {
                var xml = null;
                var reader = new FileReader();
                reader.onload = (function(theFile) {
                        return function(e) {
            				if (numFiles == 0) {
            					topNodeName = f.name;
            				}
            				else {
            					topNodeName = topNodeName + "\n" + f.name;
            				}
                            xml = new DOMParser().parseFromString(this.result, "text/xml"); 
                            addXmlDoc(theFile.name,xml);  // adds the new XML file to the drop down menu in the UI
                            doc = xml;
                            // ets are in stixCommon, observables are in cybox, other top level objs are in stix
                            $.merge(campaignObjs, xpFind('//stix:Campaigns/stix:Campaign', xml));
                            $.merge(coaObjs, xpFind('//stix:Courses_Of_Action/stix:Course_Of_Action', xml));
                            $.merge(etObjs, xpFind('//stix:Exploit_Targets/stixCommon:Exploit_Target', xml));
                            $.merge(incidentObjs, xpFind('//stix:Incidents/stix:Incident', xml));
                            $.merge(indiObjs, xpFind('//stix:Indicators/stix:Indicator', xml));
                            $.merge(obsObjs, xpFind('//stix:Observables/cybox:Observable', xml));
                            $.merge(taObjs, xpFind('//stix:Threat_Actors/stix:Threat_Actor', xml));
                            $.merge(ttpObjs, xpFind('//stix:TTPs/stix:TTP', xml));
                            
                            numFiles++;
                            if (numFiles == inputFiles.length) {  // finished last file
                            	jsonObj["name"] = topNodeName;
                                campaignNodes = processCampaignObjs(campaignObjs, incidentBottomUpInfo, indiBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo);
                                coaNodes = processCoaObjs(coaObjs);
                                etNodes = processETObjs(etObjs, coaBottomUpInfo);
                                incidentNodes = processIncidentObjs(incidentObjs, coaBottomUpInfo, indiBottomUpInfo, taBottomUpInfo, ttpBottomUpInfo);
                                indiNodes = processIndicatorObjs(indiObjs, coaBottomUpInfo, indiBottomUpInfo, ttpBottomUpInfo);
                                obsNodes = processObservableObjs(obsObjs);
                                taNodes = processThreatActorObjs(taObjs, campaignBottomUpInfo, ttpBottomUpInfo);
                                ttpNodes = processTTPObjs(ttpObjs, etBottomUpInfo);

                                addBottomUpInfoForNodes(campaignNodes, campaignBottomUpInfo);
                                addBottomUpInfoForNodes(coaNodes, coaBottomUpInfo);
                                addBottomUpInfoForNodes(etNodes, etBottomUpInfo);
                                addBottomUpInfoForNodes(incidentNodes, incidentBottomUpInfo);
                                addBottomUpInfoForNodes(taNodes, taBottomUpInfo);
                                addBottomUpInfoForNodes(ttpNodes, ttpBottomUpInfo);
                                //obsMap = processStixObservables(obsObjs);
                                jsonObj = createTreeJson(jsonObj, campaignNodes, coaNodes, etNodes, incidentNodes, indiNodes, obsNodes, taNodes, ttpNodes);
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

