/*
 * Copyright (c) 2013 – The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * This file contains the functionality for determining relationships specified in the xml
 * files loaded.  The top level function is generateTreeJson(inputXMLFiles)
 * 
 * Json is created representing the nodes and links in the tree.   This is passed to 
 * displayTree(json) for display in STIXViz.
 * 
 */

//  add top level 'grouping' nodes with nodes for each entity of that type as children 
function createStixChildren(objNodes, parentName) {
    var allObjJson = [];
    var topChildJson = null;
    if (objNodes.length == 1) {    // if there's only 1 child, don't add a grouping node
    	return objNodes[0];
    }
    else {
	    $(objNodes).each(function (index, objJson) {
		    allObjJson.push(objJson);
		});
	    if (allObjJson.length > 0) {
	    	topChildJson = {"type":parentName, "grouping":true, "children":allObjJson, "linkType":"topDown"};
	    }
	    return topChildJson;
    }
}

// main report JSON creation - add grouping node and children for each top level entity type
// top level nodes: Threat Actor, TTP, Campaign, Incident, Indicator, Exploit, Course of Action, Observable
function createRelationshipJson(jsonObj, topLevelNodes, topNodeName) {
    var reportChildren = [];
    var topLevelChild = null;

    topLevelChild = createStixChildren(topLevelNodes['campaignNodes'], STIXGroupings.ca);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(topLevelNodes['coaNodes'], STIXGroupings.coa);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(topLevelNodes['etNodes'], STIXGroupings.et);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(topLevelNodes['incidentNodes'], STIXGroupings.incident);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(topLevelNodes['indiNodes'], STIXGroupings.indi);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(topLevelNodes['obsNodes'], STIXGroupings.obs);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }    
    topLevelChild = createStixChildren(topLevelNodes['taNodes'], STIXGroupings.ta);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }
    topLevelChild = createStixChildren(topLevelNodes['ttpNodes'], STIXGroupings.ttp);
    if (topLevelChild != null) {
        reportChildren.push(topLevelChild);
    }

	jsonObj["name"] = topNodeName;
    jsonObj['children'] = reportChildren;
    return jsonObj;
}

//TODO add associated campaigns
function processCampaignObjs(caObjs, allBottomUpInfo) {
    var campaignNodes = [];
    var caJson = null;
    var caChildren = null;
    var caId = "";
    $(caObjs).each(function (index, ca) {
    		caId = getObjIdStr(ca);
            caJson = createTopDownNode(caId, STIXType.ca, getBestCampaignName(ca), "");
            // children are related_ttps, related_incidents, related_indicators, attribution(threat actors)
            caChildren = [];
            var relatedTTPs = xpFind('.//campaign:Related_TTPs//campaign:Related_TTP', ca);
            $.merge(caChildren, processChildTTPs(relatedTTPs, 'campaign:Related_TTP'));
            var incidents = xpFind('.//campaign:Related_Incidents//campaign:Related_Incident', ca);
            $.merge(caChildren, processChildIncidents(incidents, 'campaign:Related_Incident'));
            var indicators = xpFind('.//campaign:Related_Indicators//campaign:Related_Indicator', ca);
            $.merge(caChildren, processChildIndicators(indicators, 'campaign:Related_Indicator'));
            var attributedActors = xpFind('.//campaign:Attribution//campaign:Attributed_Threat_Actor', ca);
            $.merge(caChildren, processChildThreatActors(attributedActors, 'campaign:Attributed_Threat_Actor'));
            var associatedCampaigns = xpFind('.//campaign:Associated_Campaign', ca);
            $.merge(caChildren, processChildCampaigns(associatedCampaigns, 'campaign:Associated_Campaign'));
            if (caChildren.length > 0) {
                caJson["children"] = caChildren;
            }
        	if (caId != "") {
	            $(relatedTTPs).each(function (index, ttp) {
	            	addToBottomUpInfo(allBottomUpInfo['ttpBottomUpInfo'], $(xpFindSingle(STIXPattern.ttp, ttp)), STIXGroupings.ca, caId);
	            });
	            $(incidents).each(function (index, incident) {
	            	addToBottomUpInfo(allBottomUpInfo['incidentBottomUpInfo'], $(xpFindSingle(STIXPattern.incident, incident)), STIXGroupings.ca, caId);
	            });
	            $(indicators).each(function (index, indi) {
	            	addToBottomUpInfo(allBottomUpInfo['indiBottomUpInfo'], $(xpFindSingle(STIXPattern.indi, indi)), STIXGroupings.ca, caId);
	            });
	            $(attributedActors).each(function (index, actor) {
	            	addToBottomUpInfo(allBottomUpInfo['taBottomUpInfo'], $(xpFindSingle(STIXPattern.ta, actor)), STIXGroupings.ca, caId);
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
		coaJson = createTopDownNode(coaId, STIXType.coa, getBestCourseOfActionName(coa), "");
		var relatedCoas = xpFind('.//coa:Related_COA', coa);
		var coaChildren = processChildCoas(relatedCoas, 'coa:Related_COA');
		coaJson["children"] = coaChildren;
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
		etJson = createTopDownNode(etId, STIXType.et, getBestExploitTargetName(et), "");
        var coas = xpFind('.//et:Potential_COA', et);
		etChildren = processChildCoas(coas, 'et:Potential_COA');
		var ets = xpFind('.//et:Related_Exploit_Target', et);
		$.merge(etChildren, processChildExploitTargets(ets, 'et:Related_Exploit_Target'));
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

function processIncidentObjs(incidentObjs, allBottomUpInfo) {
    var incidentNodes = [];
    var incidentJson = null;
    var incidentChildren = null;
    var incidentId = null;
    $(incidentObjs).each(function (index, incident) {
    	incidentId = getObjIdStr(incident);
    	incidentJson = createTopDownNode(incidentId, STIXType.incident, getBestIncidentName(incident), "");
    	// children are related_indicators, related_observables, leverage_TTPs, Attributed_Threat_Actors
    	incidentChildren = [];
    	var indicators = xpFind('.//incident:Related_Indicators//incident:Related_Indicator', incident);
    	$.merge(incidentChildren, processChildIndicators(indicators, 'incident:Related_Indicator'));
    	var observables = xpFind('.//incident:Related_Observables//incident:Related_Observable', incident);
    	$.merge(incidentChildren, processChildObservables(observables, 'incident:Related_Observable'));
    	var ttps = xpFind('.//incident:Leveraged_TTPs//incident:Leveraged_TTP', incident);
    	$.merge(incidentChildren, processChildTTPs(ttps, 'incident:Leveraged_TTP'));
    	var tas = xpFind('./incident:Attributed_Threat_Actors//incident:Threat_Actor', incident);
    	$.merge(incidentChildren, processChildThreatActors(tas, 'incident:Threat_Actor'));
    	var coas = xpFind('./incident:COA_Requested', incident);	
    	$.merge(incidentChildren, processChildCoas(coas, 'incident:COA_Requested'));
    	coas = xpFind('./incident:COA_Taken', incident);    	
    	$.merge(incidentChildren, processChildCoas(coas, 'incident:COA_Taken'));
    	var relatedIncidents = xpFind('./incident:Related_Incident', incident);
    	$.merge(incidentChildren, processChildIncidents(relatedIncidents, 'incident:Related_Incident'));
    	if (incidentChildren.length > 0) {
    		incidentJson["children"] = incidentChildren;
    	}
		if (incidentId != "") {
			$(indicators).each(function (index, indi) {
				addToBottomUpInfo(allBottomUpInfo['indiBottomUpInfo'], $(xpFindSingle(STIXPattern.indi, indi)), STIXGroupings.incident, incidentId);
			});
			$(observables).each(function (index, obs) {
				addToBottomUpInfo(allBottomUpInfo['obsBottomUpInfo'], $(xpFindSingle(STIXPattern.obs, obs)), STIXGroupings.incident, incidentId);
			});
			$(ttps).each(function (index, ttp) {
				addToBottomUpInfo(allBottomUpInfo['ttpBottomUpInfo'], $(xpFindSingle(STIXPattern.ttp, ttp)), STIXGroupings.incident, incidentId);
			});
			$(tas).each(function (index, ta) {
				addToBottomUpInfo(allBottomUpInfo['taBottomUpInfo'], $(xpFindSingle(STIXPattern.ta, ta)), STIXGroupings.incident, incidentId);
			});
			$(coas).each(function (index, coa) {
				addToBottomUpInfo(allBottomUpInfo['coaBottomUpInfo'], $(xpFindSingle('./incident:Course_Of_Action', coa)), STIXGroupings.incident, incidentId);
			});
			$(coas).each(function (index, coa) {
				addToBottomUpInfo(allBottomUpInfo['coaBottomUpInfo'], $(xpFindSingle('./incident:Course_Of_Action', coa)), incidentId);
			});
		} 
    	incidentNodes.push(incidentJson);
		});
    return incidentNodes;
}

// TODO add related_indicators
function processIndicatorObjs(indiObjs, allBottomUpInfo) {
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
	    var childJson = createTopDownNode(indiId, STIXType.indi, getBestIndicatorName(indi), "");
	    var typeNode = xpFindSingle('.//indicator:Type', indi);
	    if (typeNode != null) {
	    	subType = $(typeNode).text();
	    }
	    addBottomUpInfoToChildren(childJson, allBottomUpInfo['indiBottomUpInfo']);
		indiChildren = childJson["children"];
		var coas = xpFind('.//indicator:Suggested_COA', indi);
		$.merge(indiChildren, processChildCoas(coas, 'indicator:Suggested_COA'));
		// children are Indicated_TTP, Observables
	    var indicatedTTPs = xpFind('.//indicator:Indicated_TTP', indi);
		$.merge(indiChildren, processChildTTPs(indicatedTTPs, 'indicator:Indicated_TTP'));
		var observables = xpFind('.//indicator:Observable', indi);
		$.merge(indiChildren, processChildObservables(observables, 'indicator:Observable'));
		var relatedIndicators = xpFind('.//indicator:Related_Indicator', indi);
		$.merge(indiChildren, processChildIndicators(relatedIndicators, 'indicator:Related_Indicator'));
		if (indiId != "") {
			$(coas).each(function (index, coa) {
				addIndicatorToBottomUpInfo(allBottomUpInfo['coaBottomUpInfo'], $(xpFindSingle(STIXPattern.coa, coa)), subType, indiId);
			});
			$(indicatedTTPs).each(function (index, indicatedTTP) {
				addIndicatorToBottomUpInfo(allBottomUpInfo['ttpBottomUpInfo'], $(xpFindSingle(STIXPattern.ttp, indicatedTTP)), subType, indiId);
			});
			$(observables).each(function (index, obs) {
				addIndicatorToBottomUpInfo(allBottomUpInfo['obsBottomUpInfo'], obs, subType, indiId);
			});
		}
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
	    indiJson = {"type": STIXType.indi, "grouping":true, "subtype":subType, "children":children, "linkType":"topDown"};
	    indiNodes.push(indiJson);
	});
    return indiNodes;
}

// NOT including sub-observables for now
function processObservableObjs(obsObjs) {
	var obsNodes = [];
	var obsJson = null;
	var obsId = null;
	$(obsObjs).each(function (index, obs) {
		obsId = getObjIdStr(obs);
		obsJson = createTopDownNode(obsId, STIXType.obs, getBestObservableName(obs), "");
		obsNodes.push(obsJson);
	});
	return obsNodes;
}

// TODO - add associated actors
// Note: if a threat actor is specified via Attribution in a campaign, and 
//     the campaign is specified as an associated_campaign in the threat actor,
//     the campaign node will appear twice in the tree under the threat actor
function processThreatActorObjs(taObjs, allBottomUpInfo) {
    var taNodes = [];
    var taJson = null;
    var taChildren = null;
    var taId = null;
    $(taObjs).each(function (index, ta) {
    		taId = getObjIdStr(ta);
            taJson = createTopDownNode(taId, STIXType.ta, getBestThreatActorName(ta), "");
            // children are observed_ttps, associated_campaigns, <Incidents>
            taChildren = [];
            var relatedTTPs = xpFind('.//threat-actor:Observed_TTP', ta);
            $.merge(taChildren, processChildTTPs(relatedTTPs, 'threat-actor:Observed_TTP'));
            var campaigns = xpFind('.//threat-actor:Associated_Campaign', ta);
            $.merge(taChildren, processChildCampaigns(campaigns, 'threat-actor:Associated_Campaign'));
            var relatedActors = xpFind('.//threat-actor:Associated_Actor', ta);
            $.merge(taChildren, processChildThreatActors(relatedActors, 'threat-actor:Associated_Actor'));
            if (taChildren.length > 0) {
                taJson["children"] = taChildren;
            }
    		if (taId != "") {
	            $(relatedTTPs).each(function (index, ttp) {
	            	addToBottomUpInfo(allBottomUpInfo['ttpBottomUpInfo'], $(xpFindSingle(STIXPattern.ttp, ttp)), STIXGroupings.ta, taId);
	            });
	            $(campaigns).each(function (index, ca) {
	            	addToBottomUpInfo(allBottomUpInfo['campaignBottomUpInfo'], ca, STIXGroupings.ta, taId);
	            });
    		}
            taNodes.push(taJson);
        });
    return taNodes;
}

// createSingleTTPJson used here, and for processing inline TTPs found as children of other objs
function processTTPObjs(ttpObjs, etBottomUpInfo) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttpObjs).each(function (index, ttp) {
    	 ttpJson = createSingleTTPJson(ttp, etBottomUpInfo, "");
         ttpNodes.push(ttpJson);
        });
    return ttpNodes;
}

function processChildTTPs(ttps, relationship) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttps).each(function (index, ttp) {
	    var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.ttp, ttp)));
            if (idRef != "") {
            	if (relationship == 'ttp:Related_TTP') {
            		ttpJson = createSiblingIdRef(STIXType.ttp, idRef, relationship);
            	}
            	else {
            		ttpJson = createTopDownIdRef(STIXType.ttp, idRef, relationship);
            	}
            }
            else {  // inline TTP
            	ttpJson = createSingleTTPJson(ttp, relationship);
            }
            ttpNodes.push(ttpJson);
	});
    return ttpNodes;
}

function processChildCampaigns(cas, relationship) {
    var caNodes = [];
    var caJson = null;
    var caId = null;
    $(cas).each(function (index, ca) {
	    var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.ca, ca)));
            if (idRef != "") {
            	if (relationship == 'campaign:Associated_Campaign') {
            		caJson = createSiblingIdRef(STIXType.ca, idRef, relationship);
            	}
            	else {
            		caJson = createTopDownIdRef(STIXType.ca, idRef, relationship);
            	}
            }
            else {  // inline specification
            	caId = getObjIdStr(ca);
            	if (relationship == 'campaign:Associated_Campaign') {
            		caJson = createSiblingNode(caId, STIXType.ca, getBestCampaignName(ca), relationship);
            	}
            	else {
            		caJson = createTopDownNode(caId, STIXType.ca, getBestCampaignName(ca), relationship);
            	}
            }
            caNodes.push(caJson);
	});
    return caNodes;
}

function processChildCoas(coas, relationship) {
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
	        	if (relationship == 'coa:Related_COA') {
	        		coaJson = createSiblingIdRef(STIXType.coa, idRef, relationship);
	        	}
	        	else {
	        		coaJson = createTopDownIdRef(STIXType.coa, idRef, relationship);
	        	}
	        }	
	        else {
	        	coaId = getObjIdStr(coa);
	        	if (relationship == 'coa:Related_COA') {
	        		coaJson = createSiblingNode(coaId, STIXType.coa,getBestCourseOfActionName(coa), relationship);
	        	}
	        	else {
	        		coaJson = createTopDownNode(coaId, STIXType.coa,getBestCourseOfActionName(coa), relationship);
	        	}
	        }
	        coaNodes.push(coaJson);
		}
	});
	return coaNodes;
}

function processChildExploitTargets(ets, relationship) {
	var etNodes = [];
	$(ets).each(function(index, etObj) {
		var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.et, etObj)));
	    if (idRef != "") {
	    	if (relationship == 'et:Related_Exploit_Target') {
	    		etNodes.push(createSiblingIdRef(STIXType.et, idRef, relationship));
	    	}
	    	else {
	    		etNodes.push(createTopDownIdRef(STIXType.et, idRef, relationship));
	    	}
	    }
	});
    return etNodes;
}

// TODO first just handle idRefs, need to add inline processing
function processChildThreatActors(actors, relationship) {
    var actorNodes = [];
    $(actors).each(function (index, actor) {
	    var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.ta, actor)));
	    if (idRef != "") {
	    	if (relationship == 'threat-actor:Associated_Actor') {
	    		actorNodes.push(createSiblingIdRef(STIXType.ta, idRef, relationship));
	    	}
	    	else {
	    		actorNodes.push(createTopDownIdRef(STIXType.ta, idRef, relationship));
	    	}
	    }
	});
    return actorNodes;
}

//TODO first just handle idRefs, need to add inline processing
function processChildIncidents(incidents, relationship) {
    var incidentNodes = [];
    $(incidents).each(function (index, incident) {
    	var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.incident, incident)));
		if (idRef != "") {
			if (relationship == 'incident:Related_Incident') {
				incidentNodes.push(createSiblingIdRef(STIXType.incident, idRef, relationship));
			}
			else {
				incidentNodes.push(createTopDownIdRef(STIXType.incident, idRef, relationship));
			}
		}
    });
    return incidentNodes;
}

//TODO first just handle idRefs, need to add inline processing
function processChildIndicators(indis, relationship) {
	var indiNodes = [];
	$(indis).each(function (index, indi) {
		var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.indi, indi)));
		if (idRef != "") {
			if (relationship == 'indicator:Related_Indicator') {
				indiNodes.push(createSiblingIdRef(STIXType.indi, idRef, relationship));
			}
			else {
				indiNodes.push(createTopDownIdRef(STIXType.indi, idRef, relationship));
			}
		}
	});
    return indiNodes;
}

function processChildObservables(observables, relationship) {
    var obsNodes = [];
    var obsId = null;
    $(observables).each(function (index, obs) {
    	var idRef = getObjIdRefStr(obs);  // indicators have idRef on them
    	if (idRef == "") {   // other refs are on Observable
    		idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.obs, obs)));
    	}
    	if (idRef != "") {
    		obsNodes.push(createTopDownIdRef(STIXType.obs, idRef, relationship));
    	}
    	else {
    		obsId = getObjIdStr(obs);
    		obsNodes.push(createTopDownNode(obsId, STIXType.obs,getBestObservableName(obs), relationship));
    	}
    });
    return obsNodes;
}

/** 
 * Top level entities are gathered from each xml file
 * 
*/
function gatherRelationshipTopLevelObjs(xml, topLevelObjs) {
	
	if (topLevelObjs == null) {
		topLevelObjs = {};
		topLevelObjs['campaignObjs'] = [];
		topLevelObjs['coaObjs'] = [];
		topLevelObjs['etObjs'] = [];
		topLevelObjs['incidentObjs'] = [];
		topLevelObjs['indiObjs'] = [];
		topLevelObjs['obsObjs'] = [];
		topLevelObjs['taObjs'] = [];
		topLevelObjs['ttpObjs'] = [];
	}
	
	/*
	 * 
	else {
		campaignObjs = topLevelObjs['campaignObjs'];
		coaObjs = topLevelObjs['coaObjs'];
		etObjs = topLevelObjs['etObjs'];
		incidentObjs = topLevelObjs['incidentObjs'];
	}
	*/
	
    // first collect top level components from all files
    // ets are in stixCommon, observables are in cybox, other top level objs are in stix
    $.merge(topLevelObjs['campaignObjs'], xpFind('//stix:Campaigns/stix:Campaign', xml));
    $.merge(topLevelObjs['coaObjs'], xpFind('//stix:Courses_Of_Action/stix:Course_Of_Action', xml));
    $.merge(topLevelObjs['etObjs'], xpFind('//stix:Exploit_Targets/stixCommon:Exploit_Target', xml));
    $.merge(topLevelObjs['incidentObjs'], xpFind('//stix:Incidents/stix:Incident', xml));
    $.merge(topLevelObjs['indiObjs'], xpFind('//stix:Indicators/stix:Indicator', xml));
    $.merge(topLevelObjs['obsObjs'], xpFind('//stix:Observables/cybox:Observable', xml));
    $.merge(topLevelObjs['taObjs'], xpFind('//stix:Threat_Actors/stix:Threat_Actor', xml));
    $.merge(topLevelObjs['ttpObjs'], xpFind('//stix:TTPs/stix:TTP', xml));
    
    return topLevelObjs;
}

/*
 * Json nodes are created for each top level entity.
 * Next, bottom up references are added to the nodes
 * 
 */
function processTopLevelObjects(topLevelObjs, topLevelNodes) {
	if (topLevelNodes == null) {
		topLevelNodes = {};
		var campaignNodes = [];
		var coaNodes = [];
		var etNodes = [];
		var incidentNodes = [];
		var indiNodes = [];
		var obsNodes = [];
		var taNodes = [];
		var ttpNodes = [];	
	}
	var allBottomUpInfo = {};
	allBottomUpInfo['campaignBottomUpInfo'] = {};
	allBottomUpInfo['coaBottomUpInfo'] = {};
	allBottomUpInfo['etBottomUpInfo'] = {};
	allBottomUpInfo['incidentBottomUpInfo'] = {};
	allBottomUpInfo['indiBottomUpInfo'] = {};
	allBottomUpInfo['obsBottomUpInfo'] = {};
	allBottomUpInfo['taBottomUpInfo'] = {};
	allBottomUpInfo['ttpBottomUpInfo'] = {};

	campaignNodes = processCampaignObjs(topLevelObjs['campaignObjs'], allBottomUpInfo);
	coaNodes = processCoaObjs(topLevelObjs['coaObjs']);
	etNodes = processETObjs(topLevelObjs['etObjs'], allBottomUpInfo['coaBottomUpInfo']);
	incidentNodes = processIncidentObjs(topLevelObjs['incidentObjs'], allBottomUpInfo);
	indiNodes = processIndicatorObjs(topLevelObjs['indiObjs'], allBottomUpInfo);
	obsNodes= processObservableObjs(topLevelObjs['obsObjs']);
	taNodes = processThreatActorObjs(topLevelObjs['taObjs'], allBottomUpInfo);
	ttpNodes = processTTPObjs(topLevelObjs['ttpObjs'], allBottomUpInfo['etBottomUpInfo']);
	
	// after processing object, add children collected from idRefs
	addBottomUpInfoForNodes(campaignNodes, allBottomUpInfo['campaignBottomUpInfo']);
	addBottomUpInfoForNodes(coaNodes, allBottomUpInfo['coaBottomUpInfo']);
	addBottomUpInfoForNodes(etNodes, allBottomUpInfo['etBottomUpInfo']);
	addBottomUpInfoForNodes(incidentNodes, allBottomUpInfo['incidentBottomUpInfo']);
	addBottomUpInfoForNodes(obsNodes, allBottomUpInfo['obsBottomUpInfo']);
	addBottomUpInfoForNodes(taNodes, allBottomUpInfo['taBottomUpInfo']);
	addBottomUpInfoForNodes(ttpNodes, allBottomUpInfo['ttpBottomUpInfo']);
	
	topLevelNodes['campaignNodes'] = campaignNodes;
	topLevelNodes['coaNodes'] = coaNodes;
	topLevelNodes['etNodes'] = etNodes;
	topLevelNodes['incidentNodes'] = incidentNodes;
	topLevelNodes['indiNodes'] = indiNodes;
	topLevelNodes['obsNodes'] = obsNodes;
	topLevelNodes['taNodes'] = taNodes;
	topLevelNodes['ttpNodes'] = ttpNodes;
	
	return topLevelNodes;
}




