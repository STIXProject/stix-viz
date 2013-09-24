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
function createTreeJson(jsonObj, campaignNodes, incidentNodes, taNodes, ttpNodes) {
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
function processCampaignObjs(caObjs) {
    var campaignNodes = [];
    var caJson = null;
    var caChildren = null;
    $(caObjs).each(function (index, ca) {
            caJson = {"type":"campaign"};
            caJson["nodeId"] = getObjIdStr(ca);
            caJson["name"] = getBestCampaignName(ca);
            // children are related_ttps, related_incidents, related_indicators, attribution(threat actors)
            caChildren = [];
            $.merge(caChildren, processChildTTPs(xpFind('.//campaign:Related_TTPs//campaign:Related_TTP', ca)));
            $.merge(caChildren, processChildIncidents(xpFind('.//campaign:Related_Incidents//campaign:Related_Incident', ca)));
            $.merge(caChildren, processChildIndicators(xpFind('.//campaign:Related_Indicators//campaign:Related_Indicator', ca)));
            $.merge(caChildren, processChildThreatActors(xpFind('.//campaign:Attribution//campaign:Attributed_Threat_Actor', ca)));
            if (caChildren.length > 0) {
                caJson["children"] = caChildren;
            }
            campaignNodes.push(caJson);
        });
    return campaignNodes;
}

//TODO add <Campaigns>
function processIncidentObjs(incidentObjs) {
    var incidentNodes = [];
    var incidentJson = null;
    var incidentChildren = null;
    $(incidentObjs).each(function (index, incident) {
            incidentJson = {"type":"Incident"};
            incidentJson["nodeId"] = getObjIdStr(incident);
            incidentJson["name"] = getBestIncidentName(incident);
            // children are related_indicators, related_observables, leverage_TTPs, Attributed_Threat_Actors
            incidentChildren = [];
            $.merge(incidentChildren, processChildIndicator(xpFind('.//incident:Related_Indicators//incident:Related_Indicator', incident)));
            $.merge(incidentChildren, processChildObservables(xpFind('.//incident:Related_Observables//incident:Related_Observable', incident)));
            $.merge(incidentChildren, processChildTTPs(xpFind('.//incident:Leveraged_TTPs//incident:Leveraged_TTP', incident)));
            $.merge(incidentChildren, processChildThreatActors(xpFind('./incident:Attributed_Threat_Actors//incident:Threat_Actor', incident)));
            if (incidentChildren.length > 0) {
                incidentJson["childre"] = incidentChildren;
            }
            incidentNodes.push(incidentJson);
        });
    return incidentNodes;
}

// TODO - add associated actors
function processThreatActorObjs(taObjs) {
    var taNodes = [];
    var taJson = null;
    var taChildren = null;
    $(taObjs).each(function (index, ta) {
            taJson = {"type":"threatActor"};
            taJson["nodeId"] = getObjIdStr(ta);
            taJson["name"] = getBestThreatActorName(ta);
            // children are observed_ttps, associated_campaigns, <Incidents>
            taChildren = [];
            $.merge(taChildren, processChildTTPs(xpFind('.//threat-actor:Observed_TTP', ta)));
            $.merge(taChildren, processChildCampaigns(xpFind('.//threat-actor:Associated_Campaign', ta)));
            //TODO add <Incidents>
            if (taChildren.length > 0) {
                taJson["children"] = taChildren;
            }
            taNodes.push(taJson);
        });
    return taNodes;
}

function createSingleTTPJson(ttp) {
    var ttpJson = {"type":"ObservedTTP"};
    ttpJson["nodeId"] = getObjIdStr(ttp);
    ttpJson["name"] = getBestTTPName(ttp);
    // children can be INDICATORS (from indicator file), RESOURCES, 
    // BEHAVIORS, or Victim_Targeting
    var ttpChildren = [];
    $.merge(ttpChildren, processTTPBehaviors(ttp));
    $.merge(ttpChildren, processTTPResources(ttp));
    $.merge(ttpChildren, processTTPVictimTargeting(ttp));
    $.merge(ttpChildren, processTTPExploitTargets(ttp));
    if (ttpChildren.length > 0) {
        ttpJson["children"] = ttpChildren;
    }
    return ttpJson;
}

//  TODO add <Indicators>, <Campaigns>, <Incidents>, <ThreatActors>
function processTTPObjs(ttpObjs) {
    var ttpNodes = [];
    var ttpJson = null;
    $(ttpObjs).each(function (index, ttp) {
    		ttpJson = createSingleTTPJson(ttp);
            ttpNodes.push(ttpJson);
        });
    return ttpNodes;
}

// TODO - NOT looking for idRefs
function processTTPVictimTargeting(ttp) {
	var nameStr = "";
    var targets = [];
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
		targets.push({"type":"VictimTargeting", "name":nameStr});
    }
    return targets;
}

// TODO - Implement!
function processTTPExploitTargets(ttp) {
    var targets = [];
    return targets;
}

// RESOURCES (cybox observables (URI, ip addresses, ttp:Tool), 
// TODO - NOT looking for idRefs
// TODO - need to add more child types
function processTTPResources(ttp) {
    var id="";
    var resources = [];
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
			resources.push({"type":"Tools", "nodeId":id, "name":toolString});
		    }
		}
    }
    return resources;
}

// BEHAVIORS (malware, attack pattern, exploit)
// TODO - NOT looking for idRefs
// TODO - need to add more child types
function processTTPBehaviors(ttp) {
    var behaviors = [];
    var malware = xpFindSingle('.//ttp:Behavior//ttp:Malware', ttp);
    var mName = "";
    if (malware != null) {
		malware = $(malware).get(0);
		//var instance = $(malware).children('ttp\\:Malware_Instance, Malware_Instance');
		var instance = xpFindSingle('.//ttp:Malware_Instance', malware);
		if (instance != null) {
		    //mName = $(instance).children('ttp\\:Name, Name').text();
			mName = $(xpFindSingle('.//ttp:Name', instance)).text();
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

// TODO first just handle idRefs, need to add inline ttp processing
function processChildTTPs(ttps) {
    var ttpNodes = [];
    $(ttps).each(function (index, ttp) {
	    var idRef = $(xpFindSingle('.//stixCommon:TTP', ttp)).attr('idref');
            if (typeof(idRef) != 'undefined') {
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
	    var idRef = $(xpFindSingle('.//stixCommon:Campaign', ca)).attr('idref');
            if (typeof(idRef) != 'undefined') {
                ttpNodes.push({"type":"Campaign", "nodeIdRef":idRef});
            }
	});
    return caNodes;
}

// TODO first just handle idRefs, need to add inline ttp processing
function processChildThreatActors(actors) {
    var actorNodes = [];
    $(actors).each(function (index, actor) {
	    var idRef = $(xpFindSingle('.//stixCommon:Threat_Actor', actor)).attr('idref');
	    if (typeof(idRef) != 'undefined') {
                actorNodes.push({"type":"threatActor", "nodeIdRef":idRef});
	    }
	});
    return actorNodes;
}

// TODO implement!
function processChildIncidents(incidents) {
    return [];
}

// TODO implement!
function processChildIndicators(indis) {
    return [];
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
        var etNodes = [];
        var incidentNodes = [];
        var indiNodes = [];
        var taNodes = [];
        var ttpNodes = [];
	
	var numFiles = 0;

	$(inputFiles).each(function (index, f) {
                var xml = null;
                var reader = new FileReader();
                reader.onload = (function(theFile) {
                        return function(e) {
                            xml = new DOMParser().parseFromString(this.result, "text/xml"); 
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
                                campaignNodes = processCampaignObjs(campaignObjs);
                                incidentNodes = processIncidentObjs(incidentObjs);
                                
                                taNodes = processThreatActorObjs(taObjs);
                                ttpNodes = processTTPObjs(ttpObjs);

                                //obsMap = processStixObservables(obsObjs);
                                jsonObj = createTreeJson(jsonObj, campaignNodes, incidentNodes, taNodes, ttpNodes);
                                // displays to web page
                                
                                //$('#jsonOutput').text(JSON.stringify(jsonObj, null, 2));  
                                displayTree(JSON.stringify(jsonObj, null, 2));
                            }
                        };
                    }) (f);
                reader.readAsText(f);
	    });
}

