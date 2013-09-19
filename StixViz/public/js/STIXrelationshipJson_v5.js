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

function addSTIXChildren(reportChildren, objMap, parentName) {
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
function createTreeJson(jsonObj, taMap, ttpMap, campaignMap, indicatorMap, incidentMap) {
    var reportChildren = [];
    var mergedIndicatorList = [];
    var mergedIndicatorMap = {};
    addSTIXChildren(reportChildren, campaignMap, 'Campaigns');
    addSTIXChildren(reportChildren, taMap, 'ThreatActors');
    addSTIXChildren(reportChildren, ttpMap, 'TTPs');
    addSTIXChildren(reportChildren, incidentMap, 'Incidents');
    $.map(indicatorMap, function(indicators, ttpId) {  // each in
            $(indicators).each(function(index, indi) {
                    if (indi.type == 'Indicator') {
                        if (typeof(mergedIndicatorMap[indi.subtype]) === 'undefined') {
                            mergedIndicatorMap[indi.subtype] = indi;
                        }
                        else {  // already have a node of this subtype, just add new children
                            $.merge(mergedIndicatorMap[indi.subtype].children, indi.children);
                        }
                    }
                });
	});
    $.map(mergedIndicatorMap, function(node, subtype) {
            mergedIndicatorList.push(node);
        });
    if (mergedIndicatorList.length > 0) {
	reportChildren.push({"type":'Indicators', "children":mergedIndicatorList});
    }

    // SRL - add Incident, Exploit, Course of Action
    jsonObj['children'] = reportChildren;
    return jsonObj;
}

function createSingleThreatActorJson(ta, id, indicatorMap, ttpMap, taMap, incidentMap) {
    var actorJson = {"type":"threatActor"};
    actorJson["nodeId"] = getObjIdStr(ta);
    actorJson["name"] = getBestThreatActorName(ta);
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

function createTTPObjMap(ttpObjs) {
    var ttpObjMap = {};
    $(ttpObjs).each(function(index, ttp) {
            var id = getObjIdStr(ttp);
            ttpObjMap[id] = ttp;
        });
    return ttpObjMap;
}

// if indicatorMap is null, it means json is going to be used
// as child of an indicator - don't want circular references
function createSingleTTPJson(ttp, id, indicatorMap, ttpMap, taMap, incidentMap) {
    var ttpChildren = [];
    var ttpName = getBestTTPName(ttp);
    var id = getObjIdStr(ttp);
    if (indicatorMap != null) {
        ttpChildren = getTTPChildren(ttp, indicatorMap[id]);
    }
    var ttpJson = {"type": "ObservedTTP",
    		"nodeId": id,
		   "name": ttpName};
    if (ttpChildren.length > 0) {
    	ttpJson["children"] = ttpChildren;
    }
    return ttpJson;
}

function createSingleCampaignJson(ca, id, indicatorMap, ttpMap, taMap, incidentMap) {
    var campaignJson = {"type":"campaign"};
    campaignJson["nodeId"] = getObjIdStr(ca);
    campaignJson["name"] = getBestCampaignName(ca);
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

function createSingleIncidentJson(incident, id, indicatorMap, ttpMap, taMap, incidentMap) {
	var incidentJson = {"type":"Incident"};
	incidentJson["nodeId"] = getObjIdStr(incident);
	incidentJson["name"] = getBestIncidentName(incident);
	//TODO fill in children here
	return incidentJson;
}

function addTTPChildJson(childList, ttp, ttpMap, indicatorMap) {
    var idRef = $(xpFindSingle('.//stixCommon:TTP', ttp)).attr('idref');
    if (typeof(idRef) != 'undefined') {   // TTP info is in the TTP section
    	childList.push(ttpMap[idRef]);
    }
    else {  // TTP info is inline, need to process
		var id = getObjIdStr(ttp);
		var inlineTTP = createSingleTTPJson(ttp, id, indicatorMap, null, null, null);
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
	var id="";
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
			resources.push({"type":"Tools", "nodeId":id, "name":toolString});
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

function createJsonMapForObjs(objs, singleJsonFnName, indicatorMap, ttpMap, taMap, incidentMap) {
    var objMap = {};
    //Create the function
    var singleJsonfn = window[singleJsonFnName];

    $(objs).each(function(index, obj) {
	    var id = getObjIdStr(obj);
	    objMap[id] = singleJsonfn(obj, id, indicatorMap, ttpMap, taMap, incidentMap);
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
function processStixIndicators(indicators, ttpObjMap) {
    var indicatorMap = {};
    var ttpIndiMap = {};
    var indiTTPMap = {};
    //first sort indis by indicated ttp
    $(indicators).each(function (index, indi) {
    	var indiId = getObjIdStr(indi);
    	var ttpId = "";
    	var ttp = xpFindSingle('.//indicator:Indicated_TTP', indi);
    	ttpObj = xpFindSingle('.//stixCommon:TTP', ttp);
    	if (ttpObj != null) {
    		ttpId = $(ttpObj).attr('idref');
    	}
    	// inline ttps will have an undefined val for ttpId
    	// ok for now
	    if (typeof(ttpIndiMap[ttpId]) == 'undefined') {
	    	ttpIndiMap[ttpId] = [indi];
	    }
	    else {
	    	ttpIndiMap[ttpId].push(indi);
	    }
	    if (typeof(ttpId) != 'undefined') {   // don't add for inline ttps
		    if (typeof(indiTTPMap[indiId]) === 'undefined') {
		    	indiTTPMap[indiId] = [ttpId];
		    }
		    else {
		    	indiTTPMap[indiId].push(ttpId);
		    }
	    }
	});

    // now create indicator Json for each ttp - one entry per subType
    //  with child nodes for each indicator of that subtype
    $.map(ttpIndiMap, function(indiObjs, ttpId) {
            var subTypeMap = {};
	    var subType = "not specified";
	    indicatorMap[ttpId] = [];
	    // sort indiObjs by subtype
	    $(indiObjs).each(function(index, indi) {
	    	var id = getObjIdStr(indi);
	    	var indiName = getBestIndicatorName(indi);
		    var typeNode = xpFindSingle('.//indicator:Type', indi);
		    if (typeNode != null) {
		    	subType = $(typeNode).text();
		    }
		    var childNode = {"type":"Indicator", "nodeId":id, "name":indiName};
		    var indicatedTTPs = indiTTPMap[getObjIdStr(indi)];
		    var indiChildren = [];
		    $(indicatedTTPs).each(function(index, ttpid) { 
		    	indiChildren.push(createSingleTTPJson(ttpObjMap[ttpid], null, null, null, null, null));
		    });
		    childNode["children"] = indiChildren;
		    if (typeof(subTypeMap[subType]) == 'undefined') {
		    	subTypeMap[subType] = [childNode];
		    }
		    else {
		    	subTypeMap[subType].push(childNode);
		    }
		});
	    // for each subtype add a child indicator node
	    $.map(subTypeMap, function(children, subType) {
		    var indiJson = {"type":"Indicator", "subtype":subType, "children":children};
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
	// var obsObjs = [];
	var campaignObjs = [];
	var incidentObjs = [];
	var ttpObjMap = [];

	var taMap = {};
	var ttpMap = {};
	var indicatorMap = {};
	// var obsMap = {};
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
                            $.merge(incidentObjs, xpFind('//stix:Incidents/stix:Incident', xml));
                            
                            numFiles++;
                            if (numFiles == inputFiles.length) {  // finished last file
                                //obsMap = processStixObservables(obsObjs);
                                ttpObjMap = createTTPObjMap(ttpObjs);  // need this to use in indicator processing
                                indicatorMap = processStixIndicators(indiObjs, ttpObjMap);
                                ttpMap = createJsonMapForObjs(ttpObjs, 'createSingleTTPJson', indicatorMap, ttpMap, taMap, incidentMap);
                                taMap = createJsonMapForObjs(taObjs, 'createSingleThreatActorJson', indicatorMap, ttpMap, taMap, incidentMap);
                                campaignMap = createJsonMapForObjs(campaignObjs, 'createSingleCampaignJson', indicatorMap, ttpMap, taMap, incidentMap);
                                incidentMap = createJsonMapForObjs(incidentObjs, 'createSingleIncidentJson', indicatorMap, ttpMap, taMap, incidentMap);
                                jsonObj = createTreeJson(jsonObj, taMap, ttpMap, campaignMap, indicatorMap, incidentMap);
                                // displays to web page
                                
                                //$('#jsonOutput').text(JSON.stringify(jsonObj, null, 2));  
                                displayTree(JSON.stringify(jsonObj, null, 2));
                            }
                        };
                    }) (f);
                reader.readAsText(f);
	    });
}

