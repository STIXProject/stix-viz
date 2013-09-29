// Collect child relationships for TTP from nodes that show it as a child
function addToTTPBottomInfo(ttpBottomUpInfo, ttpParent, parentType, parentId) {
	var parentTypeMap = null;
	var ttpId = "";
	var ttp = $(xpFindSingle('.//stixCommon:TTP', ttpParent));
	if (ttp != null) {
		ttpId = getObjIdRefStr(ttp);
	}
	if (ttpId != "") {  // track child info for this ttp
		if (typeof(ttpBottomUpInfo[ttpId]) == 'undefined') {  // first time seeing ttpId
			parentTypeMap = {};
		}
		else {
			parentTypeMap = ttpBottomUpInfo[ttpId];
		}
		parentTypeMap = addToParentTypeMap(parentTypeMap, parentType, parentId);
		ttpBottomUpInfo[ttpId] = parentTypeMap;
	}
}

// Add children to ttpJson from bottomUp relationships
function addTTPBottomUpInfo(ttpJson, bottomUpInfo) {
	var nodeId = ttpJson.nodeId;
	var info = bottomUpInfo[nodeId];
	if (typeof(ttpJson["children"]) == 'undefined') {
		ttpJson["children"] = [];
	}
	if (typeof(info) != 'undefined') {
		var indiTypeMap = info.indicators;
		if (typeof(indiTypeMap) != 'undefined') {
			$.map(indiTypeMap, function(indiList, subType) {
				var subTypeNode = {"type":"Indicator", "name":subType};
				var children = [];
				$(indiList).each(function (index, indiId) {
					children.push({"type":"Indicator", "nodeIdRef":indiId});
				});
				subTypeNode["children"] = children;
				(ttpJson.children).push(subTypeNode);
			});
		}
		var cas = info.campaigns;
		if (typeof(cas) != 'undefined') {
			$(cas).each(function (index, caId) {
				(ttpJson.children).push({"type":"campaign", "nodeIdRef":caId});		
			});
		}
		var tas = info.threatActors;
		if (typeof(tas) != 'undefined') {
			$(tas).each(function (index, actorId) {
				(ttpJson.children).push({"type":"threatActor", "nodeIdRef":actorId});
			});
		}
	}
	return ttpJson;
}

// Create basic Json node for a TTP
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

//TODO - NOT looking for idRefs
function processTTPVictimTargeting(ttp) {
	var nameStr = "";
    var targets = [];
    // Victim_Targeting
    var victimTarget = xpFindSingle('.//ttp:Victim_Targeting', ttp);
    if (victimTarget != null) {
    	var identity = xpFindSingle('.//ttp:Identity', victimTarget);
    	if (identity != null) {
    		nameStr = getBestIdentityName(identity);
    	}
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
		    	resources.push({"type":"Tools", "nodeId":id, "name":"Tool: " + toolString});
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
			mName = concatenateNames($(xpFind('.//ttp:Name', instance)));
		}
		behaviors.push({"type":'MalwareBehavior', "name":"Malware Behavior: " + mName});
    }
    var attackPats = xpFind('.//ttp:Behavior//ttp:Attack_Pattern', ttp);
    $(attackPats).each(function (index, pat) {
            behaviors.push({"type":'AttackPattern', "name":"Attack Pattern"});
        });
    var exploits = xpFind('.//ttp:Behavior//ttp:Exploits', ttp);
    $(exploits).each(function (index, exploit) {
            behaviors.push({"type":'Exploit', "name":""});
        });
    return behaviors;
}
