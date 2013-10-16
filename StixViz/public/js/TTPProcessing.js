// Create basic Json node for a TTP
function createSingleTTPJson(ttp) {
	var ttpId = getObjIdStr(ttp);
    var ttpJson = createTopDownNode(ttpId, STIXType.ttp, getBestTTPName(ttp));
    // children can be INDICATORS (from indicator file), RESOURCES, 
    // BEHAVIORS, or Victim_Targeting
    var ttpChildren = [];
    $.merge(ttpChildren, processTTPBehaviors(ttp));
    $.merge(ttpChildren, processTTPResources(ttp));
    $.merge(ttpChildren, processTTPVictimTargeting(ttp));
    $.merge(ttpChildren, processChildExploitTargets(ttp));
    if (ttpChildren.length > 0) {
        ttpJson["children"] = ttpChildren;
    }
    return ttpJson;
}

// NOT looking for idRefs because these must be specified inline
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
		targets.push(createTopDownNode(null, "VictimTargeting", nameStr));
    }
    return targets;
}

function processChildExploitTargets(ttp) {
	var etNodes = [];
    var etSection = xpFindSingle('.//ttp:Exploit_Targets', ttp);
    if (etSection != null) {
    var targets = xpFind(STIXPattern.et, etSection);
	    $(targets).each(function (index, target) {
	    	var idRef = getObjIdRefStr($(xpFindSingle(STIXPattern.et, target)));
	    	if (idRef != "") {  // target is specified via an idRef
	    		etNodes.push(createTopDownIdRef(STIXType.et, idRef));
	    	}
	    	else {   // target is specified inline
	    		var etNode = createTopDownNode(null, STIXType.et, getBestExploitTargetName(target));
	    		var coas = xpFind('.//et:Potential_COAs', target);
	    		var children = processChildCoas(coas);
	    		if (children.length > 0) {
	    			etNode["children"] = children;
	    		}
	    		etNodes.push(etNode);
	    	}
	    });
    }
    return etNodes;
}

// RESOURCES (cybox observables (URI, ip addresses, ttp:Tool), 
// TODO - NOT looking for idRefs
// TODO - need to add more child types as we see them
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
		    resources.push(createTopDownNode(null, "Observable", resourceName));
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
		    	resources.push(createTopDownNode(null, "Tools", "Tool: " + toolString));
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
		behaviors.push(createTopDownNode(null, 'MalwareBehavior', "Malware Behavior: " + mName));
    }
    var attackPats = xpFind('.//ttp:Behavior//ttp:Attack_Pattern', ttp);
    $(attackPats).each(function (index, pat) {
            behaviors.push(createTopDownNode(null, 'AttackPattern', "Attack Pattern"));
        });
    var exploits = xpFind('.//ttp:Behavior//ttp:Exploits', ttp);
    $(exploits).each(function (index, exploit) {
            behaviors.push(createTopDownNode(null, 'Exploit', ""));
        });
    return behaviors;
}
