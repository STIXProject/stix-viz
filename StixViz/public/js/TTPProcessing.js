// Create basic Json node for a TTP
function createSingleTTPJson(ttp) {
    var ttpJson = {"type":"ObservedTTP"};
    ttpJson["nodeId"] = getObjIdStr(ttp);
    ttpJson["name"] = getBestTTPName(ttp);
    ttpJson["linkType"] = "topDown";
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
		targets.push({"type":"VictimTargeting", "name":nameStr, "linkType":"topDown"});
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
		    resources.push({"type":"Observable", "name":resourceName, "linkType":"topDown"});
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
		    	resources.push({"type":"Tools", "nodeId":id, "name":"Tool: " + toolString, "linkType":"topDown"});
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
		behaviors.push({"type":'MalwareBehavior', "name":"Malware Behavior: " + mName, "linkType":"topDown"});
    }
    var attackPats = xpFind('.//ttp:Behavior//ttp:Attack_Pattern', ttp);
    $(attackPats).each(function (index, pat) {
            behaviors.push({"type":'AttackPattern', "name":"Attack Pattern", "linkType":"topDown"});
        });
    var exploits = xpFind('.//ttp:Behavior//ttp:Exploits', ttp);
    $(exploits).each(function (index, exploit) {
            behaviors.push({"type":'Exploit', "name":"", "linkType":"topDown"});
        });
    return behaviors;
}
