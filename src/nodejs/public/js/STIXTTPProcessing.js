/*
 * Copyright (c) 2015 – The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * This file contains functionality for creating a Json node for a TTP
 * 
 */

// Create basic Json node for a TTP
// used by processTTPObjs and processChildTTPs
function createSingleTTPJson(ttp, etBottomUpInfo, relationship) {
	var ttpId = getObjIdStr(ttp);
	var ttpJson = null;
	if (relationship == 'ttp:Related_TTP') {
		ttpJson = createSiblingNode(ttpId, STIXType.ttp, getBestTTPName(ttp), relationship);
	}
	else {
		ttpJson = createTopDownNode(ttpId, STIXType.ttp, getBestTTPName(ttp), relationship);
	}
    // children can be INDICATORS (from indicator file), RESOURCES, 
    // BEHAVIORS, or Victim_Targeting
    var ttpChildren = [];
    $.merge(ttpChildren, processTTPBehaviors(ttp));
    $.merge(ttpChildren, processTTPResources(ttp));
    $.merge(ttpChildren, processTTPVictimTargeting(ttp));
    $.merge(ttpChildren, processTTPChildExploitTargets(ttp, etBottomUpInfo));
    var relatedTTPs = xpFind('.//ttp:Related_TTP', ttp);
    $.merge(ttpChildren, processChildTTPs(relatedTTPs, 'ttp:Related_TTP'));
    if (ttpChildren.length > 0) {
        ttpJson["children"] = ttpChildren;
    }
    return ttpJson;
}

//BEHAVIORS (malware, attack pattern, exploit)
//TODO - NOT looking for idRefs
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
		behaviors.push(createTopDownNode(null, 'MalwareBehavior', "Malware Behavior: " + mName, 'ttp:Malware'));
 }
 var attackPats = xpFind('.//ttp:Behavior//ttp:Attack_Pattern', ttp);
 $(attackPats).each(function (index, pat) {
         behaviors.push(createTopDownNode(null, 'AttackPattern', "Attack Pattern", 'ttp:Attack_Pattern'));
     });
 var exploits = xpFind('.//ttp:Behavior//ttp:Exploits', ttp);
 $(exploits).each(function (index, exploit) {
         behaviors.push(createTopDownNode(null, 'Exploit', ""));
     });
 return behaviors;
}

//RESOURCES (cybox observables (URI, ip addresses, ttp:Tool), 
//TODO - NOT looking for idRefs
//TODO - need to add more child types as we see them
function processTTPResources(ttp) {
 var resources = [];
 resourceObj = xpFindSingle('.//ttp:Resources', ttp);
 if (resourceObj != null) {
 	var resourceName = $(xpFindSingle('.//ttp:Type', resourceObj)).text();
		if (typeof(name) == 'undefined') {
		    resourceName = "";
		}
		// see if there are Observables
		var observable = xpFindSingle('.//cybox:Observable', resourceObj);
		if (observable != null) {   // found at least one
			if (resourceName == "") {
				resourceName = getBestObservableName(observable);
			}
		    resources.push(createTopDownNode(null, "Observable", resourceName, 'ttp:Resource'));
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
		    	resources.push(createTopDownNode(null, "Tools", "Tool: " + toolString, 'ttp:Resource'));
		    }
		}
 }
 return resources;
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
		targets.push(createTopDownNode(null, "VictimTargeting", nameStr, 'ttp:Victim_Targeting'));
    }
    return targets;
}

function processTTPChildExploitTargets(ttp, etBottomUpInfo) {
	var etNodes = [];
    var etSection = xpFindSingle('.//ttp:Exploit_Targets', ttp);
    if (etSection != null) {
    var targets = xpFind(STIXPattern.et, etSection);
    var ttpId = getObjIdStr(ttp);
    if (ttpId != null) {
        $(targets).each(function (index, et) {
        	addToBottomUpInfo(etBottomUpInfo, et, STIXGroupings.ttp, ttpId);
        });
    }
    
	    $(targets).each(function (index, target) {
	    	var idRef = getObjIdRefStr(target);
	    	if (idRef != "") {  // target is specified via an idRef
	    		etNodes.push(createTopDownIdRef(STIXType.et, idRef, 'ttp:Exploit_Target'));
	    	}
	    	else {   // target is specified inline
	    		var etNode = createTopDownNode(null, STIXType.et, getBestExploitTargetName(target), 'ttp:Exploit_Target');
	    		var coas = xpFind('.//et:Potential_COAs', target);
	    		var children = processChildCoas(coas, 'et:Potential_COAs');
	    		if (children.length > 0) {
	    			etNode["children"] = children;
	    		}
	    		etNodes.push(etNode);
	    	}
	    });
    }
    return etNodes;
}
