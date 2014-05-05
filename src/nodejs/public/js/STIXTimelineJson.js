/*
 * Copyright (c) 2014 The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * This file contains the functionality for extracting time related data specified in the xml
 * files loaded.  The top level function is generateTimelineJson(inputXMLFiles)
 * 
 * Json is created representing time related data as either single points (instances) or time
 * ranges with a start and end time.   This is passed to displayJson(json) for display in STIXViz.
 * 
 */

//indiObjs are Sightings with timestamps
function getIndicatorNodes(indiObjs) {
	var indiNodes = [];
	var indiId = "";
	var node = {};
	$(indiObjs).each(function (index, indi) {
		node = {'type':'Indicator-Sighting'};
		parentIndi = $(indi).parent().get(0);
		indiId = getObjIdStr(parentIndi);
		node['parentObjId'] = indiId;
		node['description'] = getBestIndicatorName(parentIndi);
		node['timeRange'] = false;
		node['start'] = $(indi).attr('timestamp');
		indiNodes.push(node);
	});
	return indiNodes;
}

// return description string for incident:Course_Of_Action
function getCOADescription(coaTaken) {
	desc = "";
	if (coaTaken != null) {
		var coaType = xpFindSingle('./coa:Type', coaTaken);
		if (coaType != null) {
			desc = $(coaType).text();
		}
		var coaDescription = xpFindSingle('./coa:Description', coaTaken);
		if (coaDescription != null) {
			if (desc.length > 0) {
				desc = desc + ": " + $(coaDescription).text();
			}
			else {
				desc = $(coaDescription).Text();
			}
		}
	}
	return desc;
}

//incident objs are all incidents - check to see if have time, coataken
function getIncidentNodes(incidentObjs) {
var incidentNodes = [];
    var incidentId = "";
    var node = {};
    var timeObj = null;
    var timeTypeObj = null;
    var coaTakenTime = null;
    var startTime = null;
    var endTime = null;
    $(incidentObjs).each(function (index, incident) {
        incidentId = getObjIdStr(incident);
        timeObj = xpFindSingle('./incident:Time', incident);
        if (timeObj != null) {
                    $(timeObj.children).each(function(i, timeTypeObj) {
            node = {}
            node["parentObjId"] = incidentId;
            node["description"] = getBestIncidentName(incident);
            node['timeRange'] = false;
            //timeTypeObj = xpFindSingle('./incident:First_Malicious_Action', timeObj);
            // there are many different time types: First_Malicious_Action, Initial_Compromise, First_Data_Exfiltration,  Incident_Discovery, Incident_Opened, Containment_Achieved,        
            //             Restoration_Achieved, Incident_Reported, Incident_Closed
            //timeTypeObj = timeObj.firstElementChild;
            if (timeTypeObj != null) {
                //node['type'] = 'Incident-First-Malicious-Action';
                node['type'] = 'Incident-' + timeTypeObj.localName;
                node['start'] = $(timeTypeObj).text();
                incidentNodes.push(node);
            }
                    });
        }
        coaTakenTime = xpFindSingle('./incident:COA_Taken/incident:Time', incident);
        if (coaTakenTime != null) {
            node = {}
            node["parentObjId"] = incidentId;
            var coaTaken = xpFindSingle('./incident:COA_Taken/incident:Course_Of_Action', incident);
            node["description"] = getCOADescription(coaTaken);
            node['timeRange'] = true;
            node['type'] = 'Incident-COATaken';
            startTime = xpFindSingle('./incident:Start', coaTakenTime);
            if (startTime != null) {
                node['start'] = $(startTime).text();
            }
            endTime = xpFindSingle('./incident:End', coaTakenTime);
            if (endTime != null) {
                node['end'] = $(endTime).text();
            }
            incidentNodes.push(node);
        }

    });
    return incidentNodes;
}

function createTimelineJson(topLevelObjs) {
 var timelineJson = [];
 $.merge(timelineJson, getIncidentNodes(topLevelObjs['incidentObjs']));
 $.merge(timelineJson, getIndicatorNodes(topLevelObjs['indiObjs']));
 return timelineJson;
}

/** 
 * Top level entities are gathered from each xml file
 * 
*/
function gatherTimelineTopLevelObjs(xml, topLevelObjs) {
	
	if (topLevelObjs == null) {
		topLevelObjs = {};
		topLevelObjs['incidentObjs'] = [];
		topLevelObjs['indiObjs'] = [];
	}
	
    // ets are in stixCommon, observables are in cybox, other top level objs are in stix
    $.merge(topLevelObjs['incidentObjs'], xpFind('.//stix:Incidents/stix:Incident', xml));  // get all incident objs
    $.merge(topLevelObjs['indiObjs'], xpFind('.//stix:Indicators/stix:Indicator/indicator:Sightings/indicator:Sighting[@timestamp]', xml));
    
    return topLevelObjs;
}

