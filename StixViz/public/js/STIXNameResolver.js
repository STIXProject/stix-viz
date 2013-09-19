function concatenateNames(names) {
    var nameStr = "";
    $(names).each(function (index, name) {
            nameStr = nameStr + $(name).text();
            if (index < names.length - 1) {
                nameStr = nameStr + "\n";
            }
        });
    return nameStr;
}

// Title
// Names (Join)
// Intended_Effect + @id
function getBestCampaignName(ca) {
    var titleNode = xpFindSingle('.//campaign:Title', ca);
    if (titleNode != null) {
        return $(titleNode).text();
    }
    else {
        var names = $(xpFind('.//campaign:Name', ca));
        var nameStr = concatenateNames(names);
        if (nameStr.length > 0) {
            return nameStr;
        }
        else { 
        	var id = getObjIdStr(ca);
        	var effect = xpFindSingle('./campaign:Intended_Effect/stixCommon:Value', ca);
            if (effect != null) {
            	return $(effect)+id;
            }
            else {
            	return id;
            }
        }
    }
}

// Title
// Description (truncate) – probably won’t be used w/o Title but you never know
// Objective.Description (truncate)
// @id
function getBestCourseOfActionName(coa) {
	var titleNode = xpFindSingle('.//coa:Title', coa);
	if (titleNode != null) {
		return $(titleNode).text();
	}
	else { // TODO - implement backup titles
		return "";
	}
}

// title
// Vulnerability.CVE_ID, Weakness.CWE_ID, Configuration.CCE_ID (Join)
// @id
function getBestExploitTargetName(exploitTarget) {
	var titleNode = xpFindSingle('.//et:Title', exploitTarget);
	if (titleNode != null) {
		return $(titleNode).text();
	}
	else { // TODO - implement backup titles
		return "";
	}
}

// Title
// Description (truncate) – probably won’t be used w/o Title but you never know
// Categories.Category (join) + @id
function getBestIncidentName(incident) {
	var titleNode = xpFindSingle('.//incident:Title', incident);
	if (titleNode != null) {
		return $(titleNode).text();
	}
	else { // TODO - implement backup titles
		return "";
	}
}

// Title
// Description (truncate) – probably won’t be used w/o Title but you never know
// Observable.Title
// Type + @id – Obviously if there is a higher level grouping of type here you don’t need to repeat type
function getBestIndicatorName(indi) {
	var titleNode = xpFindSingle('.//indicator:Title', indi);
	if (titleNode != null) {
		return $(titleNode).text();
	}
	else { 
		var desc = xpFindSingle('./indicator:Description', indi);
		if (desc != null) {
			return $(desc).text();
		}
		else { 
			var obsTitle = xpFindSingle('.//indicator:Observable//cybox:Title', indi);
			if (obsTitle != null) {
				return $(obsTitle).text();
			}
			else {
				return "";
			}
		}
	}
}

// create a name for a threat_actor based on it's Identity Specification if there
// is one.  Otherwise use it's common name
// Title
// Identity.Name
// Specification.OrganisationNames.NameElement+SubdivisionName
// Specification.PersonName.NameElement
// Type + @id
function getBestThreatActorName(actor) {
    var titleNode = xpFindSingle('.//threat-actor:Title', actor);
    if (titleNode != null) {
		return $(titleNode).text();
	}
	else {
		var nameNode = xpFindSingle('.//threat-actor:Identity/stixCommon:Name', actor);
		if (nameNode != null) {
			return $(nameNode).text();
		}
		else {
		    var nameStr = "";
			var specification = xpFindSingle('.//stix-ciq:Specification', actor);
			if (specification != null) {
				var orgNames = xpFind('.//xpil:PartyName//xnl:OrganisationName', specification);
				if (orgNames.length > 0) { // PartyName is an organisation
					$(orgNames).each(function (index, org) {
						var nameElt = xpFindSingle('.//xnl:NameElement', org);
						nameStr = nameStr + $(nameElt).text();
						var subdivElt = xpFindSingle('.//xnl:SubDivisionName', org);
						if (subdivElt != null) {
							nameStr = nameStr + "\n" + $(subdivElt).text();
						}
						if (index < orgNames.length-1) {
							nameStr = nameStr + "\n";
						}
					});
				}
				else {
					var personNames = xpFind('.//xnl:PersonName', specification);
					if (personNames.length > 0) {
						$(personNames).each(function (index, person) {
							var nameElt = xpFindSingle('.//xnl:NameElement', person);
							nameStr = nameStr + $(nameElt).text();
							if (index < personNames.length-1) {
								nameStr = nameStr + "\n";
							}
						});
					}
				}
				return nameStr;
			}
			else {
				var id = getObjIdStr(actor);
				var type = xpFindSingle('./threat-actor:Type/stixCommon:Value', actor);
				if (type != null) {
					return $(type).text()+id;
				}		
				else {
					return id;
				}
			}
		}
	}
}

// Title
// Description (truncate) – probably won’t be used w/o Title but you never know
// This is a little complicated, but maybe say which of the following elements are there plus the ID: Behavior, Resources, Victim_Targeting. 
//    For example, if the TTP has Behavior and Resource but no Victim Targeting, say “Behavior, Resources: ttp-234”
function getBestTTPName(ttp) {
	var titleNode = xpFindSingle('.//ttp:Title', ttp);
	if (titleNode != null) {
		return $(titleNode).text();
	}
	else { // TODO - implement backup titles
		return "";
	}
}