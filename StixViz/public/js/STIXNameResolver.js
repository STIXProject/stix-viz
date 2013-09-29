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
	var nameStr = "";
	var titleNode = xpFindSingle('.//indicator:Title', indi);
	if (titleNode != null) {
		nameStr = $(titleNode).text();
	}
	else { 
		var desc = xpFindSingle('./indicator:Description', indi);
		if (desc != null) {
			nameStr = $(desc).text();
		}
		else { 
			var obsTitle = xpFindSingle('.//indicator:Observable//cybox:Title', indi);
			if (obsTitle != null) {
				nameStr = $(obsTitle).text();
			}
			else {
				var id = getObjIdStr(indi);
				var type = xpFindSingle('.//indicator:Type/stixCommon:Value', indi);
				if (type != null) {
					nameStr = $(type).text() + id;
				} 
				else {
					nameStr = id;
				}
			}
		}
	}
	return nameStr;
}

//Identity.Specification.PartyName.OrganisationName
//Identity.Specification.PartyName.PersonName
function getPartyName(specification) {
	var nameStr = "";
	var partyName = xpFindSingle('.//xpil:PartyName', specification);
	if (partyName != null) {
		var orgNames = xpFind('.//xpil:PartyName//xnl:OrganisationName', partyName);
		if (orgNames.length > 0) { // PartyName has organisations
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
		else {     //PartyName has person names
			var personNames = xpFind('.//xnl:PersonName', partyName);
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
	}
	return nameStr;
}


//Identity.Specification.Addresses
function getAddressNames(specification) {
	var nameStr = "";
	var addresses = xpFindSingle('.//xpil:Addresses', specification);
	if (addresses != null) {
		nameStr = concatenateNames(xpFind('.//xal:NameElement', addresses));
	}
	return nameStr;
}

//Identity.Specification.ElectronicAddressesIdentifiers
function getElectronicAddressNames(specification) {
	var nameStr = "";
	var electronicAddresses = xpFindSingle('.//xpil:ElectronicAddressIdentifiers', specification);
	if (electronicAddresses != null) {
		nameStr = concatenateNames(xpFind('.//xpil:ElectronicAddressIdentifier', electronicAddresses));
	}
	return nameStr;
}

//Identity.Specification.Memberships
function getMembershipNames(specification) {
	var nameStr = "";
	var memberships = xpFindSingle('.//xpil:Memberships', specification);
	if (memberships != null) {
		nameStr = concatenateNames(xpFind('.//xpil:MembershipElement', memberships));
	}
	return nameStr;
}

//TODO - more to add here such as ElectronicAddressIdentifier
//Identity.Name
//Specification.PartyName.OrganisationNames.NameElement+SubdivisionName
//Specification.PersonName.NameElement
//Specification.Memberships.MemebershipElement
function getBestIdentityName(identity) {
    var nameStr = "";
	var nameNode = xpFindSingle('.//stixCommon:Name', identity);
	if (nameNode != null) {
		nameStr = $(nameNode).text();
	}
	else {
		var specification = xpFindSingle('.//stix-ciq:Specification', identity);
		if (specification != null) {
			nameStr = getPartyName(specification);
			if (nameStr == "") {
				nameStr = getAddressNames(specification);
			}
			else { return nameStr; }
			if (nameStr == "") {
				nameStr = getElectronicAddressNames(specification);
			}
			else { return nameStr; }
			if (nameStr == "") {
				nameStr = getMembershipNames(specification);
			}
			else { return nameStr; }
		}
	}
	return nameStr;
}

// Title
// Identity  (see getBestIdentityName)
// Type + @id
// @id
function getBestThreatActorName(actor) {
	var nameStr = "";
    var titleNode = xpFindSingle('.//threat-actor:Title', actor);
    if (titleNode != null) {
		nameStr = $(titleNode).text();
	}
	else {
		var identity = xpFindSingle('.//threat-actor:Identity', actor);
		if (identity != null) {
			nameStr = getBestIdentityName(identity);
		}
	}
	if (nameStr == "") {  // didn't find an Identity or didn't get anything from it
		var id = getObjIdStr(actor);
		var type = xpFindSingle('./threat-actor:Type/stixCommon:Value', actor);
		if (type != null) {
			nameStr = $(type).text() + id;
		} 
		else {
			nameStr = id;
		}
	}
    return nameStr;
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