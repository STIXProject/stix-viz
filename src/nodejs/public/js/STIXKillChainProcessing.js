function gatherKillChainObjs(xml, killChainObjs) {
	
	if (killChainObjs == null) {
		killChainObjs = [];
	}
	
    $.merge(killChainObjs, xpFind('//stixCommon:Kill_Chain', xml));
        
    return killChainObjs;
}

function processKillChainObjs(killChainObjs) {
	var killChainInfo = {};
	$(killChainObjs).each(function(index, killChain) {
		var thisChainInfo = {};
		var kcId = getObjIdStr(killChain);
		thisChainInfo['name'] = $(killChain).attr('name');
		var phaseNodes = $(xpFind('.//stixCommon:Kill_Chain_Phase', killChain));
		var phases = [];
		$(phaseNodes).each(function (i, phase) {
			var phaseInfo = {}
			var phaseId = $(phase).attr('phase_id');
			phaseInfo['phase_id'] = phaseId;
			phaseInfo['name'] = $(phase).attr('name');
			phaseInfo['ordinality'] = $(phase).attr('ordinality');
			phases.push(phaseInfo);
		});
		thisChainInfo['phases'] = phases;
		killChainInfo[kcId] = thisChainInfo;
	});
	return killChainInfo;
}

function getKillChainPhaseIds(phaseObjs) {
	var phaseIds = [];
	$(phaseObjs).each(function(index, phase) {
		phaseIds.push($(phase).attr('phase_id'));
	});
	return phaseIds;
}