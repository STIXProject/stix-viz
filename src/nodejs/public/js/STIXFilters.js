$(function () { 
	var filterText = "";
    //$(filterDiv).hide();
	$('#filterDiv').hide();
	$.map(entityRelationshipMap, function(relationships, entity) {
		filterText = '<span class="entityFilter"><label><input type="checkbox" id="' + entity + 'EFilter" onChange="toggleEntityFilter(\'' + entity + '\')"; checked> ' + entity + '</label>';
		if ($(relationships).length > 0) {
			filterText += '<a data-toggle="collapse" data-target="#' + entity + 'Relationships" class="expandCollapse">+</a></span>';
			filterText += '<div class="collapse" id="' + entity + 'Relationships">'
			$.each(relationships, function(index, r) {
				filterText += '<span class="relationshipFilter"><label><input type="checkbox" id="' + entity + r + 'RFilter" onChange="toggleRelationshipFilter(\'' + entity + '\',\''+ r + '\')"; checked> ' + r + '</label></span>';
			});
			filterText += '</div>';
		}
		$('#filterNodeDivMenu').append(filterText);
	});
	
	$('#filterNodeDivMenu').on('hide.bs.collapse', function () {
		$('#filterNodeDivTitleText').text('Filter');
		view.resize();
	});
	$('#filterNodeDivMenu').on('show.bs.collapse', function () {
		$('#filterNodeDivTitleText').text('Include Nodes/Relationships');
		view.resize();
	});

	$('#filterKCDivMenu').on('hide.bs.collapse', function () {
		$('#filterKCDivTitleText').text('Show KC');
		view.resize();
	});
	$('#filterKCDivMenu').on('show.bs.collapse', function () {
		$('#filterKCDivTitleText').text('Show Kill Chain Phases');
		view.resize();
	});

	$('.expandCollapse').click(function(){ 
			$(this).text(function(i,old){
				return old=='+' ?  '-' : '+';
			});
		});
});

function addKillChainFilters() {
	var filterText = "";
	var ctr = 0;
	$.each(viewKillChains, function (kcid, killChainInfo) {
		filterText += '<span class="killChainFilter"><label><input type="checkbox" id="' + kcid + 'KillChain" onChange="toggleKillChainFilter(\'' + kcid + '\')"; > ' + killChainInfo['name'] + '</label>';
		var phases = killChainInfo['phases'];
		if ($(phases).length > 0) {
			filterText += '<a data-toggle="collapse" data-target="#killChain' + ctr + 'Phases" class="expandCollapse">+</a></span>';
			filterText += '<div class="collapse" id="killChain' + ctr + 'Phases">'
			$.each(phases, function(index, phase) {
				filterText += '<span class="kcPhaseFilter"><label><input type="checkbox" id="' + phase['phase_id'] + 'kcPhaseFilter" onChange="toggleKCPhaseFilter(\'' + phase['phase_id'] + '\')"; > ' + phase['name'] + '</label></span>';
			});
			filterText += '</div>';
		}
		$('#filterKCDivMenu').append(filterText);
		ctr += 1;
	});
}

function addKillChainBands () { 
	// calculate the width to allocate to each killChain phase
	if (Object.keys(viewKillChains).length > 0) {
		var kc_id = Object.keys(viewKillChains)[0];
		$.each(viewKillChains[kc_id].phases, function (p,phase) {
			$('#killChainBands').append('<div id="kcBand_'+phase.phase_id+'" class="killChainBand">'+phase.name+'</div>')
			.hide();
		});
	}
}

// check all checkboxes for entities and relationships, collapse entities
$.fn.filterDivReset = function() {
	$.map(entityRelationshipMap, function(relationships, entity) {
		$('#' + entity + 'EFilter').prop('checked', true);    // reset entities 
		$('#' + entity + relationships).removeClass('in');   // collapse relationship lists
		$.each(relationships, function(index, r) {
			$('#' + entity + r + 'RFilter').prop('checked', true);   // reset relationships
		});
	});
	var ctr = 0;
	$.each(viewKillChains, function(kcid, killChainInfo) {
		$('#' + kcid + 'KillChain').prop('checked', true);    // reset kill chain filters
		$('#killChain' + ctr + 'Phases').removeClass('in');   // collapse phase lists
		var phases = killChainInfo['phases'];
		if ($(phases).length > 0) {
			$.each(phases, function(index, phase) {
				$('#' + phase['phase_id'] + 'kcPhaseFilter').prop('checked', true);   // reset phases
			});
		}
		ctr += 1;
	});
}

function toggleEntityFilter(entity) {
	var relationships = entityRelationshipMap[entity];
	if ($('#' + entity + 'EFilter').prop('checked')) {
		view.addNodesOfEntityType(entity);	
		$(relationships).each(function(index, r) {
			$('#' + entity + r + 'RFilter').prop('checked', true);
			view.showLinksOfType(entity, r);
		});
	}
	else {
		$(relationships).each(function(index, r) {
			$('#' + entity + r + 'RFilter').prop('checked', false);
			view.hideLinksOfType(entity, r);
		});
		view.removeNodesOfEntityType(entity);
	}
}

function toggleRelationshipFilter(entity, relationship) {
	if ($('#' + entity + relationship + 'RFilter').prop('checked')) {
		view.showLinksOfType(entity, relationship);	
	}
	else {
		view.hideLinksOfType(entity, relationship);
	}	
}

function toggleKillChainFilter(kcid) {
	var phases = viewKillChains[kcid]['phases'];
	if ($('#' + kcid.replace( /(:|\.|\[|\])/g, "\\$1" ) + 'KillChain').prop('checked')) {
		if ($(phases).length > 0) {
			$.each(phases, function(index, phase) {
				$('#' + phase.phase_id.replace( /(:|\.|\[|\])/g, "\\$1" ) + 'kcPhaseFilter').prop('checked',true);
				view.addNodesFromKillChainPhase(phase['phase_id']);
			});
		}
	}
	else {
		if ($(phases).length > 0) {
			$.each(phases, function(index, phase) {
				$('#' + phase.phase_id.replace( /(:|\.|\[|\])/g, "\\$1" ) + 'kcPhaseFilter').prop('checked',false);
				view.removeNodesFromKillChainPhase(phase['phase_id']);
			});
		}
	}
}

function toggleKCPhaseFilter(phase_id) {
	if ($('#' + phase_id.replace( /(:|\.|\[|\])/g, "\\$1" ) + 'kcPhaseFilter').prop('checked')) {
		view.addNodesFromKillChainPhase(phase_id);
	}
	else {
		view.removeNodesFromKillChainPhase(phase_id);
	}
}
