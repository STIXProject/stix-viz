$(function () { 
	var filterText = "";
    //$(filterDiv).hide();
	$('#filterDiv').hide();
	$.map(entityRelationshipMap, function(relationships, entity) {
		filterText = '<span class="entityFilter"><label><input type="checkbox" id="' + entity + 'EFilter" onChange="toggleEntityFilter(\'' + entity + '\')"; checked> ' + entity + '</label>';
		if ($(relationships).length > 0) {
			filterText += '<a data-toggle="collapse" + data-target="#' + entity + 'Relationships" class="expandCollapse">+</a></span>';
			filterText += '<div class="collapse" id="' + entity + 'Relationships">'
			$.each(relationships, function(index, r) {
				filterText += '<span class="relationshipFilter"><label><input type="checkbox" id="' + entity + r + 'RFilter" onChange="toggleRelationshipFilter(\'' + entity + '\',\''+ r + '\')"; checked> ' + r + '</label></span>';
			});
			filterText += '</div>';
		}
		$('#filterDivMenu').append(filterText);
	});
	
	$('#filterDivMenu').on('hide.bs.collapse', function () {
		$('#filterDivTitleText').text('Filter');
		view.resize();
	});
	$('#filterDivMenu').on('show.bs.collapse', function () {
		$('#filterDivTitleText').text('Filter by Nodes/Relationships');
		view.resize();
	});
	
	$('.expandCollapse').click(function(){ 
			$(this).text(function(i,old){
				return old=='+' ?  '-' : '+';
			});
		});
});

// check all checkboxes for entities and relationships, collapse entities
$.fn.filterDivReset = function() {
	$.map(entityRelationshipMap, function(relationships, entity) {
		$('#' + entity + 'EFilter').prop('checked', true);    // reset entities 
		$('#' + entity + relationships).removeClass('in');   // collapse relationship lists
		$.each(relationships, function(index, r) {
			$('#' + entity + r + 'RFilter').prop('checked', true);   // reset relationships
		});
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
