$(function () { 
	var filterText = "";
    $(filterDiv).hide();
	$.map(entityRelationshipMap, function(relationships, entity) {
		//filterText = '<div class="entityFilterDiv" id="' + entity + 'Filter">';
		filterText = '<span class="entityFilter"><input type="checkbox" id="' + entity + 'Filter" onChange="toggleEntityFilter(\'' + entity + '\')"; checked> ' + entity;
		//filterText += '<a data-toggle="collapse" data-parent="#' + entity + 'Filter" href="#' + entity + 'Relationships"">+</a></span>';
		filterText += '<a data-toggle="collapse" + data-target="#' + entity + 'Relationships">+</a></span>';
		filterText += '<div class="collapse" id="' + entity + 'Relationships">'
		$.each(relationships, function(index, r) {
			filterText += '<span class="relationshipFilter"><input type="checkbox" id="' + r + 'Filter" onChange="toggleRelationshipFilter(\'' + r + '\')"; checked> ' + r + '</span>';
		});
		//filterText += '</div></div>';
		filterText += '</div>';
		$(filterDiv).append(filterText);
	});
});

function toggleEntityFilter(entity) {
	var relationships = entityRelationshipMap[entity];
	$.each(relationships, function(index, r) {
		var filter = "#" + r + 'Filter';
		$(filter).prop('checked', !($(filter).is(':checked')));
		toggleRelationshipFilter(r);
	});
}

function toggleRelationshipFilter(relationship) {
	
}
