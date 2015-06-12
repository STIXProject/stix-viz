/*
 * Copyright (c) 2015 - The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * This file contains the top level invocation of STIXViz.   It is invoked when the file is loaded by
 * index.html.
 * 
 * The main function to display the tree view is displayTree(jsonString)
 * 
 * created 2013
 * gertner@mitre.org
 * lubar@mitre.org
 * 
 */


var StixGraph = function () { 
	
	var _self = this;
	
	var nodeWidth = 60,
	nodeHeight = 60,
	labelHeight = 35;

    var nodeWarnThresh = 20;

	var dragToPin = true,
	showGrouping = true,
	dragInitiated = false,
	x0 = 0, // Initial position at start of drag
	y0 = 0, 
	epsilon = 0.1;
	


	/* Root is the node that is currently visible at the top of the tree. Report is the root of the entire structure.*/
	var report={},
	svg=null,
	node=[],
	link=[];

	report.hiddenRelationships = {};
	report.hiddenNodes = {};

//	var xmlDocs = {}, docIndex = 0;

	/* Layout of tree within its div */
	var margin = {
			top : 15,
			right : 20,
			bottom : 35,
			left : 10
	};

	function graphSize () { 
		return [$('#graphSVG').width() - nodeWidth,$('#graphSVG').height()-nodeHeight-labelHeight];
	}

		
	/**
	 * Construct the force layout object 
	 */
	var force = d3.layout.force().on("tick", tick);


	var drag = force.drag()
	.on("dragstart", function (d, i) {
		if (d3.event.sourceEvent.which == 1) {// initiate on left mouse button only
			dragInitiated = true;               // -> set dragInitiated to true
			x0 = d.x;
			y0 = d.y;
		}
		force.stop();
	})
	.on("drag", function (d, i) { 
		if (dragInitiated) {                   // perform only if a drag was initiated
			d.px += d3.event.dx;
			d.py += d3.event.dy;
			d.x += d3.event.dx;
			d.y += d3.event.dy;

			if (d.x >= force.size()[0] - 60) {
				$('#graphSVG').width($('#graphSVG').width()+5);
				_self.resize();
			} else if (d.x <= 60) {
				$('#graphSVG').width($('#graphSVG').width()+5);
				// Move all fixed nodes over by the amount of the size increase to accommodate the additional space
				d3.selectAll('.fixed').datum(function (d) { 
					d.px = d.px+5; 
					return d; 
					});
				_self.resize();
			}
			
			if (d.y >= force.size()[1] ) { 
				$('#graphSVG').height($('#graphSVG').height()+5);
				_self.resize();
			} else if (d.y <= 20) { 
				$('#graphSVG').height($('#graphSVG').height()+5);
				// Move all fixed nodes over by the amount of the size increase to accommodate the additional space
				d3.selectAll('.fixed').datum(function (d) { 
					d.py = d.py+5; 
					return d; 
					});
				_self.resize();
			}

			
			tick();
		}
	})
	.on("dragend", function (d, i) {
		if (d3.event.sourceEvent.which == 1) { //  only take gestures into account that
			force.resume();                     // were valid in "dragstart"
			// Only pin the node if the position changed. Stops a plain click from causing a pin. 
			if (dragToPin && 
					(Math.abs(d.x - x0) > epsilon || Math.abs(d.y - y0) > epsilon)) {
				d3.select(this).classed("fixed", d.fixed = true);
			} 
			tick();
			dragInitiated = false;              // terminate drag gesture
		}
	});

	function updateContext (d) { 
		if (d.fixed) { 
			$('#toggleFix a').text("Unpin node");
		} else { 
			$('#toggleFix a').text("Pin node");
		}
		
		if (d.label) { 
			$('#showLabels a').text("Hide labels");
		} else { 
			$('#showLabels a').text("Show labels");
	}
	}
	
	
	function toggleFix (node) {
		d3.select(node).classed("fixed", function (d) { 
			return d.fixed = !d.fixed;
		});
		force.resume();
	}

	function toggleLabels (node) {
		
		var nd = d3.select(node).datum();
		nd.label = !nd.label;
		
		// Highlight related links
		d3.selectAll('.link').filter(function (l) { return l.source === nd; })
		.classed("label",function (d) { return d.label = nd.label; });
		
		d3.selectAll('.link').filter(function (l) { return l.target === nd; })
		.classed("label", function (d) { return d.label = nd.label; });
		
		force.resume();
	}

	function hideNode (node) { 
		var d = d3.select(node).datum();
		// if it's a top level grouping node, use the filter menu to hide
		if (d.depth === 1) {
			var type = d.type.substring(0,d.type.length-1);
			$('#filterDiv input#'+type+'EFilter').click();
		} else {
			$.each(d.parents, function (pid, p) {
					if (p.node._children.indexOf(d) === -1) { 
						p.node._children.push(d);
				}
					pos = p.node.children.indexOf(d);
					p.node.children.splice(pos,1);
			});
		update();
	}
	}
	
	

	_self.resize = function () { 

		if (!node || node.length == 0) return;

		updateForce(showGrouping);
		
		update();

	};


	/**
	 *  Compute the graph layout based on the JSON representation of the XML data
	 */
	_self.display = function (jsonString) {

		// Set context menu for nodes in graph view
		$('#contextMenu ul').append($('#graphContextMenuTemplate').html());
		
		// Handlers for right-click context menu on nodes
		$('#toggleFix a').click(function () { toggleFix(contextNode); });
		$('#hideNode a').click(function () { hideNode(contextNode); });
		$('#showLabels a').click(function () { toggleLabels(contextNode); });

		
		showGrouping = true;
		configureNav();
		
		// Add graph container element
		$('#contentDiv').html($('#graphTemplate').html());
		
		/**
		 *  Append svg container for tree
		 */
		svg = d3.select("#graphSVGContainer").append("svg")
		.attr("id","graphSVG")
	    .append("g")
	    .attr("transform","translate(" + margin.left + "," + margin.top + ")");

		updateForce(showGrouping);
		
		/**
		 *  define color filter for lightening non-expandable nodes
		 */
		svg.append("defs")
		.append("filter")
		.attr("id","lighten")
		.append("feColorMatrix")
			.attr("type","matrix")
			.attr("values","1 .2 .2 0 0  .2 1 .2 0 0  .2 .2 1 0 0  0 0 0 1 0");
		
		
		// define arrow markers for graph links
		svg.select('defs').append('svg:marker')
		    .attr('id', 'end-arrow')
		    .attr('viewBox', '0 -5 10 10')
		    .attr('refX', 90)
		    .attr('markerWidth', 10)
		    .attr('markerHeight', 10)
		    .attr('orient', 'auto')
		    .attr('class','arrow')
		    .attr('markerUnits','userSpaceOnUse')
		  .append('svg:path')
		    .attr('d', 'M0,-5L10,0L0,5');

		// bold arrow for highlighted links
		svg.select('defs').append('svg:marker')
		    .attr('id', 'bold-arrow')
		    .attr('viewBox', '0 -5 10 10')
		    .attr('refX', 90)
		    .attr('markerWidth', 10)
		    .attr('markerHeight', 10)
		    .attr('orient', 'auto')
		    .attr('class','arrow bold')
		    .attr('markerUnits','userSpaceOnUse')
		  .append('svg:path')
		    .attr('d', 'M0,-5L10,0L0,5');


		link = svg.selectAll(".link");
		node = svg.selectAll(".node");

		report = $.parseJSON(jsonString);
		report.hiddenRelationships = {};
		report.hiddenNodes = {};
		
		removeBottomUp(report);		// Remove bottom up links since they are only needed for tree view
		mergeNodes(report); // this will set the correct ids for all nodes in the graph and merge duplicate nodes 
		report._children = [];
		report.children.forEach(collapse);

		// start the root node out fixed in the middle of the display
		report.px = graphSize()[0]/2;
		report.py = graphSize()[1]/2;
		report.fixed = true;
		

		// This is where the tree actually gets displayed
		update();

	};

	/**
	 * Collapse node d by moving "children" to "_children". Since this is a graph, we could go through the same 
	 * node twice, therefore check that the children are not empty before collapsing them. 
	 * @param d
	 */
	function collapse(d) {
		if (d.children && d.children.length > 0) {
			d._children = d.children;
			d.children = [];
			d._children.forEach(collapse);
		}
	}
	
	/* 
	 * Remove and add node functions are used for filtering
	 * Calls update after filtering is complete
	*/
	_self.removeNodesOfEntityType = function(entityType) {
		report.hiddenNodes[entityType.toLowerCase()] = true;
		update();
	};
	
	_self.addNodesOfEntityType = function(entityType) {
		report.hiddenNodes[entityType.toLowerCase()] = false;
		update();
	};
	
	_self.showLinksOfType = function(entity, r) {
		if (entity.toLowerCase() in report.hiddenRelationships) {
			delete report.hiddenRelationships[entity.toLowerCase()][r];
		}
		update();
	};
	
	_self.hideLinksOfType = function(entity, r) {
		if (entity.toLowerCase() in report.hiddenRelationships) {
			report.hiddenRelationships[entity.toLowerCase()][r] = true;
		}
		else {
			report.hiddenRelationships[entity.toLowerCase()] = {};
			report.hiddenRelationships[entity.toLowerCase()][r] = true;
		}
		update();
	};

	/**
	 * Remove links that are "bottom up" since they are only needed for tree view
	 */
	function removeBottomUp(d) {
		if (d.children) { 
			d.children = d.children.filter(function(c) { return ((c.linkType === 'topDown') || (c.linkType === 'sibling')); });
			d.children.forEach(removeBottomUp);
		}
		if (d._children) { 
			d._children = d._children.filter(function (c) { return ((c.linkType === 'topDown') || (c.linkType === 'sibling')) ; });
			d._children.forEach(removeBottomUp);
		}
	}

	/**
	 * Expand node d by moving "_children" to "children"
	 * @param d
	 */
	function expand (d) { 
		if (d._children && d._children.length > 0) {
			d.children = d.children.concat(d._children);
			d._children = [];
			d.children.forEach(expand);
		}
	}
	
	function expandAll (d) { 
		var seen = []; 
		
		function recurse (d) { 
			if (seen.indexOf(d) < 0) { 
				seen.push(d);
				if (d._children && d._children.length > 0) {
					d.children = d.children.concat(d._children);
					d._children = [];
				}
				if (d.children && d.children.length > 0) { 
					d.children.forEach(recurse);
				}
			}
		}
		
		recurse(d);
	}
	
	function expandGroupNodes (d) { 
		var seen = []; 
			
		function recurse (d) { 
			if (seen.indexOf(d) < 0) { 
				seen.push(d);
				if (isGroupingNode(d)) {
					if (d._children && d._children.length > 0) {
						d.children = d.children.concat(d._children);
			d._children = [];
		}
	}
				if (d.children && d.children.length > 0) { 
					d.children.forEach(recurse);
				}
				if (d._children && d._children.length > 0) { 
					d._children.forEach(recurse);
				}
			}
		}
		
		recurse(d);

	}
	

	function updateForce () { 
		if (showGrouping) {
		force
		.linkStrength(.9)
		.friction(.7)
		.size(graphSize())
		.linkDistance(Math.min(250,Math.min.apply(Math,graphSize())/3))
		.gravity(function (d) { 
				return 80/(Math.min.apply(Math,graphSize()) * (1+d.depth));
		})
			.charge(Math.min.apply(Math,graphSize()) * -1);
		} else { 
			force
			.linkStrength(.9)
			.friction(.7)
			.size(graphSize())
			.linkDistance(Math.min(250,Math.min.apply(Math,graphSize())/3))
			.gravity(80/Math.min.apply(Math,graphSize())) 
			.charge(Math.min.apply(Math,graphSize()) * -1);
		}
	}

	/** 
	 * Update the tree display starting at node "source"
	 * @param source The root node for the update
	 */
	function update() {


		var data = flatten(report,showGrouping), 
		nodes = data.nodes,
		links = data.links;

		// Restart the force layout.
		force
		.nodes(nodes)
		.links(links)
		.start();

		// Update links.
		link = link.data(links, function(d) {
			return d.source.id + "-" + d.target.id; 
		});

		link.exit().remove();

		var linkEnter = link.enter().insert("g",".node")
		.attr("class","link")
		.classed("label", function (d) { 
			return d.label = d.source.label || d.target.label; 
		});


		linkEnter.append("path")
		.attr("id", function (d) { return "linkId_" + d.source.id + "_" + d.target.id; })
		.attr("class", "to")
		.attr("d", function (d) { 
			return moveto(d) + lineto(d);
		});
		
		linkEnter.append('text')
		.attr("class","linkLabel")
		.attr('dy', -5)
		.attr('text-anchor','middle')
		.append('textPath')
		.attr('xlink:href',function (d) { 
			return '#linkId_' + d.source.id + '_' + d.target.id; })
		.attr('startOffset','50%')
		.text(function (d) { 
			return !d.relationship ? "" : d.relationship ; });
		
		
		// Update nodes.
		node = node.data(nodes, function(d) { return d.id; });

		node.exit().remove();
		
		node
		.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })
		.classed("collapsed", hasHiddenChildren);


		var nodeEnter = node.enter().append("g")
		.attr("class", "node")
		.classed("fixed", function (d) { return d.fixed; })
		.classed("parent",function(d) { 
			return hasChildren(d) && !isGroupingNode(d);
		})
		.classed("collapsed", hasHiddenChildren)
		.classed("group", function (d) { 
			return hasChildren(d) && isGroupingNode(d);
		})
		.on("click", click)
		.on("contextmenu", function (d) {
			if (d3.event.defaultPrevented) {
				force.resume();
				return;
			}
			
			force.stop();
			position = d3.mouse(this);
			offset = $(this).offset();
			scrollTop = $('#viewContainer').scrollTop();
			updateContext(d);
			showContext(this,(position[0]+offset.left+(nodeWidth/2))+'px',(position[1]+offset.top-nodeHeight+scrollTop)+'px');
			d3.event.preventDefault();
		})
		.call(drag);


		// Append the image icon according to nodeTypeMap
		nodeEnter.append("svg:image")
		.attr("height", String(nodeHeight)+"px")
		.attr("width", String(nodeWidth)+"px")
		.attr("xlink:href",getImageUrl)
		.attr("transform","translate("+ -nodeWidth/2 + "," + -nodeHeight/2 + ")")
		.attr("filter",function (d) { 
			return !hasChildren(d) ? "url(#lighten)" : "none";   // lighten the color of leaf nodes
		});

		// Add circle indicating "pinned" status
		nodeEnter.append('circle')
		.attr("class","pin")
		.attr("r", 5)
		.attr("cx", -(nodeWidth/2)+10)
		.attr("cy",-(nodeHeight/2)+10);
		
		// Add rounded rectangle "border" to all expandable parent nodes
		nodeEnter.filter(".parent").append('rect')
		.attr("height", String(nodeHeight+4)+"px")
		.attr("width", String(nodeWidth+4)+"px")
		.attr("rx","10")
		.attr("ry","10")
		.attr("class","parentborder")
		.attr("transform","translate("+ -(nodeWidth+4)/2 + "," + ((-nodeHeight/2) - 2) + ")");
		
//		// add layered icons for grouping nodes
//		for (var i = 0; i < 3; i++) { 
//			nodeEnter.filter('.group').insert("svg:image", ':first-child')
//			.attr("height", String(nodeHeight)+"px")
//			.attr("width", String(nodeWidth)+"px")
//			.attr("xlink:href",getImageUrl)
//			.attr("transform","translate("+ (-(nodeWidth/2)+(2*i)) + "," + (-(nodeHeight/2)-(2*i)) + ")");
//		}
		

		// Append text label to each node
		nodeEnter.append("text")
		.attr("y", function(d) { return nodeHeight + 12; })
		.attr("text-anchor", "middle")
		.attr("transform","translate(0,"+ -nodeHeight/2 +")")
		.attr("class","nodeLabel")
		.text(getName)
		.style("fill-opacity", 1);


		// Append title text to be shown as tooltip
		nodeEnter.append("title")
		.text(function (d) { 
			return (getId(d) + '\n' + getName(d)).trim(); });


		// Add handler to highlight related nodes (in tree and HTML) on mouseover
		$(".node").on("mouseenter", function () {
			var d = d3.select(this).datum();  
			var nodeId = d.nodeId ? d.nodeId : d.nodeIdRef;

			// Highlight related links
			d3.selectAll('.link').filter(function (l) { return l.source === d; })
			.classed("bold",true)
			.classed("out",true);
			
			d3.selectAll('.link').filter(function (l) { return l.target === d; })
			.classed("bold",true)
			.classed("in",true);

			
			highlightHtml(nodeId);
		});

		// handler to remove highlighting when the mouse leaves the node
		$(".node").on("mouseleave", function () { 
			removeHighlightedNodes();

			// un-highlight links
			d3.selectAll('.link')
			.classed("bold",false)
			.classed("in",false)
			.classed("out",false);


			$(".expandableContainer tr").removeClass("infocus");
		});


		// wrap text description 
		svg.selectAll('text.nodeLabel').each(wraptext);


	}

	function getImageUrl (d) {        	
		if (d.type == 'top') 
			return "./public/icons/report.png";
		else
			if (isGroupingNode(d)) {
				return "./public/xslt/images/"+nodeTypeMap[d.type]+"-group.svg"; 	
			} else {
				return "./public/xslt/images/"+nodeTypeMap[d.type]+".svg"; 
			}
			
	}



	/** 
	 * Toggle node expansion on click
	 * @param d The node that was clicked
	 */
	function click (d) {
		if (d3.event.defaultPrevented) return; // ignore drag

		if (!hasChildren(d)) return; // ignore leaf nodes

		var numChildren = getChildCount(d);
		if(numChildren >=  nodeWarnThresh)
		{
			var r=confirm("This node has "+numChildren+" child nodes! Do you still want to expand this node?");
		}
		else
		{
			r = true;
		}
		if (r===true)
		{
			d3.select('body').classed('loading',true);  // Set wait cursor while expanding
			if (d._children && d._children.length > 0) {
				d.children = d._children.concat(d.children);
				d._children = [];
				d.children.forEach(function (c) {
					// Start at the same position as the parent
					c.x = d.x + Math.random();
					c.y = d.y + Math.random();
					// Expand other nodes that share children in common with the clicked node
					$.each(c.parents, function (id,properties) {
						n = properties.node;
						if (n._children) {
							pos = n._children.indexOf(c);
							if (pos > -1) {
								n.children.push(c);
								n._children.splice(pos,1);
							}
						}
					});
				});
			} else {
				d._children = d.children.concat(d._children);
				d.children = [];
				// collapse other nodes that have children in common with the clicked node
				d._children.forEach(function (c) { 
					$.each(c.parents,function (id,properties) {
						n = properties.node;
						if (n.children) {
							pos = n.children.indexOf(c);
							if (pos > -1) {
								n._children.push(c);
								n.children.splice(pos,1); // remove node from other node's children
							}
						}
					});
				});
			} 
			update();
			$(this).mouseenter();
			d3.select('body').classed('loading',false);
		}	
	}	

	/** 
	 * Reposition nodes and links on each tick
	 */
	function tick(e) {
		
	    // avoid node collisions
		node.each(collide(0.5));
		
		// Move nodes within the view bounding box
		node.each(function (d) { 
			d.x = Math.max(nodeWidth, Math.min(graphSize()[0] - nodeWidth, d.x));
			d.y = Math.max(nodeHeight - labelHeight, Math.min(graphSize()[1], d.y));
		});


//		link.attr("x1", function(d) { return d.source.x; })
//		.attr("y1", function(d) { return d.source.y; })
//		.attr("x2", function(d) { return d.target.x; })
//		.attr("y2", function(d) { return d.target.y; });

		link.selectAll("path").attr("d", function (d) { 
			return moveto(d) + lineto(d);
		});
		

		link.selectAll("text")
		.attr('transform',function (d) {
			if (d.source.x > d.target.x) { 
				var x = (d.source.x + d.target.x)/2;
				var y = (d.source.y + d.target.y)/2;
				return 'rotate(180 '+x+','+y+')';
			} else { 
				return 'rotate(0)';
			}
		})
		.attr("dy", function (d) { 
			if (d.source.x > d.target.x) { 
				return 10;
			} else { 
				return -5;
			}
		});
		

		node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
	}


	function moveto (d) {
		return "M"+d.source.x+","+d.source.y;
	}

	function lineto (d) { 
		return "L"+d.target.x+","+d.target.y;
	}

//	Resolves collisions between d and all other nodes.
	function collide(alpha) {
		var quadtree = d3.geom.quadtree(force.nodes());
		return function(d) {
			var nx1 = d.x - nodeWidth,
			nx2 = d.x + nodeWidth,
			ny1 = d.y - nodeHeight,
			ny2 = d.y + nodeHeight;
			quadtree.visit(function(quad, x1, y1, x2, y2) {
				if (quad.point && (quad.point !== d)) {
					var x = d.x - quad.point.x,
					y = d.y - quad.point.y,
					l = Math.sqrt(x * x + y * y),
					r = Math.sqrt(nodeWidth * nodeWidth + nodeHeight * nodeHeight);
					if (l < r) {
						l = (l - r) / l * alpha;
						d.x -= x *= l;
						d.y -= y *= l;
						quad.point.x += x;
						quad.point.y += y;
					}
				}
				return x1 > nx2
				|| x2 < nx1
				|| y1 > ny2
				|| y2 < ny1;
			});
		};
	}

	/**
	 * Wrap the text of the node label so that it is no wider than the node
	 * @param d The node having its text wrapped
	 */
	function wraptext (d) { 
		var el = d3.select(this);
		// check if it was already wrapped
		if (el.selectAll('tspan').size() > 0) return;
		el.text(el.text().replace(/\n/g,'; '));
		var words = el.text().split(/\s+/);//el.classed("NodeTypeLabel") ? el.text().split(/\s+/) : el.text().split(/\n+/);
		el.text('');

		var len = 0, i = 0;
		var lastText = '';
		var tspan = el.append('tspan');
		while (i < words.length) { 
			len = tspan.node().getComputedTextLength();
			while (len <= nodeWidth && i < words.length) {
				lastText = tspan.text();
				tspan.text((lastText + ' ' + words[i++]).trim());
				len = tspan.node().getComputedTextLength();
			}
			// back up if the text is too long
			if (len > nodeWidth)  {
				if (lastText) {
					i--;
					tspan.text(lastText);
					if (i < words.length) { 
						tspan = el.append('tspan').text(words[i++]).attr('x',0).attr('dy',10);
						lastText = '';
					}
				} else {
					var j = 0, origText = tspan.text();
					while (j < origText.length) { 
						len = tspan.node().getComputedTextLength();
						tspan.text(tspan.text()+'-');
						while (len > nodeWidth) {
							tspan.text(tspan.text().substring(0,tspan.text().length-2) + '-');
							len = tspan.node().getComputedTextLength();
						}
						j += tspan.text().length-1;
						if ( j < origText.length) {
							tspan = el.append('tspan').text(origText.substring(j)).attr('x',0).attr('dy',10);
						} else { 
							tspan.text(tspan.text().substring(0,tspan.text().length-1));
						}
					}
				}
			} else {
				if (i < words.length) { 
					tspan = el.append('tspan').text(words[i++]).attr('x',0).attr('dy',10);
				}
			}
		}
		el.selectAll('tspan').filter(function (d,i) { return i > 2; }).remove();
	}


	/**
	 *  Get the name to display under the node. 
	 */
	function getName (d) { 
		return d.name ? d.name : (d.nodeIdRef && findBaseNode(d.nodeIdRef)) ? findBaseNode(d.nodeIdRef).name : d.subtype ? d.subtype : "";
	}


	/**
	 * Returns true if the node has children
	 * @param d
	 * @returns
	 */
	function hasChildren (d) { 
		return (d.children && d.children.length > 0) || (d._children && d._children.length > 0); 
	}
	
	/** 
	 * Returns true if the node has children that are currently hidden
	 * @param d
	 * @returns
	 */
	function hasHiddenChildren (d) { 
		return d._children && d._children.length > 0; 
	}
	
	/** 
	 * Returns the count of unique hidden children a node has
	 * @param d
	 * @returns
	 */
        function getChildCount(d){
            var counter = {};
            var uniqueCount = 0;
            d._children.forEach(function (cc) {
                if(!counter[cc.id])
                {
                    counter[cc.id] = cc.id;
                    uniqueCount++;
                }
            });
            return uniqueCount;
        }
	
	/** 
	 * Any node that does not have a relationship defined with its parent will be considered a grouping node
	 */
	function isGroupingNode(d) { 
		return d.grouping || d.type === 'top';
	}

	/**
	 * Given a nodeId, find the node in the tree that has that value for its nodeId attribute
	 * @param nodeId
	 * @returns
	 */
	function findBaseNode (nodeId) { 
		var queue = [report];
		var node;
		var seen = [];
		while (queue.length > 0) {
			node = queue.shift();
			if ('nodeId' in node && node.nodeId == nodeId) { 
				return node;
			} else { 
				seen.push(node);
				if (node.children) { 
					$.each(node.children,function(i,c) { if (seen.indexOf(c) < 0) queue.push(c); });
				}
				if (node._children) { 
					$.each(node._children,function(i,c) { if (seen.indexOf(c) < 0) queue.push(c); });
				}
			} 	
		} 
		return null;
	};

	
	/**
	 * Traverse the entire tree from the root, merging any nodes that have the same id. This will produce a graph from the tree. 
	 * Also saves the list of parents in each node, for easier manipulation later
	 * @param root
	 */
	function mergeNodes (root) { 
		var nodes = [],nodeid=0;

		function recurse(node,depth,parent) {

			var ref = null;
			var pos = 0;
			if (getId(node)) {
				// Look in the list of nodes we have seen so far and see if this node is a duplicate, by id 
				ref = nodes.filter(function (n) { return getId(n) === getId(node);})[0];
			} else if (node.id) { 
				ref = nodes.filter(function (n) { return n.id === node.id; })[0];
			}
			
			// If this is the first time we have processed this node, add an id and depth parameter
			if (!node.id && !ref) { 
				node.id = nodeid++;
				node.depth = depth;
				
				nodes.push(node);

				var relationship = null;
				if (node.relationship && parent) {
					relationship = node.relationship.split(':')[1] || node.relationship;
				}

				node.parents = {};
				
				// the parent list is initialized to a list containing the current parent, if there is one
				if (nodes[parent]) {
					node.parents[nodes[parent].id] = {node:nodes[parent],relationship:relationship,linkType:node.linkType}; 
				}

				pos = nodes.length-1;
			}
			// If there is a pre-existing node, merge it with the new node and then replace the new node with the old one in 
			// the new node's parent's list of children (creating a true graph rather than a tree)
			if (ref) {
				pos = nodes.indexOf(ref);
//				if (!node.id) node.id = ref.id;
//				if (!node.name) node.name = ref.name;
				
				if (!ref.name) ref.name = node.name;
				// adjust depth to lowest observed value
				if (ref.depth > depth) { 
					ref.depth = depth;
				}
				
				// merge children
				if (ref.children && node.children) { 
					var refchildids = ref.children.map(function (c) { return c.id; });
					ref.children = ref.children.concat(node.children.filter(function (c) { return refchildids.indexOf(c.id) === -1; }));
					node.children = ref.children;
				} else if (node.children) { 
					ref.children = node.children;
				}
				var childPos = nodes[parent].children.indexOf(node);
				if (childPos > -1) { 
					// Remove the duplicate child and replace it with the existing ref node 
					nodes[parent].children.splice(childPos,1,ref);
				}

				var relationship = null;
				if (node.relationship && parent) { 
					relationship = node.relationship.split(':')[1] || node.relationship;
				}
				
				if (nodes[parent]) {
					ref.parents[nodes[parent].id] = {node:nodes[parent],relationship:relationship,linkType:node.linkType};
				}
				
			}

			// these are stored in the parents property so delete them from the top level
			delete node.relationship;
			delete node.linkType;
			
			// Recurse on the children of the new node, since we might not have seen them before
			if (node.children) { 
				node.children.forEach(function (n) { 
					recurse(n,depth+1,pos);
				});
			}

		}
		
		recurse(root,0);
	}


	/**
	 * flatten the graph into a list of nodes and a list of links, to be used by the d3 force layout 
	 * @param root
	 * @returns the lists of nodes and links that define the graph
	 */
	function flatten(root,showGrouping) {
		var nodes = [], links = [];

		function recurse(node,parent) {

			var pos = 0;

			// don't show root or grouping nodes
			if (!showGrouping && (isGroupingNode(node) || node.id === 0)) {
				if (node.children) { 
					node.children.forEach(function (n) { 
						recurse(n,parent);
					});
				}
			}
			// Recurse on the node's children
			// If we have seen this node before, use the position in the node list
			else if (nodes.indexOf(node) > -1) { 
				pos = nodes.indexOf(node); 
				addLinkToParent(node,parent,pos);
			} else { 			// Otherwise, add the node to the list

				if (!report.hiddenNodes[nodeTypeMap[node.type]] && !isOrphan(node, report.hiddenRelationships)) {			
				nodes.push(node);
				pos = nodes.length-1;
				if (node.children) { 
					node.children.forEach(function (n) { 
						recurse(n,pos);
					});
				}
					
					addLinkToParent(node,parent,pos);
					
			}
			}

		}
		
		function addLinkToParent(node,parent,pos) {
			// Add link to parent
			if (typeof parent !== 'undefined') {
				if (links.filter(function (l) { return l.source === parent && l.target === pos; }).length == 0) {
					relationship = node.parents[nodes[parent].id].relationship;
					linkType = node.parents[nodes[parent].id].linkType;
					// don't push if report.hiddenRelationships[entity][relationships]==true
					var entity = node.parents[nodes[parent].id].node.type.toLowerCase();
					if (!(entity in report.hiddenRelationships) ||
							!(relationship in report.hiddenRelationships[entity])) {
						links.push({source:parent,target:pos,relationship:relationship,linkType:linkType});
					}
				}
			}

			
		}
		
		recurse(root);
		return {nodes:nodes,links:links};
	}


	/**
	 * Remove all node highlighting
	 */
	_self.removeHighlightedNodes = function () { 
		d3.selectAll("rect.nodeborder").remove();
	};



	/**
	 * Highlight all nodes in the tree that match the given nodeId. 
	 * 
	 * @param nodeId The id of the node to highlight
	 */
	_self.highlightDuplicateNodes = function (nodeId) { 
		if (!nodeId) return;
		var matches = d3.selectAll(".node").filter(function (d) { 
			return d.nodeId == nodeId || d.nodeIdRef == nodeId;
		});
		matches.append("rect")
		.attr("height", String(nodeHeight+10)+"px")
		.attr("width", String(nodeWidth+10)+"px")
		.attr("rx","10")
		.attr("ry","10")
		.attr("class","nodeborder")
		.attr("transform","translate("+ -(nodeWidth+10)/2 + "," + ((-nodeHeight/2) - 5) + ")");
	};

	// true if all links coming into the node are currently hidden
	function isOrphan(node, hiddenRelationships) {
		var orphan = true;
		var parentType = null;
		var linkType = null;
		if (node.type == "top") {return false;}  // root node is not an orphan
		$.each(node.parents,function (id,parentProperties) {
			parentType = parentProperties.node.type;
			relationship = parentProperties.relationship;
			if (!(parentType in hiddenRelationships) ||
					!(relationship in hiddenRelationships[parentType])) {
 				orphan = false;
			}
		});
		return orphan;
	}
	
	function configureNav () {
		
		// Set up drag to pin interaction. Turned on by default.
		$('#viewControls').append($('#graphControlsTemplate').html());
		
		$('#dragToPinInput').prop('checked',dragToPin);
		
		$('#dragToPinInput').change(function () { 
			dragToPin = $(this).prop('checked');
		});
		
		
		$('#resetGraphButton').click(function () {
			//reset filters
			$.fn.filterDivReset();
			report.hiddenNodes = {};
			report.hiddenRelationships = {};

			// collapse all children after the top level
			if (showGrouping) {
				expand(report);
				report.children.forEach(collapse);
			} else { 
				expandAll(report);
			}
			
			
			d3.selectAll('.node')
			.classed("fixed",function (d) { 
				if (d.index === 0) {
					// the root node is fixed initially
					return d.fixed = true;
				} else {
					// all other nodes are not fixed
					return d.fixed = false;
				}
			})
			.datum(function (d) { // remove fixed link labels  
				d.label = false;
				return d;
			});
			
			// reset the size 
			$('#graphSVG').height('100%');
			$('#graphSVG').width('100%');
			_self.resize();

			// start the root node out fixed in the middle of the display
			report.px = graphSize()[0]/2;
			report.py = graphSize()[1]/2;
			force.start();

		});
		
		$('#unpinAllButton').click(function () {
			d3.selectAll('.node').classed("fixed", function (d) { return d.fixed = false; });
		});
		
		$('#groupButton').text("Ungroup");
		
		$('#groupButton').click(function () { 
			showGrouping = !showGrouping;
			if (!showGrouping) {
				expandAll(report);
				//expandGroupNodes(report);
				$(this).text("Group");
			} else { 
				expand(report);
				report.children.forEach(collapse);
				// Move root node back to center
				report.px = graphSize()[0]/2;
				report.py = graphSize()[1]/2;
				$(this).text("Ungroup");
			}

			updateForce();
			update();
		});
		
		var holdTimer, resizeGraph = null, timerIsRunning = false, delay = 400;
		resizeGraph = function (widthDiff, heightDiff) {
			if (widthDiff !== 0) { 
				$('#graphSVG').width($('#graphSVG').width()+widthDiff);
				//report.x = report.x-(widthDiff/2);
			}
			if (heightDiff !== 0) {
				$('#graphSVG').height($('#graphSVG').height()+heightDiff);
				//report.y = report.y-(heightDiff/2);
			}
			_self.resize();
			holdTimer = setTimeout(function () { resizeGraph(widthDiff,heightDiff); },delay);
			if (delay > 20) delay = delay * 0.7;
			if (!timerIsRunning) { 
				$('body').mouseup(function () {
					clearTimeout(holdTimer);
					$('body').off('mouseup');
					timerIsRunning = false; 
					delay = 500;
				});
				timerIsRunning = true;
			}
			
		};
		$('#heightPlus').mousedown(function () { resizeGraph(0,5); });
		$('#heightMinus').mousedown(function () { resizeGraph(0,-5); });
		$('#widthPlus').mousedown(function () { resizeGraph(5,0);});
		$('#widthMinus').mousedown(function () { resizeGraph(-5,0); });
		
		$('#freeze').click(function () { force.stop(); });
		
	}
	

	
};
