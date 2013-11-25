/*
 * Copyright (c) 2013 – The MITRE Corporation
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

var StixTree = function () { 

	var nodeWidth = 60,
	nodeHeight = 60,
	nodeSep = 160,
	markerSize = 6;
	var nodeCount = 0;

	/* Root is the node that is currently visible at the top of the tree. Report is the root of the entire structure.*/
	var stixroot=null,report,svg;

	/* Id of the node that was last right-clicked */
	var contextNode = null;

//	var xmlDocs = {}, docIndex = 0;

	/* Layout of tree within its div */
	var margin = {
			top : 20,
			right : 20,
			bottom : 35,
			left : 10
	}, 
	width = 1100 - margin.right - margin.left,
	height = 1200 - margin.top- margin.bottom;

	function treeWidth () { 
		return $(window).width() - nodeWidth;
	}

	/**
	 * Construct the tree layout object 
	 */
	var tree = d3.layout.tree().nodeSize([ nodeWidth, nodeHeight ]).size([treeWidth(),height]);

	/**
	 * Diagonal for drawing links between nodes
	 */
	var diagonal = d3.svg.diagonal()
	.source(function (d) { 
		return {x:d.source.x, y:d.source.y+nodeHeight};
	});


	/**
	 * Duration of animated transitions
	 */
	var duration = 750;



	_self.resize = function () { 
		tree.size([treeWidth(),height]);

		if (stixroot) { 
			update(stixroot);
		}
	};


	/**
	 *  Compute the tree layout based on the JSON representation of the XML data
	 */
	_self.display = function (jsonString) {

		report = $.parseJSON(jsonString);
		stixroot = report;

		stixroot.y0 = height / 2;
		stixroot.x0 = 0;

		stixroot.children.forEach(collapse);

		addParents(stixroot);

		// This is where the tree actually gets displayed
		update(stixroot);

	}

	/**
	 * Collapse node d by moving "children" to "_children"
	 * @param d
	 */
	function collapse(d) {
		if (d.children) {
			d._children = d.children;
			d._children.forEach(collapse);
			d.children = null;
		}
	}

	/**
	 * Expand node d by moving "_children" to "children"
	 * @param d
	 */
	function expand (d) { 
		if (d._children) { 
			d.children = d._children; 
			d._children = null;
		}
	}


	/**
	 * add parents to each node so that we can walk back up the tree after drilling down
	 */
	function addParents(parent) { 
		if (parent.children && parent.children.length > 0) { 
			parent.children.forEach(function (child) {
				child.parent = parent;
				addParents(child);
			});
		}

	}


	/** 
	 * Update the tree display starting at node "source"
	 * @param source The root node for the update
	 */
	function update(source) {

		var nodes = tree.nodes(stixroot),
		links = tree.links(nodes);

		// Update the nodes…
		node = svg.selectAll("g.node")
		.data(nodes, function(d) {
			return d.id || (d.id = ++nodeCount);
		});



		// Compute y position of nodes
		var zigzag = [];
		var level = 0;
		var nodeArray = nodes.filter(function (d) { return d.depth == level; });
		var minx,maxx;
		while (nodeArray.length > 0) { 
			minx = nodeArray.reduce(function(a, b, i, arr) {return a.x < b.x ? a : b;});
			maxx = nodeArray.reduce(function(a, b, i, arr) {return a.x > b.x ? a : b;});
			zigzag.push(nodeArray.length * nodeWidth > maxx.x - minx.x + nodeWidth);
			level++;
			nodeArray = nodes.filter(function (d) { return d.depth == level;});
		}

		// Normalize for fixed-depth.
		var maxY = 0;
		nodes.sort(function(a,b) { return a.id - b.id; } ).forEach(function(d,i) {
			if (zigzag[d.depth] && i % 2 == 0) { 
				d.y = (d.depth * nodeSep) + nodeHeight+20;
			} else { 
				d.y = d.depth * nodeSep;
			}
			if (d.y > maxY) maxY = d.y;
		});

		$('svg').height(maxY+margin.top+margin.bottom+(2*nodeHeight)+nodeSep);


		// Enter any new nodes at the parent's previous position.
		var nodeEnter = node.enter()
		.append("g")
		.attr("class", "node")
		.attr("transform", function(d) {
			return "translate(" + (source.x0 + (nodeWidth/2)) + "," + (source.y0 + (nodeHeight/2)) + ")";
		})
		.on("click", click)
		.on("dblclick",doubleclick)
		.on("contextmenu", showContext)
		.classed("parent",function(d) { 
			return hasChildren(d);
		});


		// Append title text to be shown as tooltip
		nodeEnter.append("title")
		.text(function (d) { 
			return (getId(d) + '\n' + getName(d)).trim(); });

		// Append the image icon according to typeIconMap
		nodeEnter.append("svg:image")
		.attr("height", 1e-6)
		.attr("width", 1e-6)
		.attr("xlink:href",function (d) {  return "./public/icons/13-008 ICONS - STIX_"+typeIconMap[d.type]+".png"; })
		.attr("transform","translate("+ -nodeWidth/2 + ")")
		.attr("class", function(d) { return d.type; })
		.attr("filter",function (d) { 
			return !hasChildren(d) ? "url(#lighten)" : "none";   // lighten the color of leaf nodes
		})
		.classed("leaf",function (d) { 
			return !hasChildren(d);             
		});

		// Add rounded rectangle "border" to all expandable parent nodes
		nodeEnter.filter(".parent").append('rect')
		.attr("height", String(1e-6)+"px")
		.attr("width", String(1e-6)+"px")
		.attr("rx","10")
		.attr("ry","10")
		.attr("class","parentborder")
		.attr("transform","translate("+ -(nodeWidth+4)/2 + "," + "-2" + ")");

		// Append text label to each node
		nodeEnter.append("text")
		.attr("y", function(d) { return nodeHeight + 12; })
		.attr("text-anchor", "middle")
		.text(getName)
		.style("fill-opacity", 1e-6);

		// Add handler to highlight related nodes (in tree and HTML) on mouseover
		$(".node").on("mouseenter", function () {
			var d = d3.select(this).datum();  
			var nodeId = d.nodeId ? d.nodeId : d.nodeIdRef;

			highlightDuplicateNodes(nodeId);
			highlightHtml(nodeId);
		});

		// handler to remove highlighting when the mouse leaves the node
		$(".node").on("mouseleave", function () { 
			removeHighlightedNodes();
			$(".expandableContainer tr").removeClass("infocus");
		});


		// wrap text description 
		svg.selectAll('text').each(wraptext);


		// Transition nodes to their new position and make all attached elements visible
		var nodeUpdate = node.transition()
		.duration(duration)
		.attr("transform",function(d) {	return "translate(" + d.x + "," + d.y + ")";	});

		nodeUpdate.select("image")
		.attr("height", String(nodeHeight)+"px")
		.attr("width", String(nodeWidth)+"px");

		nodeUpdate.select("text").style("fill-opacity", 1);

		nodeUpdate.select('rect')
		.attr("height",String(nodeHeight+4)+"px")
		.attr("width",String(nodeWidth+4)+"px");


		// Transition exiting nodes to the parent's new position.
		var nodeExit = node.exit().transition().duration(duration).attr(
				"transform", function(d) {
					return "translate(" + (source.x + (nodeWidth/2)) + "," + (source.y + (nodeWidth/2)) + ")";
				}).remove();

		nodeExit.select("image")
		.attr("height", 1e-6)
		.attr("width", 1e-6);

		nodeExit.select("text")
		.style("fill-opacity", 1e-6);

		nodeExit.select("rect")
		.attr("height", String(1e-6)+"px")
		.attr("width", String(1e-6)+"px");



		// Add markers (arrows) to all links
		var marker = svg.select("defs")
		.selectAll("marker")
		.data(links, function (d) { return d.target.id; });


		// Create triangle path for each new marker 
		marker.enter().append("svg:marker")
		.attr("id",function (d) { return "arrow" + d.target.id; })
		.attr("viewBox", "0 -5 10 10")
		.attr("refX", 30)
		.attr("markerWidth",1e-6)
		.attr("markerHeight",1e-6)
		.classed("arrow",true)
		.append("svg:path")
		.attr("d",function (d) {
			if (d.target.linkType == "topDown") { 
				return "M0,-5L10,0L0,5";
			} else { 
				return "M10,-5L0,0L10,5";
			}
		});


		//Reset position and orientation of all markers based on new position of the target node
		marker.attr("refY", function (d) { return (1/markerSize)*(90-computeAngle(d));})
		.attr("orient",computeAngle);

		// remove exiting markers
		marker.exit().remove();


		// Update the links…
		var link = svg.selectAll("path.link")
		.data(links, function(d) {return d.target.id;});

		// Enter any new links at the parent's previous position.
		link.enter()
		.insert("path", "g")
		.attr("class", "link")
		.attr("d",
				function(d) {
			var o = {
					x : source.x0,
					y : source.y0
			};
			return diagonal({
				source : o,
				target : o
			});
		})
		.attr("marker-end",function(d){ 
			return "url(#arrow"+d.target.id+")"; 
		});


		// Transition links to their new position.
		link.transition()
		.duration(duration)
		.attr("d", diagonal);


		// After the links have moved to their position, show the arrow markers
		marker.transition()
		.duration(duration)
		.attr("markerWidth",markerSize)
		.attr("markerHeight",markerSize);


		// Transition exiting links to the parent's new position.
		link.exit()
		.transition()
		.duration(duration)
		.attr("d", function(d) {
			var o = {
					x : source.x,
					y : source.y
			};
			return diagonal({
				source : o,
				target : o
			});
		})
		.remove();

		// Stash the old positions for transition.
		nodes.forEach(function(d) {
			d.x0 = d.x;
			d.y0 = d.y;
		});

		// Add top link if needed
		d3.selectAll(".toplink").remove();
		d3.selectAll("g.node").filter(function(d) { return d.depth == 0 && d.parent; }).append("svg:line")
		.classed("link toplink",true)
		.attr("y1",-10)
		.attr("y2",-1)
		.attr("x1",0)
		.attr("x2",0);


	}

	/** Show the context menu for showing the HTML view when right clicking a node
	 * 
	 * @param data The node that was clicked
	 */
	function showContext (data) {
		contextNode = data;
		if (getId(data) || htmlSectionMap[data.type]) {  // disable if the node has no ID or section header 
			$('#showHtml').removeClass('disabled');
		} else { 
			$('#showHtml').addClass('disabled');
		}
		position = d3.mouse(this);
		offset = $(this).offset();
		scrollTop = $('#treeView').scrollTop(); 
		d3.select("#contextMenu")  // Display the context menu in the right position
		.style('position','absolute')
		.style('left',(position[0]+offset.left+(nodeWidth/2))+'px')
		.style('top',(position[1]+offset.top-nodeHeight+scrollTop)+'px')
		.style('display','block');
		d3.event.preventDefault();
	}


	/** 
	 * Toggle node expansion on click
	 * @param d The node that was clicked
	 */
	function click(d) {
		d3.event.stopPropagation();
		if (d.children) {
			d._children = d.children;
			d.children = null;
		} else if (d._children) {
			d.children = d._children;
			d._children = null;
		} else if (d.nodeIdRef) { 
			// Infinite tree - if there are no children, find the matching base node and use its children
			var base = findBaseNode(d.nodeIdRef);
			if (base && hasDirectChildren(base)) { 
				d.children = clone(base.children ? base.children : base._children); 
			}
		}
		update(d);
	}

	/**
	 * Reposition the node at the visible root of the tree on double click. If double click is on the visible root, 
	 * move that node down one level and put it's parent at the visible root position
	 * @param d The node that was doubleclicked
	 */
	function doubleclick (d) { 
		d3.event.stopPropagation();

		if (d.depth != 0) {   // If we are not clicking on the root 
			stixroot = d;
			expand(d);
			update(d); 
		} else if (d.parent) {    // we are clicking on the root 
			d.parent.depth = -1;
			doubleclick(d.parent);
		} 

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
	 * Given a nodeId, find the node in the tree that has that value for its nodeId attribute
	 * @param nodeId
	 * @returns
	 */
	function findBaseNode (nodeId) { 
		var queue = [report];
		var node;
		while (queue.length > 0) {
			node = queue.shift();
			if ('nodeId' in node && node.nodeId == nodeId) { 
				return node;
			} else { 
				if (node.children) { 
					$.each(node.children,function(i,c) { queue.push(c); });
				} else if (node._children) { 
					$.each(node._children,function(i,c) { queue.push(c); });
				}
			} 	
		} 
		return null;
	};

	/**
	 * Returns true if the node has children or if the base node with the same nodeId has children
	 * @param d
	 * @returns
	 */
	function hasChildren (d) {
		if (hasDirectChildren(d)) return true;
		else if (d.nodeIdRef) { 
			var base = findBaseNode(d.nodeIdRef);
			return base ? hasDirectChildren(base) : false;
		}
	}

	/**
	 * Returns true only if the node has direct children (either d.children or d._children)
	 * @param d
	 * @returns {Boolean}
	 */
	function hasDirectChildren (d) { 
		return (d.children && d.children.length > 0) || (d._children && d._children.length > 0);
	}

	/**
	 *  Get the name to display under the node. 
	 */
	function getName (d) { 
		return d.name ? d.name : (d.nodeIdRef && findBaseNode(d.nodeIdRef)) ? findBaseNode(d.nodeIdRef).name : d.subtype ? d.subtype : "";
	}

	/**
	 * Get the id of the node in the XML.
	 * @param d
	 * @returns
	 */
	function getId (d) { 
		return d.nodeId ? d.nodeId : d.nodeIdRef ? d.nodeIdRef : "";
	}

	/**
	 * Clone a list of nodes. Used to create the "infinite tree" when a copy of a node that is defined in 
	 * another part of the structure is clicked on 
	 * @param dlist
	 * @returns {Array}
	 */
	function clone (dlist) {
		var clist = [];
		$.each(dlist, function (i,d) { 
			var data = {name:d.name,type:d.type,linkType:d.linkType,nodeIdRef:d.nodeId ? d.nodeId : d.nodeIdRef};
			if (hasDirectChildren(d)) { 
				data._children = clone(d.children ? d.children : d._children);
			}
			clist.push(data);
		});
		return clist;
	}


	/**
	 *  Compute the angle of a link from source to target without bezier curve. Used to determine the orientation 
	 *  of arrow markers on links
	 */
	function computeAngle (d) { 
		dy = d.target.y - d.source.y;
		dx = d.target.x - d.source.x;
		rad = Math.atan(-dx/dy);
		return (rad * 200/Math.PI)+90; // use 200 rather than 180 because the bezier makes the angle slightly sharper at the point we are placing the arrow
	}



};

// export StixTree module
module.exports = StixTree;


