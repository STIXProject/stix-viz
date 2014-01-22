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


var StixGraph = function () { 
	
	var _self = this;
	
	var nodeWidth = 60,
	nodeHeight = 60,
	markerSize = 6,
	labelHeight = 20;


	/* Root is the node that is currently visible at the top of the tree. Report is the root of the entire structure.*/
	var report,svg,node,link;


	/* Id of the node that was last right-clicked */
	var contextNode = null;

//	var xmlDocs = {}, docIndex = 0;

	/* Layout of tree within its div */
	var margin = {
			top : 20,
			right : 20,
			bottom : 35,
			left : 10
	};

	function graphSize () { 
		return [$(window).width() - nodeWidth,$(window).height()-nodeHeight-100];
	}

	/**
	 * Construct the force layout object 
	 */
	var force = d3.layout.force()
	.linkDistance(170)
	.linkStrength(1)
	.friction(.6)
	.charge(-200)
	.gravity(.001)
	.size(graphSize())
	.on("tick", tick);

	/**
	 * Duration of animated transitions
	 */
	var duration = 750;



	_self.resize = function () { 

			force.size(graphSize());


			update();
	}


	/**
	 *  Compute the graph layout based on the JSON representation of the XML data
	 */
	_self.display = function (jsonString) {

		
		/**
		 *  Append svg container for tree
		 */
		svg = d3.select("#contentDiv").append("svg")
	    .append("g")
	    .attr("transform","translate(" + margin.left + "," + margin.top + ")");

		/**
		 *  define color filter for lightening non-expandable nodes
		 */
		svg.append("defs")
		.append("filter")
		.attr("id","lighten")
		.append("feColorMatrix")
			.attr("type","matrix")
			.attr("values","1 .5 .5 0 0  .5 1 .5 0 0  .5 .5 1 0 0  0 0 0 1 0");
		
		
		// define arrow markers for graph links
		svg.select('defs').append('svg:marker')
		    .attr('id', 'end-arrow')
		    .attr('viewBox', '0 -5 10 10')
		    .attr('refX', 60)
		    .attr('markerWidth', 5)
		    .attr('markerHeight', 5)
		    .attr('orient', 'auto')
		    .attr('class','arrow')
		  .append('svg:path')
		    .attr('d', 'M0,-5L10,0L0,5');


		link = svg.selectAll(".link");
		node = svg.selectAll(".node");

		report = $.parseJSON(jsonString);
		
		removeBottomUp(report);		
		flatten(report); // this will set the correct ids for all nodes in the graph 
		report.children.forEach(collapse);

		// This is where the tree actually gets displayed
		update();

	};

	/**
	 * Collapse node d by moving "children" to "_children"
	 * @param d
	 */
	function collapse(d) {
		if (d.children) {
			d._children = d.children;
			d._children.forEach(collapse);
			d.children = [];
		}
	}
	
	/**
	 * Remove links that are "bottom up" since they are only needed for tree view
	 */
	function removeBottomUp(d) {
		if (d.children) { 
			d.children = d.children.filter(function(c) { return c.linkType === 'topDown'; });
			d.children.forEach(removeBottomUp);
		}
		if (d._children) { 
			d._children = d._children.filter(function (c) { return c.linkType === 'topDown'; });
			d._children.forEach(removeBottomUp);
		}
	}

	/**
	 * Expand node d by moving "_children" to "children"
	 * @param d
	 */
	function expand (d) { 
		if (d._children) { 
			d.children = d._children; 
			d._children = [];
		}
	}


	/** 
	 * Update the tree display starting at node "source"
	 * @param source The root node for the update
	 */
	function update() {

		var data = flatten(report), 
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

		link.enter().insert("line", ".node")
		.attr("class", "link")
		.attr("marker-end",function(d){ 
			return "url(#end-arrow)"; 
		});

		// Update nodes.
		node = node.data(nodes, function(d) { return d.id; });

		node.exit().remove();
		
		node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });


		var nodeEnter = node.enter().append("g")
		.attr("class", "node")
		.classed("parent",function(d) { 
			return hasChildren(d);
		})
		.on("click", click)
		.on("contextmenu", function (d) {
			position = d3.mouse(this);
			offset = $(this).offset();
			scrollTop = $('#viewContainer').scrollTop(); 
			showContext(d,(position[0]+offset.left+(nodeWidth/2))+'px',(position[1]+offset.top-nodeHeight+scrollTop)+'px');
		})
		.call(force.drag);


		// Append the image icon according to typeIconMap
		nodeEnter.append("svg:image")
		.attr("height", String(nodeHeight)+"px")
		.attr("width", String(nodeWidth)+"px")
		        .attr("xlink:href",function (d) { 
        	if (d.type == 'top') 
        		return "./public/icons/report.png";
        	else
        		return "./public/xslt/images/"+typeIconMap[d.type]+".svg"; 
        	})
		.attr("transform","translate("+ -nodeWidth/2 + "," + -nodeHeight/2 + ")")
		.attr("class", function(d) { return d.type; })
		.attr("filter",function (d) { 
			return !hasChildren(d) ? "url(#lighten)" : "none";   // lighten the color of leaf nodes
		})
		.classed("leaf",function (d) { 
			return !hasChildren(d);             
		});

		// Add rounded rectangle "border" to all expandable parent nodes
		nodeEnter.filter(".parent").append('rect')
		.attr("height", String(nodeHeight+4)+"px")
		.attr("width", String(nodeWidth+4)+"px")
		.attr("rx","10")
		.attr("ry","10")
		.attr("class","parentborder")
		.attr("transform","translate("+ -(nodeWidth+4)/2 + "," + ((-nodeHeight/2) - 2) + ")");

		// Append text label to each node
		nodeEnter.append("text")
		.attr("y", function(d) { return nodeHeight + 12; })
		.attr("text-anchor", "middle")
		.attr("transform","translate(0,"+ -nodeHeight/2 +")")
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

			highlightHtml(nodeId);
		});

		// handler to remove highlighting when the mouse leaves the node
		$(".node").on("mouseleave", function () { 
			removeHighlightedNodes();
			$(".expandableContainer tr").removeClass("infocus");
		});


		// wrap text description 
		svg.selectAll('text').each(wraptext);


	}


	

	/** 
	 * Toggle node expansion on click
	 * @param d The node that was clicked
	 */
	function click(d) {
		if (d3.event.defaultPrevented) return; // ignore drag
		if (d._children) {
			d.children = d._children;
			d._children = null;
			d.children.forEach(function (c) { 
				node.each(function (n) {
					if (n._children) { 
						n._children.forEach(function (nc) { 
							if (nc.id && nc.id === c.id) { 
								n.children.push(nc);
							}
						});
					}
				});
			});
		} else {
			d._children = d.children;
			d.children = [];
		} 
		update();
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


		link.attr("x1", function(d) { return d.source.x; })
		.attr("y1", function(d) { return d.source.y; })
		.attr("x2", function(d) { return d.target.x; })
		.attr("y2", function(d) { return d.target.y; });

		node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
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
	 * Returns true if the node has children or if the base node with the same nodeId has children
	 * @param d
	 * @returns
	 */
	function hasChildren (d) { 
		return (d.children && d.children.length > 0) || (d._children && d._children.length > 0); 
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



	var nodeid = 0;
//	Returns a list of all nodes under the root.
	function flatten(root) {
		var nodes = [], links = [];

		function recurse(node,depth,parent) {

			var ref = null;
			var pos;
			if (getId(node)) {
				ref = nodes.filter(function (n) { return getId(n) === getId(node);})[0];
			}
			if (!node.id && !ref) { 
				node.id = nodeid++;
				node.depth = depth;
			}

			if (ref) {
				pos = nodes.indexOf(ref);
				if (!node.id) node.id = ref.id;
				if (!node.name) node.name = ref.name;
				else if (!ref.name) ref.name = node.name;
			} else {
				nodes.push(node);
				pos = nodes.length-1;
			}

			if (typeof parent !== 'undefined') {
				if (links.filter(function (l) { return l.source === parent && l.target === pos; }).length == 0) {
					links.push({source:parent,target:pos});
				}
			} else { 
				node.fixed = true;
				node.px = graphSize()[0]/2;
				node.py = graphSize()[1]/2;
			}

			// Only use top down links in the graph view
			if (node.children) { 
				node.children.forEach(function (n) { recurse(n,depth+1,pos);
				});
				
			}

		}

		recurse(root,0);
		return {nodes:nodes,links:links};
	}

	/**
	 * Remove all node highlighting
	 */
	function removeHighlightedNodes () { 
		d3.selectAll("rect.nodeborder").remove();
	}

	

	/**
	 * Highlight all nodes in the tree that match the given nodeId. 
	 * 
	 * @param nodeId The id of the node to highlight
	 */
	function highlightDuplicateNodes (nodeId) { 
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
		.attr("transform","translate("+ -(nodeWidth+10)/2 + "," + "-5" + ")");
	}




}
