$(function() {
	
	$('#files').on('change', function () { handleFileSelect($(this)); });

	
	function handleFileSelect(fileinput) {
		var mime = require('mime');
		
		var files = fileinput.get(0).files;

	    // render the first file entered as a tree
	    var f = files[0];

	    var mimetype = mime.lookup(f.name);
	    
	    // Only process json files.
	    if (!mimetype.match('application/json')) {
	        return
	    }

	    var reader = new FileReader();

	    // Closure to capture the file information.
	    reader.onload = (function(theFile) {
	      return function(e) {
	      	displayTree(e.target.result);
	      };
	    })(f);

	    // Read in the JSON file as text
	    reader.readAsText(f);
	};



	var typeLabelMap = {"ThreatActors":"Threat Actors","TTPs":"TTPs","AttackPattern":"Attack Pattern", "Indicator": "Indicator", 
			"MalwareBehavior":"Malware Behavior","Observable":"Observable","Observable-ElectronicAddress": "Observable",
			"Observable-Email":"Observable", "Observable-IPRange":"Observable",
			"Observable-MD5":"Observable","Observable-URI":"Observable", "ObservedTTP":"TTP", "threatActor": "Threat Actor",
			"top":"Report", "UsesTool":"TTP", "VictimTargeting":"Victim Targeting", "Indicator-Utility":"Indicator",
			"Indicator-Composite":"Indicator","Indicator-Backdoor":"Indicator","Indicator-Downloader":"Indicator"};


	var nodeWidth = 60;
	var nodeHeight = 40;
	var i = 0;

	var tree,root,svg,diagonal;
	
	var margin = {
			top : 20,
			right : 10,
			bottom : 20,
			left : 10
	}, 
	width = 1100 - margin.right - margin.left,
	height = 1200 - margin.top- margin.bottom;
	

	var duration = 750;
	

	// Compute the new tree layout.
	function displayTree(report) { 


		tree = d3.layout.tree().size([ width, height ]);

		diagonal = d3.svg.diagonal().projection(function(d) {
			return [ d.x, d.y + nodeHeight];
		});

		d3.select("svg").remove();
		
		svg = d3.select("#content").append("svg")
		.attr("width", width + margin.right + margin.left)
		.attr("height", height + margin.top + margin.bottom)
		.append("g")
		.attr("transform","translate(" + margin.left + "," + margin.top + ")");
		
		

		root = $.parseJSON(report);
		root.y0 = height / 2;
		root.x0 = 0;
		
		
		root.children.forEach(collapse);
		
		addParents(root);

		update(root);


		//d3.select(self.frameElement).style("height", "800px");
	}
	

	function collapse(d) {
		if (d.children) {
			d._children = d.children;
			d._children.forEach(collapse);
			d.children = null;
		}
	}
	
	function addParents(parent) { 
		if (parent.children && parent.children.length > 0) { 
			parent.children.forEach(function (child) {
					child.parent = parent;
					addParents(child);
					});
		}
			
	}
	
	function update(source) {

		var nodes = tree.nodes(root),//.reverse(),
			links = tree.links(nodes);

		// Update the nodes…
		node = svg.selectAll("g.node")
		.data(nodes, function(d) {
			return d.id || (d.id = ++i);
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
		nodes.sort(function(a,b) { return a.id - b.id; } ).forEach(function(d,i) {
			if (zigzag[d.depth] && i % 2 == 0) { 
				d.y = (d.depth * 180) + 80;
			} else { 
				d.y = d.depth * 180;
			}
		});


		// Enter any new nodes at the parent's previous position.
		var nodeEnter = node.enter()
		.append("g")
		.attr("class", "node")
		.attr("transform", function(d) {
			return "translate(" + (source.x0 + (nodeHeight/2)) + "," + (source.y0 + (nodeWidth/2)) + ")";
			})
		.on("click", click)
		.on("dblclick",doubleclick)
		.classed("parent",function(d) { 
	    	  return d.children || d._children;
		  });

		
		 nodeEnter.append("rect")
	      .attr("height", 1e-6)
	      .attr("width", 1e-6)
	      .attr("rx", "5") // round the corners with rx and ry
	      .attr("ry", "5")
	      .attr("transform","translate("+ -nodeWidth/2 + ")")
	      .attr("class", function(d) { return d.type; })
	      .classed("leaf",function (d) { 
	    	 return (!d.children && !d._children) || (d.children && d.children.length == 0) || (d._children && d._children.length == 0); 
	      });
	      
	      
		nodeEnter.append("text")
		.attr("y", function(d) { return nodeHeight + 12; })
		.attr("text-anchor", "middle")
		.text(function(d) {return d.name;})
		.style("fill-opacity", 1e-6);
		
		// add node type labels (indicator, ttp, ...)
		nodeEnter.append("text")
		.attr("dy", nodeHeight/2)
		.attr("class", "NodeTypeLabel")
		.style("text-anchor", "middle")
		.text(function(d) { 
			return typeLabelMap[d.type];	
			});
		

		// wrap text description
		svg.selectAll('text').each(wraptext);


		// Transition nodes to their new position.
		var nodeUpdate = node.transition()
		.duration(duration)
		.attr("transform",function(d) {	return "translate(" + d.x + "," + d.y + ")";	});

		nodeUpdate.select("rect")
	      .attr("height", nodeHeight)
	      .attr("width", nodeWidth)
	      .attr("rx", "5") // round the corners with rx and ry
	      .attr("ry", "5");
	      

		nodeUpdate.select("text").style("fill-opacity", 1);

		// Transition exiting nodes to the parent's new position.
		var nodeExit = node.exit().transition().duration(duration).attr(
				"transform", function(d) {
					return "translate(" + (source.x + (nodeWidth/2)) + "," + (source.y + (nodeWidth/2)) + ")";
				}).remove();

		nodeExit.select("rect")
		.attr("height", 1e-6)
		.attr("width", 1e-6);

		nodeExit.select("text")
		.style("fill-opacity", 1e-6);
		


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
				});

		// Transition links to their new position.
		link.transition()
		.duration(duration)
		.attr("d", diagonal);

		// Transition exiting nodes to the parent's new position.
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

	// Toggle children on click.
	function click(d) {
		d3.event.stopPropagation();
		if (d.children) {
			d._children = d.children;
			d.children = null;
		} else {
			d.children = d._children;
			d._children = null;
		}
		update(d);
	}
	
	function doubleclick (d) { 
		d3.event.stopPropagation();
		
		if (d.depth != 0) { 
			root = d;
			update(d); 
		} else if (d.parent) { 
			d.parent.depth = -1;
			doubleclick(d.parent);
		} 
		
	}
	
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
			
		}

});
