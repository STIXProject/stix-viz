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



var nodeWidth = 60,
 nodeHeight = 60,
 nodeSep = 160,
 markerSize = 6;
var nodeCount = 0;

/* Root is the node that is currently visible at the top of the tree. Report is the root of the entire structure.*/
var stixroot,report,svg,node,link,layout;


/* Id of the node that was last right-clicked */
var contextNode = null;

//var xmlDocs = {}, docIndex = 0;

/* Layout of tree within its div */
var margin = {
    top : 20,
    right : 20,
    bottom : 35,
    left : 10
}, 
    width = 1100 - margin.right - margin.left,
    height = 1200 - margin.top- margin.bottom;
	
function graphSize () { 
	return [$(window).width() - nodeWidth,$(window).height()-nodeHeight-150];
}

/**
 * Construct the force layout object 
 */
var force = d3.layout.force()
.linkDistance(200)
.charge(-300)
.gravity(.02)
.size(graphSize())
.on("tick", tick);





/**
 * Duration of animated transitions
 */
var duration = 750;

/**
 * Mapping from node type to sections headings in the HTML rendering
 */
var htmlSectionMap = { 
	"ThreatActors":"Threat Actors",
	"TTPs":"TTPs",
	"Indicators":"Indicators",
	"Campaigns":"Campaigns",
	"CoursesOfAction":"Courses of Action",
	"Incidents":"Incidents",
	"ExploitTargets":"Exploit Targets",
	"Observables":"Observables"
};

/**
 * Mapping from node type to icon names to be used in the tree display
 */
var typeIconMap = {
	"ThreatActors" : "ThreatActor",
	"TTPs" : "TTP",
	"CourseOfAction" : "Course of Action",
	"CoursesOfAction" : "Course of Action",
	"AttackPattern" : "TTP",
	"Indicator" : "Indicator",
	"MalwareBehavior" : "TTP",
	"Observable" : "Observable",
	"Observable-ElectronicAddress" : "Observable",
	"Observable-Email" : "Observable",
	"Observable-IPRange" : "Observable",
	"Indicators" : "Indicator",
	"Campaigns" : "Campaign",
	"campaign" : "Campaign",
	"Observable" : "Observable",
	"Observables" : "Observable",
	"Observable-MD5" : "Observable",
	"Observable-URI" : "Observable",
	"ObservedTTP" : "TTP",
	"threatActor" : "ThreatActor",
	"UsesTool" : "TTP",
	"Tools" : "TTP",
	"VictimTargeting" : "Victim",
	"Indicator-Utility" : "Indicator",
	"Indicator-Composite" : "Indicator",
	"Indicator-Backdoor" : "Indicator",
	"Indicator-Downloader" : "Indicator",
	"Incident" : "Incident",
	"Incidents" : "Incident",
	"Exploit" : "ExplotTarget",
	"ExploitTarget" : "ExplotTarget",
	"ExploitTargets" :  "ExplotTarget",
	"top" : "Report"
};




$(function() {

	
	/**
	 *  Add handler for file select input
	 */
	$('#files').on('change', function () { handleFileSelect($(this)); });
	

	/**
	 *  Initialize the page layout. North section is nav menu, center is the tree view, south is the HTML view
	 */
	layout = $('body').layout({ 
		defaults: { 
			resizable:true,
			fxName:'slide',
			fxSpeed:'slow'
		},
		north: { 
			size:"auto",
			spacing_open:			0,			// cosmetic spacing
			togglerLength_open:		0,			// HIDE the toggler button
			togglerLength_closed:	-1,			// "100%" OR -1 = full width of pane
			resizable: 				false,
			slidable:				false,		//	override default effect
			fxName:					"none"
		},
		center: { 
			minSize:400
		},
		south: {
			initClosed:true,
			size:300
		} 			
	});
	
	/**
	 *  Append svg container for tree
	 */
	svg = d3.select("#treeView").append("svg")
    .append("g")
    .attr("width", width)
    .attr("height", height)
    .attr("transform","translate(" + margin.left + "," + margin.top + ")");

	
	link = svg.selectAll(".link");
    node = svg.selectAll(".node");
	
	
	/**
	 *  define color filter for lightening non-expandable nodes
	 */
	svg.append("defs")
	.append("filter")
	.attr("id","lighten")
	.append("feColorMatrix")
		.attr("type","matrix")
		.attr("values","1 .5 .5 0 0  .5 1 .5 0 0  .5 .5 1 0 0  0 0 0 1 0");
	

	/**
	 * When the window is resized, resize and update the tree 
	 */
	$(window).resize(function (e) { 

		force.size(graphSize());

		update();
	});
	
	/**
	 * Handler for top level Show HTML button
	 */
	$('#showHtml').on('click',function () {
		$("#contextMenu").hide();
		showHtmlByContext(contextNode);
	});
	
	/**
	 * If there's a context menu open, you can hide it by clicking somewhere else in the document
	 */
	$(document).click(function () { 
		$('#contextMenu').hide();
	});
	
});


	

/**
 *  Compute the tree layout based on the JSON representation of the XML data
 */
function displayTree(jsonString) {
	
    report = $.parseJSON(jsonString);
    		
    //report.children.forEach(collapse);
		
    // This is where the tree actually gets displayed
    update();

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
        .attr("class", "link");

    // Update nodes.
    node = node.data(nodes, function(d) { return d.id; });

    node.exit().remove();

    var nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .classed("parent",function(d) { 
                return hasChildren(d);
            })
        .on("click", click)
        .call(force.drag);

    
    // Append the image icon according to typeIconMap
    nodeEnter.append("svg:image")
    	.attr("height", String(nodeHeight)+"px")
    	.attr("width", String(nodeWidth)+"px")
        .attr("xlink:href",function (d) {  return "./public/icons/13-008 ICONS - STIX_"+typeIconMap[d.type]+".png"; })
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
  if (d3.event.defaultPrevented) return; // ignore drag
  if (d.children) {
    d._children = d.children;
    d.children = null;
  } else {
    d.children = d._children;
    d._children = null;
  }
  update();
}	

/** 
 * Reposition nodes and links on each tick
 */
function tick() {

	node.each(collide(0.5));

	link.attr("x1", function(d) { return d.source.x; })
	.attr("y1", function(d) { return d.source.y; })
	.attr("x2", function(d) { return d.target.x; })
	.attr("y2", function(d) { return d.target.y; });

	node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
}



//Resolves collisions between d and all other circles.
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
 * Remove all node highlighting
 */
function removeHighlightedNodes () { 
	svg.selectAll("rect.nodeborder").remove();
}

/**
 * Highlight the div in the HTML view corresponding to the given nodeId
 * @param nodeId
 */
function highlightHtml (nodeId) { 
	if (!nodeId) return;
	$(".topLevelCategory .expandableContainer[data-stix-content-id='"+nodeId+"'] tr").eq(0).addClass("infocus");
}


/**
 * Returns true if the node has children or if the base node with the same nodeId has children
 * @param d
 * @returns
 */
function hasChildren (d) { 
	return d.children || d._children;
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
 * Handle the selection of input file(s)
 * @param fileinput
 */
function handleFileSelect(fileinput) {
	
    var mime = require('mime');
		
    var files = fileinput.get(0).files;

    // If only one JSON file was loaded (for testing purposes only)
    if (files.length == 1 && mime.lookup(files[0].name).match('application/json')) { 
    	// remove old xml docs
    	reset();

        var reader = new FileReader();

        // Closure to capture the file information.
        reader.onload = (function(theFile) {
          return function(e) {
            displayTree(e.target.result);
          };
        })(files[0]);

        // Read in the JSON file as text
        reader.readAsText(files[0]);

    } else { // When one or more XML files are selected

    	reset();     	// remove old xml docs and reset display
    	
    	$(files).each(function (index, f) {
    		var mimetype = mime.lookup(f.name);

    		// Only process xml files.
    		if (!mimetype.match('application/xml')) {
    			return;
    		}
    	});


    	// create json tree structure from xml files read in
    	generateTreeJson(files);
    }

};

/**
 *  Reset the display when new XML files are loaded
 */
function reset () { 
	xmlDocs = {};
	docIndex = 0;
	$('#xmlFileList').empty();
	svg.selectAll("g.node").remove();
	svg.selectAll("path.link").remove();
	$('#htmlView').empty();
	layout.close("south");
}


var nodeid = 0;
//Returns a list of all nodes under the root.
function flatten(root) {
	var nodes = [], links = [], i = force.nodes().length;

	function recurse(node,parent) {

		var ref = null;
		var pos;
		if (getId(node)) {
			ref = nodes.filter(function (n) { return getId(n) === getId(node);})[0];
		}
		if (!node.id && !ref) { 
			node.id = nodeid++;
		}
		
		if (ref) {
			pos = nodes.indexOf(ref);
		} else {
			nodes.push(node);
			pos = nodes.length-1;
		}
		if (typeof parent !== 'undefined') { 
			links.push({source:parent,target:pos})
		} else { 
			node.fixed = true;
			node.x = graphSize()[0]/2;
			node.y = graphSize()[1]/2;
		}

		// Only use top down links in the graph view
		if (node.children) node.children.filter(function(c) { return c.linkType === 'topDown'; }).forEach(function (n) { recurse(n,pos);});

	}

  recurse(root);
  return {nodes:nodes,links:links};
}





/**
 * Show HTML view for a given node. 
 *  If the node has an id, find and scroll to the DOM element with that id, otherwise find the DOM element that matches 
 *  the type section header. 
 * @param data The node selected to show HTML
 */
function showHtmlByContext (data) {
	showProcessing();
	var waitForXslt = setInterval(function () { // wait until xslt processing is complete
		if (working == 0) { 
			clearInterval(waitForXslt);
			endProcessing();
			var nodeid = getId(data);
			if (nodeid) {
				var found = false;
				$.each(xmlDocs, function (i,entry) {
					if ($(entry.html).find(".topLevelCategory .expandableContainer[data-stix-content-id='"+nodeid+"']").get(0) != undefined) {
						showHtml(new XMLSerializer().serializeToString($(entry.html).find('#wrapper').get(0)));
						var objRef = $(".topLevelCategory .expandableContainer[data-stix-content-id='"+nodeid+"']"); 
						objRef.find('tr').eq(0).addClass("infocus");
						objRef.get(0).scrollIntoView();
						expandSection(objRef);
						found = true;
						return false;
					} else { 
						return true;
					}
				});
				// If we get here, there was no entry in xmldocs for the given node
				if (!found) { 
					showHtml("<div id='wrapper'><h2>Could not convert XML file to HTML</h2></div>");
				}
			} else { 
				var section = htmlSectionMap[data.type];
				$.each(xmlDocs, function (i,entry) {
					if ($(entry.html).find("h2 > a:contains('"+section+"')").get(0) != undefined) {
						showHtml(new XMLSerializer().serializeToString($(entry.html).find('#wrapper').get(0)));
						$("h2 > a:contains('"+section+"')").get(0).scrollIntoView();
						return false;
					} else { 
						return true;
					}
				});
			}
		}
	}, 200);
}


function showProcessing () { 
	
	
	$('#htmlView').empty();
	$('#htmlView').addClass('loading');
	$('#htmlView').append('<div id="loadingMessage"><h3> <img src="public/icons/spinner.gif"> Processing XML Transform</h3></div>');
	layout.open("south");
}

function endProcessing () { 
	
	$('#htmlView').removeClass('loading');
	$('#htmlView').empty();
}


/**
 * display the given HTML in the HTML view panel
 * @param html
 */
function showHtml (html) { 
	$('#htmlView').empty();
	layout.open("south");
	
	$('#htmlView').append(html);
	
	// Handlers to highlight associated tree nodes on mouseenter/mouseleave
	$(".topLevelCategory .expandableContainer[data-stix-content-id] tr:has(.expandableToggle)").on("mouseenter", function () { 
		$(this).addClass("infocus");
		highlightDuplicateNodes($(this).parents(".expandableContainer").data("stix-content-id"));
	});

	$(".topLevelCategory .expandableContainer[data-stix-content-id] tr:has(.expandableToggle)").on("mouseleave", function () {
		$(this).removeClass("infocus");
		removeHighlightedNodes();
	});
	

}

/**
 * Expand a given node in the HTML and then expand all of the nested expandable nodes (uses stix_to_html function
 * to expand nested expandables).
 * @param node
 */
function expandSection (node) { 
	node.find('.expandableToggle').click();
	expandNestedExpandables(node.get(0));
}

