var nodeWidth = 60,
 nodeHeight = 60,
 nodeSep = 160;
var i = 0;


// Root is the node that is currently at the top of the tree. Report is the root of the entire report
var stixroot,report,svg,layout;

var xmlDocs = [];


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

var tree = d3.layout.tree().nodeSize([ nodeWidth, nodeHeight ]).size([treeWidth(),height]);

var diagonal = d3.svg.diagonal()
.source(function (d) { 
	return {x:d.source.x, y:d.source.y+nodeHeight};
})
.projection(function(d) {
        return [ d.x, d.y ];
    });

	

var duration = 750;

var findBaseNode;

var typeIconMap = {
	"ThreatActors" : "ThreatActor",
	"TTPs" : "TTP",
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
	"ExploitTarget" : "ExplotTarget",
	"top" : "Report"
};



$(function() {
	$('#files').on('change', function () { handleFileSelect($(this)); });
	
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
			fxName:					"none",
		},
		center: { 
			minSize:400,
		},
		south: {
			initClosed:true,
			size:200,
			maxSize:300,
		} 			
	});
	
	// 98% fits the div vertically in the window including the upper and lower padding
//	$('#treeView').height($(window).height()-$('nav').outerHeight());
//	$('#htmlView').css('display','none');
//	$('#htmlView').resizable({
//		handles:"n",
//		resize: function (event, ui) {
//			ui.element.css("top","0");
//
//			$('#treeView').height($(window).height() - $('nav').outerHeight() - $('#htmlView').outerHeight());
//			$('#treeView').width($(window).width());
//			
//			
//			// Even though the width shouldn't be changing here, it is necessary to do this 
//			// to reverse the effect of the resize event propagating up to the window
//			// For some reason the window width gets set to the width minus the scrollbar when 
//			// resizing the html panel upward, but then gets reset back to the correct value here. 
//			tree.size([$(window).width()-margin.left-margin.right,height]);
//
//			if (stixroot) { 
//				update(stixroot);
//			}
//		}
//	});

	
	svg = d3.select("#treeView").append("svg")
    .append("g")
    .attr("transform","translate(" + margin.left + "," + margin.top + ")");

	svg.append("defs")
	.append("filter")
	.attr("id","lighten")
	.append("feColorMatrix")
		.attr("type","matrix")
		.attr("values","1 .5 .5 0 0  .5 1 .5 0 0  .5 .5 1 0 0  0 0 0 1 0");


	$(window).resize(function (e) { 
		//$('#treeView').width($(window).width());
		//$('#treeView').height($(window).height() - $('nav').outerHeight() - ($('#htmlView').css('display') == 'none' ? 0 : $('#htmlView').outerHeight()));

		tree.size([treeWidth(),height]);

		if (stixroot) { 
			update(stixroot);
		}
	});
	
});


	

// Compute the new tree layout.
function displayTree(jsonString) {
	
	
	svg.selectAll("g.node").remove();

    report = $.parseJSON(jsonString);
    stixroot = report;
	
    stixroot.y0 = height / 2;
    stixroot.x0 = 0;
		
    stixroot.children.forEach(collapse);
		
    addParents(stixroot);

    update(stixroot);

}
	

function collapse(d) {
    if (d.children) {
        d._children = d.children;
        d._children.forEach(collapse);
        d.children = null;
    }
}

function expand (d) { 
	if (d._children) { 
		d.children = d._children; 
		d._children = null;
	}
}
	

// add parents to each node so that we can walk back up the tree after drilling down
function addParents(parent) { 
    if (parent.children && parent.children.length > 0) { 
        parent.children.forEach(function (child) {
                child.parent = parent;
                addParents(child);
            });
    }
			
}
	
function update(source) {

    var nodes = tree.nodes(stixroot),//.reverse(),
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
                return "translate(" + (source.x0 + (nodeHeight/2)) + "," + (source.y0 + (nodeWidth/2)) + ")";
            })
        .on("click", click)
        .on("dblclick",doubleclick)
        .classed("parent",function(d) { 
                return d.children || d._children;
            });

    nodeEnter.append("title")
    .text(getName);
		
    nodeEnter.append("svg:image")
        .attr("height", 1e-6)
        .attr("width", 1e-6)
        .attr("xlink:href",function (d) {  return "./public/icons/13-008 ICONS - STIX_"+typeIconMap[d.type]+".png"; })
        .attr("transform","translate("+ -nodeWidth/2 + ")")
        .attr("class", function(d) { return d.type; })
        .attr("filter",function (d) { 
            return !hasChildren(d) ? "url(#lighten)" : "none"; 
        })
        .classed("leaf",function (d) { 
            return !hasChildren(d);             
            });
	      
	      
    nodeEnter.append("text")
        .attr("y", function(d) { return nodeHeight + 12; })
        .attr("text-anchor", "middle")
        .text(getName)
        .style("fill-opacity", 1e-6);
		

    $(".node").on("mouseenter", function () { 
    	var d = d3.select(this).datum();  
    	var nodeId = d.nodeId ? d.nodeId : d.nodeIdRef;
    	if (!nodeId) return;
    	var matches = d3.selectAll(".node").filter(function (d) { 
    		return d.nodeId == nodeId || d.nodeIdRef == nodeId;
    	});
    	if (matches.size() > 1) { 
    		matches.append("rect")
    		.attr("height", String(nodeHeight+10)+"px")
    		.attr("width", String(nodeWidth+10)+"px")
    		.attr("rx","10")
    		.attr("ry","10")
    		.attr("class","nodeborder")
    		.attr("transform","translate("+ -(nodeWidth+10)/2 + "," + "-5" + ")");
    	}
    });
    
    $(".node").on("mouseleave", function () { 
    	svg.selectAll("rect.nodeborder").remove();
    });

    // wrap text description
    svg.selectAll('text').each(wraptext);


    // Transition nodes to their new position.
    var nodeUpdate = node.transition()
        .duration(duration)
        .attr("transform",function(d) {	return "translate(" + d.x + "," + d.y + ")";	});

    nodeUpdate.select("image")
        .attr("height", String(nodeHeight)+"px")
        .attr("width", String(nodeWidth)+"px");

    nodeUpdate.select("text").style("fill-opacity", 1);

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

function hasChildren (d) {
	if (hasDirectChildren(d)) return true;
	else if (d.nodeIdRef) { 
		var base = findBaseNode(d.nodeIdRef);
		return base ? hasDirectChildren(base) : false;
	}
}

function hasDirectChildren (d) { 
	return (d.children && d.children.length > 0) || (d._children && d._children.length > 0);
}

function getName (d) { 
	return d.name ? d.name : d.nodeIdRef ? findBaseNode(d.nodeIdRef).name : d.subtype ? d.subtype : "";
}

function clone (dlist) {
	var clist = [];
	$.each(dlist, function (i,d) { 
		if (!hasDirectChildren(d)) { 
			clist.push({name:d.name,type:d.type,nodeIdRef:d.nodeId ? d.nodeId : d.nodeIdRef});
		} else { 
			clist.push({name:d.name,type:d.type,nodeIdRef:d.nodeId ? d.nodeId : d.nodeIdRef,_children:clone(d.children ? d.children : d._children)});
		}	
	});
	return clist;
}

function handleFileSelect(fileinput) {
	
    var mime = require('mime');
		
    var files = fileinput.get(0).files;

    // If only one JSON file was loaded (for testing)
    if (files.length == 1 && mime.lookup(files[0].name).match('application/json')) { 
    	// remove old xml docs
    	xmlDocs = [];
    	$('#xmlFileList').empty();

        var reader = new FileReader();

        // Closure to capture the file information.
        reader.onload = (function(theFile) {
          return function(e) {
            displayTree(e.target.result);
          };
        })(files[0]);

        // Read in the JSON file as text
        reader.readAsText(files[0]);

    } else { 
    	$(files).each(function (index, f) {
    		var mimetype = mime.lookup(f.name);

    		// Only process xml files.
    		if (!mimetype.match('application/xml')) {
    			return;
    		}
    	});

    	// remove old xml docs
    	xmlDocs = [];
    	$('#xmlFileList').empty();

    	// create json tree structure from xml files read in
    	generateTreeJson(files);
    }

};


function addXmlDoc (f,xml) { 
	
	var i = xmlDocs.length;
	xmlDocs.push({name:f,xml:xml});
	$('#htmlView').empty();

	$('#xmlFileList').append('<li><a id="xmlFile-'+i+'" href="#">'+f+'</a></li>');
    $('#xmlFile-'+i).on("click", function () { 
    	layout.open("south");

    	xml = xmlDocs[$(this).attr("id").split("-")[1]].xml;
    	xslFileName = "public/xslt/stix_to_html.xsl";
    	
    	xslt = Saxon.requestXML(xslFileName);
    	processor = Saxon.newXSLT20Processor(xslt);
    	processor.setSuccess(function (proc) { 
    		resultDocument = proc.getResultDocument();
        	wrapperHtml = new XMLSerializer().serializeToString($(resultDocument).find('#wrapper').get(0));
        	$('#htmlView').append(wrapperHtml);

        	runtimeCopyObjects();
    	});
    	
    	processor.transformToDocument(xml);

    });
}




function toggleHtml () {
	layout.toggle("south");
}
