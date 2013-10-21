var nodeWidth = 60,
 nodeHeight = 60,
 nodeSep = 160,
 markerSize = 6;
var nodeCount = 0;

// Root is the node that is currently at the top of the tree. Report is the root of the entire report
var stixroot,report,svg,layout;

// Id of the node that was last right-clicked
var contextNode = null;

var xmlDocs = {}, docIndex = 0;


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
});


	

var duration = 750;


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
			fxName:					"none"
		},
		center: { 
			minSize:400
		},
		south: {
			initClosed:true,
			size:200
		} 			
	});
	
	$('#loadingDiv').hide();
	
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
	
	$('#showHtml').on('click',function () {
		$("#contextMenu").hide();
		showHtmlByContext(contextNode);
	});
	
	$(document).click(function () { 
		$('#contextMenu').hide();
	});
	
});


	

// Compute the new tree layout.
function displayTree(jsonString) {
	
	


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
        .on("contextmenu", function (data,index) {
        	contextNode = data;
        	if (getId(data) || htmlSectionMap[data.type]) { 
        		$('#showHtml').removeClass('disabled');
        	} else { 
        		$('#showHtml').addClass('disabled');
        	}
        	position = d3.mouse(this);
        	offset = $(this).offset();
        	scrollTop = $('#treeView').scrollTop(); 
        	d3.select("#contextMenu")
        	.style('position','absolute')
        	.style('left',(position[0]+offset.left+(nodeWidth/2))+'px')
        	.style('top',(position[1]+offset.top-nodeHeight+scrollTop)+'px')
        	.style('display','block');
        	d3.event.preventDefault();
        })
        .classed("parent",function(d) { 
                return hasChildren(d);
            });
        
    	

    nodeEnter.append("title")
    .text(function (d) { 
    	return (getId(d) + '\n' + getName(d)).trim(); });
		
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
	      
    nodeEnter.filter(".parent").append('rect')
	.attr("height", String(1e-6)+"px")
	.attr("width", String(1e-6)+"px")
	.attr("rx","10")
	.attr("ry","10")
	.attr("class","parentborder")
	.attr("transform","translate("+ -(nodeWidth+4)/2 + "," + "-2" + ")");
	      
    nodeEnter.append("text")
        .attr("y", function(d) { return nodeHeight + 12; })
        .attr("text-anchor", "middle")
        .text(getName)
        .style("fill-opacity", 1e-6);
		

    $(".node").on("mouseenter", function () {
    	var d = d3.select(this).datum();  
    	var nodeId = d.nodeId ? d.nodeId : d.nodeIdRef;

    	highlightDuplicateNodes(nodeId);
    	highlightHtml(nodeId);
    });
    
    $(".node").on("mouseleave", function () { 
    	removeHighlightedNodes();
    	$(".objectReference").removeClass("infocus");
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

    nodeUpdate.select('rect')
    	    .attr("height",String(nodeHeight+4)+"px")
    	    .attr("width",String(nodeWidth+4)+"px");

//    var dot = d3.selectAll('.node.parent')
//    .append('circle')
//    .attr("cx","0")
//    .attr("cy","63")
//    .attr("r","1e-6")
//    .attr("stroke","gray")
//    .attr("fill","white");
    


    
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

    
    var marker = svg.select("defs")
		.selectAll("marker")
	    .data(links, function (d) { return d.target.id; });
    
    
    // Add new markers
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
    
    
    //Reset position of all markers 
    marker.attr("refY", function (d) { return (1/markerSize)*(90-computeAngle(d));})
		.attr("orient",computeAngle);


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
    
    
    // After the links have moved to their position, show the arrows and the dots on the nodes
    marker.transition()
    .duration(duration)
	.attr("markerWidth",markerSize)
	.attr("markerHeight",markerSize);
	
//    dot.transition()
//    .duration(duration)
//    .attr("r",4);
    
   

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

// Highlight all nodes in the tree that match the given nodeId. If the highlight command is coming
// from a hover over the html, highlight all matches. If it is coming from the tree itself, only 
// highlight if there is more than one match (don't just highlight the singleton node)
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

function removeHighlightedNodes () { 
	svg.selectAll("rect.nodeborder").remove();
}

function highlightHtml (nodeId) { 
	if (!nodeId) return;
	$(".topLevelCategoryTable .objectReference:contains('"+nodeId+"')").addClass("infocus");
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

function getId (d) { 
	return d.nodeId ? d.nodeId : d.nodeIdRef ? d.nodeIdRef : "";
}


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

function handleFileSelect(fileinput) {
	
    var mime = require('mime');
		
    var files = fileinput.get(0).files;

    // If only one JSON file was loaded (for testing)
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

    } else { 
    	// remove old xml docs
    	reset();
    	
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

function reset () { 
	xmlDocs = {};
	docIndex = 0;
	$('#xmlFileList').empty();
	svg.selectAll("g.node").remove();
	$('#htmlView').empty();
}


// Compute the angle of a link from source to target without bezier
function computeAngle (d) { 
	dy = d.target.y - d.source.y;
	dx = d.target.x - d.source.x;
	rad = Math.atan(-dx/dy);
	return (rad * 200/Math.PI)+90;
}

var working = {};


// The processing of xslt transforms takes some time. Show the cursor as busy during that time
function addXmlDoc (f,xml) { 
	working[f] = true;
	$('body').addClass('loading');
	
	var num = docIndex++;
	
	xslFileName = "public/xslt/stix_to_html.xsl";
	
	xslt = Saxon.requestXML(xslFileName);
	var processor = Saxon.newXSLT20Processor(xslt);
	processor.setSuccess((function (filename,xmlString,index) { 
		return function (proc) {
			resultDocument = proc.getResultDocument();
			//wrapperHtml = new XMLSerializer().serializeToString($(resultDocument).find('#wrapper').get(0));
			xmlDocs[index] = {name:filename,xml:xmlString,html:resultDocument};
			delete working[filename];
			if (Object.keys(working).length == 0) { 
				$('body').removeClass('loading');
			}
		};
	})(f,xml,num));
	
	setTimeout(function () { processor.transformToDocument(xml); }, 200);

	
	$('#xmlFileList').append('<li><a id="xmlFile-'+num+'" href="#">'+f+'</a></li>');

	$('#xmlFile-'+num).on("click", function () {
		html = xmlDocs[$(this).attr("id").split("-")[1]].html;
		showHtml(new XMLSerializer().serializeToString($(html).find('#wrapper').get(0)));
		$('#htmlView').scrollTop(0);
    });
	
	
}

// If the node has an id, find the DOM element with that id, otherwise find the DOM element that matches the type section header. 
function showHtmlByContext (data) {
	var waitForXslt = setInterval(function () {
		if (Object.keys(working).length == 0) { 
			clearInterval(waitForXslt);
			var nodeid = getId(data);
			if (nodeid) {
				$.each(xmlDocs, function (i,entry) {
					if ($(entry.html).find(".topLevelCategoryTable .objectReference:contains('"+nodeid+"')").get(0) != undefined) {
						showHtml(new XMLSerializer().serializeToString($(entry.html).find('#wrapper').get(0)));
						$(".topLevelCategoryTable .objectReference:contains('"+nodeid+"')").get(0).scrollIntoView();
						$(".objectReference:contains('"+nodeid+"')").addClass("infocus");
						return false;
					} else { 
						return true;
					}
				});
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

function showHtml (html) { 
	$('#htmlView').empty();
	layout.open("south");
	$('#htmlView').addClass("loading");
	$('body').addClass("loading");
	
	$('#htmlView').append(html);
	
	$(".objectReference").on("mouseenter", function () { 
		$(this).addClass("infocus");
		highlightDuplicateNodes($(this).text());
	});

	$(".objectReference").on("mouseleave", function () {
		$(this).removeClass("infocus");
		removeHighlightedNodes();
	});
	
	$('#htmlView').removeClass("loading");
	$('body').removeClass("loading");

}


