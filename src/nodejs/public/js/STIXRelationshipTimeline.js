
//  A timeline component for d3
//  version v0.1

var StixTimeline = function () { 
    var _self = this;
    
    /* Id of the node that was last right-clicked */
    var contextNode = null;
    
    // chart geometry
    var margin = {
	top: 20, 
	right: 20, 
	bottom: 20, 
	left: 20
    },
    outerWidth = 1050,
    outerHeight = 500,
    width = outerWidth - margin.left - margin.right,
    height = outerHeight - margin.top - margin.bottom;

    _self.display = function (jsonString) {
	//alert(jsonString);
	// Define domElement and sourceFile
	var domElement = "#treeView";
	//var sourceFile = "./public/TempData/iSight-incidents.json";
	var sourceFile = "./public/TempData/testData1.json";

	/*var report = $.parseJSON(jsonString);
	timeline(domElement)
	.data(dataset)
	.band("mainBand", 0.82)
	.band("naviBand", 0.08)
	.xAxis("mainBand")
	.tooltips("mainBand")
	.xAxis("naviBand")
	.labels("mainBand")
	.labels("naviBand")
	.brush("naviBand", ["mainBand"])
	.redraw();
	*/

	// Read in the data and construct the timeline
	d3.json(sourceFile, function(dataset) {
	    timeline(domElement)
	    .data(dataset)
	    .band("mainBand", 0.82)
	    .band("naviBand", 0.08)
	    .xAxis("mainBand")
	    .tooltips("mainBand")
	    .xAxis("naviBand")
	    .labels("mainBand")
	    .labels("naviBand")
	    .brush("naviBand", ["mainBand"])
	    .redraw();

	});
	
    }


    function timeline(domElement) {
	/**
     * Mapping from node type to icon names to be used in the tree display
     */
	var typeIconMap = {
	    "ThreatActors" : "threat_actor",
	    "TTPs" : "ttp",
	    "CourseOfAction" : "course_of_action",
	    "CoursesOfAction" : "course_of_action",
	    "AttackPattern" : "attack_patterns",
	    "Indicator" : "indicator",
	    "MalwareBehavior" : "malware",
	    "Observable" : "observable",
	    "Observable-ElectronicAddress" : "observable",
	    "Observable-Email" : "observable",
	    "Observable-IPRange" : "observable",
	    "Indicators" : "indicator",
	    "Campaigns" : "campaign",
	    "campaign" : "campaign",
	    "Observable" : "observable",
	    "Observables" : "observable",
	    "Observable-MD5" : "observable",
	    "Observable-URI" : "observable",
	    "ObservedTTP" : "ttp",
	    "threatActor" : "threat_actor",
	    "UsesTool" : "tool",
	    "Tools" : "tool",
	    "VictimTargeting" : "victim_targeting",
	    "Indicator-Utility" : "indicator",
	    "Indicator-Composite" : "indicator",
	    "Indicator-Backdoor" : "indicator",
	    "Indicator-Downloader" : "indicator",
	    "Incident" : "incident",
	    "Incidents" : "incident",
	    "Exploit" : "exploit_target",
	    "ExploitTarget" : "exploit_target",
	    "ExploitTargets" :  "exploit_target",
	    "top" : "report"
	};


	//--------------------------------------------------------------------------
	//
	// chart
	//


	// global timeline variables
	var timeline = {},   // The timeline
	data = {},       // Container for the data
	components = [], // All the components of the timeline for redrawing
	bandGap = 25,    // Arbitray gap between to consecutive bands
	bands = {},      // Registry for all the bands in the timeline
	bandY = 0,       // Y-Position of the next band
	bandNum = 0;     // Count of bands for ids

	// Create svg element
	var svg = d3.select(domElement).append("svg")
	.attr("class", "svg")
	.attr("id", "svg")
	.attr("width", outerWidth)
	.attr("height", outerHeight)
	.append("g")
	.attr("transform", "translate(" + margin.left + "," + margin.top +  ")");

	svg.append("clipPath")
	.attr("id", "chart-area")
	.append("rect")
	.attr("width", width)
	.attr("height", height);

	var chart = svg.append("g")
	.attr("class", "chart")
	.attr("clip-path", "url(#chart-area)" );

	var tooltip = d3.select("body")
	.append("div")
	.attr("class", "tooltip")
	.style("visibility", "visible");


	//--------------------------------------------------------------------------
	//
	// data
	//

	timeline.data = function(items) {

	    var today = new Date(),
	    tracks = [],
	    //InstantOffset is How big an instant dot appears on the timeline
	    instantOffset = 10000000;

	    data.items = items;
	    
	    function showItems(n) {
		var count = 0, n = n || 10;
		//console.log("\n");
		items.forEach(function (d) {
		    count++;
		    if (count > n) return;
		    //console.log(toYear(d.start) + " - " + toYear(d.end) + ": " + d.label);
		})
	    }

	    function compareAscending(item1, item2) {
		// Every item must have two fields: 'start' and 'end'.
		var result = item1.start - item2.start;
		// earlier first
		if (result < 0) {
		    return -1;
		}
		if (result > 0) {
		    return 1;
		}
		// longer first
		result = item2.end - item1.end;
		if (result < 0) {
		    return -1;
		}
		if (result > 0) {
		    return 1;
		}
		return 0;
	    }

	    function compareDescending(item1, item2) {
		// Every item must have two fields: 'start' and 'end'.
		var result = item1.start - item2.start;
		// later first
		if (result < 0) {
		    return 1;
		}
		if (result > 0) {
		    return -1;
		}
		// shorter first
		result = item2.end - item1.end;
		if (result < 0) {
		    return 1;
		}
		if (result > 0) {
		    return -1;
		}
		return 0;
	    }

	    function calculateTracks(items, sortOrder, timeOrder) {
		var i, track;

		sortOrder = sortOrder || "descending"; // "ascending", "descending"
		timeOrder = timeOrder || "backward";   // "forward", "backward"

		function sortBackward() {
		    // older items end deeper
		    items.forEach(function (item) {
			for (i = 0, track = 0; i < tracks.length; i++, track++) {
			    if (item.end < tracks[i]) {
				break;
			    }
			}
			item.track = track;
			tracks[track] = item.start;
		    });
		}
		function sortForward() {
		    // younger items end deeper
		    items.forEach(function (item) {
			for (i = 0, track = 0; i < tracks.length; i++, track++) {
			    if (item.start > tracks[i]) {
				break;
			    }
			}
			item.track = track;
			tracks[track] = item.end;
		    });
		}

		if (sortOrder === "ascending")
		    data.items.sort(compareAscending);
		else
		    data.items.sort(compareDescending);

		if (timeOrder === "forward")
		    sortForward();
		else
		    sortBackward();
	    }

	    // Convert yearStrings into dates
	    data.items.forEach(function (item){
		if (item.end == null || item.end == "" || item.end==item.start) {
		    //console.log("1 item.start: " + item.start);
		    //console.log("2 item.end: " + item.end);
		    item.start = parseDate(item.start);
		    item.end = new Date(item.start.getTime() + instantOffset);
		    //console.log("3 item.end: " + item.end);
		    item.instant = true;
		} else {
		    //console.log("4 item.end: " + item.end);
		    item.start = parseDate(item.start);
		    item.end = parseDate(item.end);
		    item.instant = false;
		}
		// The timeline never reaches into the future.
		// This is an arbitrary decision.
		// Comment out, if dates in the future should be allowed.
		if (item.end > today) {
		    item.end = today
		    };
	    });

	    //calculateTracks(data.items);
	    // Show patterns
	    //calculateTracks(data.items, "ascending", "backward");
	    //calculateTracks(data.items, "descending", "forward");
	    // Show real data
	    calculateTracks(data.items, "descending", "backward");
	    //calculateTracks(data.items, "ascending", "forward");
	    data.nTracks = tracks.length;
	    data.minDate = d3.min(data.items, function (d) {
		return d.start;
	    });
	    data.maxDate = d3.max(data.items, function (d) {
		return d.end;
	    });

	    return timeline;
	};

	//----------------------------------------------------------------------
	//
	// band
	//

	timeline.band = function (bandName, sizeFactor) {
	    var band = {};
	    band.id = "band" + bandNum;
	    band.x = 0;
	    band.y = bandY;
	    band.w = width;
	    band.h = height * (sizeFactor || 1);
	    band.trackOffset = 4;
	    // Prevent tracks from getting too high
	    band.trackHeight = Math.min((band.h - band.trackOffset) / data.nTracks, 20);
	    band.itemHeight = band.trackHeight * 0.8,
	    band.parts = [],
	    band.instantWidth = 100; // arbitray value
	    band.xScale = d3.time.scale()
	    .domain([data.minDate, data.maxDate])
	    .range([0, band.w]);

	    band.yScale = function (track) {
		return band.trackOffset + track * band.trackHeight;
	    };

	    band.g = chart.append("g")
	    .attr("id", band.id)
	    .attr("transform", "translate(0," + band.y +  ")");

	    band.g.append("rect")
	    .attr("class", "band")
	    .attr("width", band.w)
	    .attr("height", band.h);

	    // Items
	    var items = band.g.selectAll("g")
	    .data(data.items)
	    .enter().append("svg")
	    .attr("y", function (d) {
		return band.yScale(d.track);
	    })
	    .attr("height", band.itemHeight)
	    .attr("class", function (d) {
		return d.instant ? "part instant" : "part interval";
	    });

	    var intervals = d3.select("#band" + bandNum).selectAll(".interval");
	    intervals.append("rect")
	    .attr("width", "100%")
	    .attr("height", "100%");
	    intervals.append("text")
	    .attr("class", "intervalLabel")
	    .attr("x", 1)
	    .attr("y", 10)
	    .text(function (d) {
		return d.type;
	    });

	    var instants = d3.select("#band" + bandNum).selectAll(".instant");
	    instants.append("circle")
	    .attr("cx", band.itemHeight / 2)
	    .attr("cy", band.itemHeight / 2)
	    .attr("r", 5);
	    instants.append("text")
	    .attr("class", "instantLabel")
	    .attr("x", 15)
	    .attr("y", 10)
	    .text(function (d) {
		return d.type;
	    });
	    /*instants.append("svg:image")
	    .attr("width", 40)
	    .attr("height", 40)
            .attr("x", 15)
            .attr("y", 10)
	    .attr("xlink:href", "./public/icons/report.png");*/



	    band.addActions = function(actions) {
		// actions - array: [[trigger, function], ...]
		actions.forEach(function (action) {
		    items.on(action[0], action[1]);
		})
	    };

	    band.redraw = function () {
		items
		.attr("x", function (d) {
		    return band.xScale(d.start);
		})
		.attr("width", function (d) {
		    return band.xScale(d.end) - band.xScale(d.start);
		});
		band.parts.forEach(function(part) {
		    part.redraw();
		})
	    };

	    bands[bandName] = band;
	    components.push(band);
	    // Adjust values for next band
	    bandY += band.h + bandGap;
	    bandNum += 1;

	    return timeline;
	};

	//----------------------------------------------------------------------
	//
	// labels
	//

	timeline.labels = function (bandName) {

	    var band = bands[bandName],
	    labelWidth = 46,
	    labelHeight = 20,
	    labelTop = band.y + band.h - 10,
	    y = band.y + band.h + 1,
	    yText = 15;

	    var labelDefs = [
	    ["start", "bandMinMaxLabel", 0, 4,
	    function(min, max) {
		return displayDateMinMax(min);
	    },
	    "Start of the selected interval", band.x + 30, labelTop],
	    ["end", "bandMinMaxLabel", band.w - labelWidth, band.w - 4,
	    function(min, max) {
		return displayDateMinMax(max);
	    },
	    "End of the selected interval", band.x + band.w - 152, labelTop]
	    ];

	    var bandLabels = chart.append("g")
	    .attr("id", bandName + "Labels")
	    .attr("transform", "translate(0," + (band.y + band.h + 1) +  ")")
	    .selectAll("#" + bandName + "Labels")
	    .data(labelDefs)
	    .enter().append("g")
	    .on("mouseover", function(d) {
		tooltip.html(d[5])
		.style("top", d[7] + "px")
		.style("left", d[6] + "px")
		.style("visibility", "visible");
	    })
	    .on("mouseout", function(){
		tooltip.style("visibility", "hidden");
	    });

	    bandLabels.append("rect")
	    .attr("class", "bandLabel")
	    .attr("x", function(d) {
		return d[2];
	    })
	    .attr("width", labelWidth)
	    .attr("height", labelHeight)
	    .style("opacity", 1);

	    var labels = bandLabels.append("text")
	    .attr("class", function(d) {
		return d[1];
	    })
	    .attr("id", function(d) {
		return d[0];
	    })
	    .attr("x", function(d) {
		return d[3];
	    })
	    .attr("y", yText)
	    .attr("text-anchor", function(d) {
		return d[0];
	    });

	    labels.redraw = function () {
		var min = band.xScale.domain()[0],
		max = band.xScale.domain()[1];

		labels.text(function (d) {
		    return d[4](min, max);
		})
	    };

	    band.parts.push(labels);
	    components.push(labels);

	    return timeline;
	};

	//----------------------------------------------------------------------
	//
	// tooltips
	//

	timeline.tooltips = function (bandName) {

	    var band = bands[bandName];

	    band.addActions([
		// trigger, function
		["mouseover", showTooltip],
		["mouseout", hideTooltip],
		["contextmenu", showContextTimeline]
		]);

	    function getHtml(element, d) {
		var html;
		if (element.attr("class") == "part interval") {
		    html = getIcon(d) + "<br>" + displayDateLabel(d.start) + " - " + displayDateLabel(d.end);
		} else {
		    html = getIcon(d) + "<br>" + displayDateLabel(d.start);
		}
		return html;
	    }

	    function showTooltip (d) {

		var x = event.pageX < band.x + band.w / 2
		? event.pageX + 10
		: event.pageX - 110,
		y = event.pageY < band.y + band.h / 2
		? event.pageY + 30
		: event.pageY - 30;

		tooltip
		.html(getHtml(d3.select(this), d))
		.style("top", y + "px")
		.style("left", x + "px")
		.style("visibility", "visible");
	    }

	    function hideTooltip () {
		tooltip.style("visibility", "hidden");
	    }
	
	/** Show the context menu for showing the HTML view when right clicking a node
	 * 
	 * @param data The node that was clicked
	 */
	    function showContextTimeline (data) {
		contextNode = data;
		$('#showHtml').removeClass('disabled');

		position = d3.mouse(this);
		offset = $(this).offset();
		scrollTop = 10; 
		showContext(data,(position[0]+offset.left+(10/2))+'px',(position[1]+offset.top-50+scrollTop)+'px');
		
	    }

	    return timeline;
	};

	//----------------------------------------------------------------------
	//
	// xAxis
	//

	timeline.xAxis = function (bandName, orientation) {

	    var band = bands[bandName];

	    var axis = d3.svg.axis()
	    .scale(band.xScale)
	    .orient(orientation || "bottom")
	    .tickSize(6, 0)
	    .tickFormat(function (d) {
		return displayDateTicks(d);
	    });

	    var xAxis = chart.append("g")
	    .attr("class", "axis")
	    .attr("transform", "translate(0," + (band.y + band.h)  + ")");

	    xAxis.redraw = function () {
		xAxis.call(axis);
	    };

	    band.parts.push(xAxis); // for brush.redraw
	    components.push(xAxis); // for timeline.redraw

	    return timeline;
	};

	//----------------------------------------------------------------------
	//
	// brush
	//

	timeline.brush = function (bandName, targetNames) {

	    var band = bands[bandName];

	    var brush = d3.svg.brush()
	    .x(band.xScale.range([0, band.w]))
	    .on("brush", function() {
		var domain = brush.empty()
		? band.xScale.domain()
		: brush.extent();
		targetNames.forEach(function(d) {
		    bands[d].xScale.domain(domain);
		    bands[d].redraw();
		});
	    });

	    var xBrush = band.g.append("svg")
	    .attr("class", "x brush")
	    .call(brush);

	    xBrush.selectAll("rect")
	    .attr("y", 4)
	    .attr("height", band.h - 4);

	    return timeline;
	};

	//----------------------------------------------------------------------
	//
	// redraw
	//

	timeline.redraw = function () {
	    components.forEach(function (component) {
		component.redraw();
	    })
	};

	//--------------------------------------------------------------------------
	//
	// Utility functions
	//

	function parseDate(dateString) {
	    //alert(dateString);
	    var date = new Date(dateString);
	    //alert(date);

	    //var format = d3.time.format("%Y-%m-%dT%H:%M:%S%Z"),
	    //date,
	    //year;
	    
	    //date = format.parse(dateString);
	    //alert(date);
	    if (date !== null) 
	    {
		return date;
	    }
	    
	}
	//not used except in console
	function toYear(date, bcString) {
	    return date.toLocaleDateString();
	}
    
	function displayDateLabel(date) {
	    return date.toLocaleString();
	}
    
	function displayDateTicks(date) {
	    var month = date.getMonth();
	    var day = date.getDate();
	    var year = date.getFullYear();
	    
	    return month + "/" + day + "/" + year;
	}
    
	function displayDateMinMax(date) {
	    var month = date.getMonth();
	    var day = date.getDate();
	    var year = date.getFullYear();
	    
	    return month + "/" + day + "/" + year;
	}
    
	function getIcon(d) {
	    if(d.type)
	    {
		var imgStr = '';
		/*if(typeIconMap[d.type])
		{
		    imgStr += '<img src="./public/xslt/images/'+typeIconMap[d.type]+'.svg">';
		}*/
		imgStr += "<br>ID: " +d.label;
	    }
	    return imgStr;
	}
    
    

	return timeline;
    }

};