/*
 * Copyright (c) 2013 – The MITRE Corporation
 * All rights reserved. See LICENSE.txt for complete terms.
 * 
 * Copied from stix_to_html package v1.0beta2 
 * 
 */

//Collapse functionality
function toggleDiv(divid, spanID)
{
  if(document.getElementById(divid).style.display == 'none')
  {
    document.getElementById(divid).style.display = 'block';
    if(spanID)
    {
      document.getElementById(spanID).innerText = "-";
    }
  } // end of if-then
  else
  {
    document.getElementById(divid).style.display = 'none';
    if(spanID)
    {
      document.getElementById(spanID).innerText = "+";
    }
  } // end of else
} // end of function toggleDiv()


<!-- toggle top-level Observables -->
function toggleDiv(divid, spanID) {
    if (document.getElementById(divid).style.display == 'none') {
        document.getElementById(divid).style.display = 'block';
        if (spanID) {
            document.getElementById(spanID).innerText = "-";
        }
    }
    else {
        document.getElementById(divid).style.display = 'none';
        if (spanID) {
            document.getElementById(spanID).innerText = "+";
        }
    }
}


<!-- onload, make a clean copy of all top level Observables for compositions before they are manipulated at runtime -->
function embedCompositions() {
    var divCompBaseList = getElementsByClass('baseobserv');
    var divCompCopyList = getElementsByClass('copyobserv');
    
    for (i = 0; i < divCompCopyList.length; i++) {
        for (j = 0; j < divCompBaseList.length; j++) {
            if (divCompCopyList[i].id == 'copy-' + divCompBaseList[j].id) {
                divCompCopyList[i].innerHTML = divCompBaseList[j].innerHTML;
            }
        }
    }
    
    return false;
}

<!-- copy object from clean src copy to dst destination and then toggle visibility -->
function embedObject(container, targetId, expandedContentContainerId) {

    //var copy = pristineCopies[targetId].cloneNode(true);
    var template = document.querySelector(".reference #" + targetId.replace(":", "\\:"));
    
    if (template == null)
    {
      console.log("tried to expand id that didn't exist in reference list: " + targetId);
      return;
    }
    //var copy = template.cloneNode(true);
    
    var target = container.querySelector("#" + expandedContentContainerId.replace(":", "\\:"));
    
    while(target.lastChild)
    {
      target.removeChild(target.lastChild);
    }
    
    var childrenToBeCopied = template.querySelectorAll(".expandableContents > *");
    for (var i = 0; i < childrenToBeCopied.length; i++)
    {
      var current = childrenToBeCopied.item(i);
      var currentCopy = current.cloneNode(true);
      target.appendChild(currentCopy);
    }
    
    //target.appendChild(copy);
    
    /*
    <!-- deep copy the source div's html into the destination div --> 
    <!-- (typically a RelatedObjects's content expanded into a parent Object's RO container) -->
    var objDiv = document.getElementById(src).cloneNode(true);
    
    for (i = 0; i < container.children.length; i++) {
        if ((typeof (container.children[i].id) != "undefined") && (container.children[i].id == dst)) {
            container.children[i].innerHTML = objDiv.innerHTML;
        }
    }
    */
    
    <!-- finally, toggle the visibility state of the div  -->
    toggle(container);
    
    return false;
}

var pristineCopies = {};
<!-- onload, make a clean copy of all id'd objects/actions for runtime copying -->
function runtimeCopyObjects() {
    var referenceItems = document.querySelector(".reference > *");
    
    for (i = 0; i < referenceItems.length; i++) {
      var current = referenceItems[i];
      var id = current.id;
      pristineCopies[id] = current;
    }
    
    /*
    for (i = 0; i < divSrcList.length; i++) {
        divDeepCopy = divSrcList[i].cloneNode(true);
        
        <!-- remove heading from copied content since expandable reference will contain header info -->
        for (j = 0; j < divDeepCopy.children.length; j++) {
            if ((typeof (divDeepCopy.children[j].className) != "undefined") && (divDeepCopy.children[j].className.indexOf("heading") > -1)) {
                divDeepCopy.removeChild(divDeepCopy.children[j]);
                break;
            }
        }
        
        for (k = 0; k < divDstList.length; k++) {
            if ('copy-' + divDeepCopy.id == divDstList[k].id)
                divDstList[k].innerHTML = divDeepCopy.innerHTML;
        }
    }
    */
    
    return false;
}

<!-- identify all elements in the document which have the parameterized class applied -->
function getElementsByClass(inClass) {
    var children = document.body.getElementsByTagName('*');
    var elements = [],
        child;
    for (var i = 0, length = children.length; i < length; i++) {
        child = children[i];
        if ((typeof (child.className) != "undefined") && (child.className.indexOf(inClass) > -1)) {
            elements.push(child);
        }
    }
    return elements;
}

<!-- toggle visibility of a container element -->
function toggle(containerElement) {
  // now using a shim to support classList in IE8/9
  containerElement.classList.toggle("collapsed");
  containerElement.classList.toggle("expanded");
}

function nsResolver(prefix) {
  var ns = {
    'xhtml' : 'http://www.w3.org/1999/xhtml',
    'mathml': 'http://www.w3.org/1998/Math/MathML'
  };
  return ns[prefix] || null;
}

function expandAll(current)
{
  console.log("expanding all..");
  var topCategoryExpandables = current.querySelectorAll("table.topLevelCategory > tbody.expandableContainer.expandableSeparate");
  
  for (var i=0; i < topCategoryExpandables.length; i++)
  {
    var currentExpandable = topCategoryExpandables.item(i);
    var currentToggle = currentExpandable.querySelector("tr > td > .expandableToggle");
    
    // document.evaluate("ancestor::*", $p, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null)
    
    // check if this item id has already been expanded
    var currentId = currentExpandable.getAttribute("data-stix-content-id");
    var ancestorList = document.evaluate("ancestor::*[@data-stix-content-id = '" + currentId + "']", currentExpandable, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null);
    if (ancestorList.snapshotLength == 0)
    {
      // if not previously expanded (that is previously in it's ancestors in the html dom)
      currentToggle.onclick();
      
    expandNestedExpandables(currentExpandable);      
    }
    
    
  }
  console.log("done expanding.");
}

function expandTopLevelCategoryTable()
{
  
}

function expandNestedExpandables(contextExpandable)
{
  // document.evaluate("ancestor::*", $p, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null)
  
  //   //div[contains(concat(' ', @class, ' '), ' Test ')]
  
  var expandableDescendentsSeparate = contextExpandable.querySelectorAll(".expandableContainer.expandableSeparate");
  for (var i=0; i < expandableDescendentsSeparate.length; i++)
  {
    var currentExpandable = expandableDescendentsSeparate.item(i);
    var currentToggle = currentExpandable.querySelector(".expandableToggle");

    // check if this item id has already been expanded
    var currentId = currentExpandable.getAttribute("data-stix-content-id");
    var ancestorList = document.evaluate("ancestor::*[@data-stix-content-id = '" + currentId + "']", currentExpandable, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null);
    if (ancestorList.snapshotLength == 0)
    {
      // if not previously expanded (that is previously in it's ancestors in the html dom)
      currentToggle.onclick();
      expandNestedExpandables(currentExpandable);      
    }
      
  }
  
  var expandableDescendentsSame = contextExpandable.querySelector(".expandableContainer.expandableSame");
}

function replaceHtmlContainers()
{
  var allTargets = document.querySelectorAll(".htmlContainer");
  for (var i = 0; i < allTargets.length; i++)
  {
    var target = allTargets[i];
    var rawHtml = target.getAttribute("data-stix-content");
    
    var htmlElement = document.createElement("html");
    htmlElement.innerHTML = rawHtml;
    
    var body = htmlElement.querySelector("body");
    var bodyChildren = body.childNodes;
    //for (var j = 0; j < bodyChildren.length; j++)
    while (bodyChildren.length > 0)
    {
      var currentBodyChild = bodyChildren[0];
      if (currentBodyChild.nodeType == Node.ELEMENT_NODE || currentBodyChild.nodeType == Node.TEXT_NODE)
      {
        target.appendChild(currentBodyChild);
      }

    }
    //target.appendChild();

  }
}


function initialize()
{
  console.log("beginning initialization...");
  wgxpath.install();
  replaceHtmlContainers();
  console.log("done initialization.");

}