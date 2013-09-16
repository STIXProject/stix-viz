// Collapse functionality
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


//<!-- toggle top-level Observables -->
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


//<!-- onload, make a clean copy of all top level Observables for compositions before they are manipulated at runtime -->
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

//<!-- copy object from clean src copy to dst destination and then toggle visibility -->
function embedObject(container, targetId, expandedContentContainerId) {

    //var copy = pristineCopies[targetId].cloneNode(true);
    var template = document.querySelector(".reference #" + targetId.replace(":", "\\:"));
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
    
//    <!-- finally, toggle the visibility state of the div  -->
    toggle(container);
    
    return false;
}

var pristineCopies = {};
//<!-- onload, make a clean copy of all id'd objects/actions for runtime copying -->
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

//<!-- identify all elements in the document which have the parameterized class applied -->
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

//<!-- toggle visibility of a container element -->
function toggle(containerElement) {
  // now using a shim to support classList in IE8/9
  containerElement.classList.toggle("collapsed");
  containerElement.classList.toggle("expanded");
}