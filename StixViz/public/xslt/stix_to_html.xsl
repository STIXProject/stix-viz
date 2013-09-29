<?xml version="1.0" encoding="UTF-8"?>
<!--
  Copyright (c) 2013 – The MITRE Corporation
  All rights reserved. See LICENSE.txt for complete terms.
 -->
<!--
STIX XML to HTML transform v1.0
Compatible with CybOX v2.0

This is an xslt to transform a STIX 2.0 document into html for easy viewing.  
CybOX observables, Indicators & TTPs are supported and turned into collapsible 
HTML elements.  Details about structure's contents are displayed in a
format representing the nested nature of the original document.

Objects which are referred to by reference can be expanded within the context
of the parent object, unless the reference points to an external document

This is a work in progress.  Feedback is most welcome!

requirements:
 - XSLT 2.0 engine (this has been tested with Saxon 9.5)
 - a STIX 2.0 input xml document
 
Created 2013
mcoarr@mitre.org
mdunn@mitre.org
  
-->

<xsl:stylesheet 
    version="2.0"
    xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:fn="http://www.w3.org/2005/xpath-functions"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"

    xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:TTP="http://stix.mitre.org/TTP-1"
    xmlns:COA="http://stix.mitre.org/CourseOfAction-1"
    xmlns:capec="http://stix.mitre.org/extensions/AP#CAPEC2.5-1"
    xmlns:marking="http://data-marking.mitre.org/Marking-1"
    xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1"
    xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
    xmlns:stixCommon='http://stix.mitre.org/common-1'
    
    xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
    exclude-result-prefixes="cybox xsi fn EmailMessageObj">
    
<xsl:output method="html" omit-xml-declaration="yes" indent="yes" media-type="text/html" version="4.0" />
  <xsl:include href="stix_common.xsl"/>
  <xsl:include href="normalize.xsl"/>
  
  <!-- <xsl:include href="cybox_common.xsl"/> -->
  <xsl:key name="observableID" match="cybox:Observable" use="@id"/>
    
    <!--
      This is the main template that sets up the html page that sets up the
      html structure, includes the base css and javascript, and adds the
      content for the metadata summary table up top and the heading and
      surrounding content for the Observables table.
    --> 
    <xsl:template match="/">
        <!--
          Perform the normalization to create "normalized" and "reference".
          "reference" is a sequence with all elements from the source document
          that have @id attributes.
          
          "normalized" has a cleaned up view of the root of the source document
          down to the first elements with @id attributes, which will be renamed
          to @idref.
          
          These two variables will become the main inputs to the primary transform.
        -->
        <xsl:variable name="normalized">
          <xsl:apply-templates select="/stix:STIX_Package/*" mode="createNormalized" />
        </xsl:variable>
        <xsl:variable name="reference">
          <xsl:apply-templates select="/stix:STIX_Package//*[@id or @phase_id[../../self::stixCommon:Kill_Chain]]" mode="createReference">
            <xsl:with-param name="isTopLevel" select="fn:true()" />
          </xsl:apply-templates>
        </xsl:variable>
      
            <html>
              <head>
                <title>STIX Output</title>
                <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
                 
                <!-- read in the main css -->
                <style type="text/css">
                    <xsl:value-of select="unparsed-text('common.css')" />
                </style>

                 <!-- this is a javascript shim to support the javascript
                   "classList" property in dom elements objects for IE.
                   
                   source: http://purl.eligrey.com/github/classList.js
                 -->
                 <script type="text/javascript">
                   <![CDATA[
                  /*! @source http://purl.eligrey.com/github/classList.js/blob/master/classList.js*/
                  if(typeof document!=="undefined"&&!("classList" in document.createElement("a"))){(function(j){if(!("HTMLElement" in j)&&!("Element" in j)){return}var a="classList",f="prototype",m=(j.HTMLElement||j.Element)[f],b=Object,k=String[f].trim||function(){return this.replace(/^\s+|\s+$/g,"")},c=Array[f].indexOf||function(q){var p=0,o=this.length;for(;p<o;p++){if(p in this&&this[p]===q){return p}}return -1},n=function(o,p){this.name=o;this.code=DOMException[o];this.message=p},g=function(p,o){if(o===""){throw new n("SYNTAX_ERR","An invalid or illegal string was specified")}if(/\s/.test(o)){throw new n("INVALID_CHARACTER_ERR","String contains an invalid character")}return c.call(p,o)},d=function(s){var r=k.call(s.className),q=r?r.split(/\s+/):[],p=0,o=q.length;for(;p<o;p++){this.push(q[p])}this._updateClassName=function(){s.className=this.toString()}},e=d[f]=[],i=function(){return new d(this)};n[f]=Error[f];e.item=function(o){return this[o]||null};e.contains=function(o){o+="";return g(this,o)!==-1};e.add=function(){var s=arguments,r=0,p=s.length,q,o=false;do{q=s[r]+"";if(g(this,q)===-1){this.push(q);o=true}}while(++r<p);if(o){this._updateClassName()}};e.remove=function(){var t=arguments,s=0,p=t.length,r,o=false;do{r=t[s]+"";var q=g(this,r);if(q!==-1){this.splice(q,1);o=true}}while(++s<p);if(o){this._updateClassName()}};e.toggle=function(p,q){p+="";var o=this.contains(p),r=o?q!==true&&"remove":q!==false&&"add";if(r){this[r](p)}return !o};e.toString=function(){return this.join(" ")};if(b.defineProperty){var l={get:i,enumerable:true,configurable:true};try{b.defineProperty(m,a,l)}catch(h){if(h.number===-2146823252){l.enumerable=false;b.defineProperty(m,a,l)}}}else{if(b[f].__defineGetter__){m.__defineGetter__(a,i)}}}(self))};
                  ]]>
                 </script>
                 
                <!-- read in the main javascript -->
                <script type="text/javascript">
                  <xsl:value-of select="unparsed-text('common.js')" />
                </script>
              </head>
              <body onload="runtimeCopyObjects();">
                    <div id="wrapper">
                        <div id="header"> 
                            <h1>STIX Output</h1>
                          
                            <!-- print out the stix metadata table -->
                            <table class="stixMetadata hor-minimalist-a" width="100%">
                                <thead>
                                    <tr>
                                        <th scope="col">STIX Version</th>
                                        <th scope="col">Filename</th>
                                        <th scope="col">Generation Date</th>
                                    </tr>
                                </thead>
                                <tr>
                                    <td><xsl:value-of select="//stix:STIX_Package/@version"/></td>
                                    <td><xsl:value-of select="tokenize(document-uri(.), '/')[last()]"/></td>
                                    <td><xsl:value-of select="current-dateTime()"/></td>
                                </tr>   
                            </table>
                        </div>
                        <h2><a name="analysis">STIX Header</a></h2>
                          <xsl:call-template name="processHeader"/>
                      
                        <!--
                          IMPORTANT
                          
                          Transform and print out the "reference" objects
                          
                          these objects will be used any time the user clicks
                          on expandable content that uses ids and idrefs.
                          
                          When the user expands content, the appropriate nodes
                          from here will be cloned and copied into the document
                        -->
                          
                        <xsl:call-template name="printReference">
                          <xsl:with-param name="reference" select="$reference" />
                          <xsl:with-param name="normalized" select="$normalized" />
                        </xsl:call-template>
                      
                        <!--
                          MAIN TOP LEVEL CATEGORY TABLES
                        -->
                      
                        <xsl:if test="$normalized/stix:Observables/*"> 
                          <h2><a name="analysis">Observables</a></h2>
                          <xsl:call-template name="processTopLevelCategory">
                              <xsl:with-param name="reference" select="$reference" />
                              <xsl:with-param name="normalized" select="$normalized" />
                              <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Observables" />
                          </xsl:call-template>
                        </xsl:if>
                      
                        <xsl:if test="$normalized/stix:Indicators/*">
                          <h2><a name="analysis">Indicators</a></h2>
                          <!-- <xsl:call-template name="processIndicators"/> -->
                          <xsl:call-template name="processTopLevelCategory">
                            <xsl:with-param name="reference" select="$reference" />
                            <xsl:with-param name="normalized" select="$normalized" />
                            <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Indicators" />
                          </xsl:call-template>
                        </xsl:if>
                      
                      <xsl:if test="$normalized/stix:TTPs/*">
                          <h2><a name="analysis">TTPs</a></h2>
                          <xsl:call-template name="processTopLevelCategory">
                            <xsl:with-param name="reference" select="$reference" />
                            <xsl:with-param name="normalized" select="$normalized" />
                            <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:TTPs" />
                            <xsl:with-param name="headingLabels" select="('ID', 'Title')" />
                          </xsl:call-template>
                        </xsl:if>
                      
                      <xsl:if test="$normalized/stix:Exploit_Targets/*">  
                        <h2><a name="analysis">Exploit Targets</a></h2>
                          <xsl:call-template name="processTopLevelCategory">
                            <xsl:with-param name="reference" select="$reference" />
                            <xsl:with-param name="normalized" select="$normalized" />
                            <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Exploit_Targets" />
                          </xsl:call-template>
                        </xsl:if>
                      
                      <xsl:if test="$normalized/stix:Incidents/*">
                        <h2><a name="analysis">Incidents</a></h2>
                        <xsl:call-template name="processTopLevelCategory">
                          <xsl:with-param name="reference" select="$reference" />
                          <xsl:with-param name="normalized" select="$normalized" />
                          <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Incidents" />
                        </xsl:call-template>
                        </xsl:if>
                      
                      <xsl:if test="$normalized/stix:Courses_Of_Action/*">
                        <h2><a name="analysis">Courses of Action</a></h2>
                        <xsl:call-template name="processTopLevelCategory">
                          <xsl:with-param name="reference" select="$reference" />
                          <xsl:with-param name="normalized" select="$normalized" />
                          <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Courses_Of_Action" />
                        </xsl:call-template>
                        </xsl:if>
                      
                      <xsl:if test="$normalized/stix:Campaigns/*">
                        <h2><a name="analysis">Campaigns</a></h2>
                        <xsl:call-template name="processTopLevelCategory">
                          <xsl:with-param name="reference" select="$reference" />
                          <xsl:with-param name="normalized" select="$normalized" />
                          <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Campaigns" />
                        </xsl:call-template>
                        </xsl:if>
                      
                      <xsl:if test="$normalized/stix:Threat_Actors/*">
                        <h2><a name="analysis">Threat Actors</a></h2>
                         <xsl:call-template name="processTopLevelCategory">
                           <xsl:with-param name="reference" select="$reference" />
                           <xsl:with-param name="normalized" select="$normalized" />
                           <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Threat_Actors" />
                         </xsl:call-template>
                        </xsl:if>
                   </div>
                </body>
            </html>
    </xsl:template>
  
  <!--
    This template prints out the "reference" variable that comes of the the
    "normalization" transform.
    
    The contents are transformed into html and printed out as html elements
    with corresponding ids.
    
    This is contained in a div with class .reference which will be hidden.
    Its contents are never directly visible to the user.
    
    The following templates with mode "printReference" are used in transforming
    and building this content.
  -->
  <xsl:template name="printReference">
    <xsl:param name="reference" select="()" />
    <xsl:param name="normalized" select="()" />
    
    <div class="reference">
      <xsl:apply-templates select="$reference" mode="printReference" />
    </div>
  </xsl:template>
  
  <!--
    For printing reference objects, default to not printing anything.
    Another template must apply if an element or attribute should be printed
    out.
  -->
  <xsl:template match="node()" mode="printReference" />
  
  <!--
    Opt in the following nodes to being printed in reference list:
     - Observable
     - Indicator
     - TTP
     - Kill Chain
     - Campaign
     - Incident
     - Thread Actor
     - Exploit Target
  -->
  <xsl:template match="cybox:Observable|indicator:Observable|stix:Indicator|stix:TTP|stixCommon:Kill_Chain|stixCommon:Kill_Chain_Phase|stix:Campaign|stix:Incident|stix:Threat_Actor|stixCommon:Exploit_Target" mode="printReference">
    <xsl:param name="reference" select="()" />
    <xsl:param name="normalized" select="()" />

    <xsl:call-template name="printGenericItemForReferenceList">
      <xsl:with-param name="reference" select="$reference" />
      <xsl:with-param name="normalized" select="$normalized" />
    </xsl:call-template>
  </xsl:template>

  <!--
    Opt in the following nodes to being printed in reference list:
     - Object
     - Related Object
     - Kill Chain
     - Course Of Action
  -->
  <xsl:template match="cybox:Object|cybox:Related_Object|stixCommon:Kill_Chain|stixCommon:Course_Of_Action|stix:Course_Of_Action" mode="printReference">
    <xsl:param name="reference" select="()" />
    <xsl:param name="normalized" select="()" />
    
    <xsl:call-template name="printObjectForReferenceList">
      <xsl:with-param name="reference" select="$reference" />
      <xsl:with-param name="normalized" select="$normalized" />
    </xsl:call-template>
  </xsl:template>
  
  <!--
      draw the main table on the page that represents the list of Observables.
      these are the elements that are directly below the root element of the page.
      
      each item will generate two rows in the table.  the first one is the
      heading that's always visible and is clickable to expand/collapse the
      second row.
      
      this template will be used to print the table for all top level content
      (observables, indicators, TTPs, etc).
    -->
  <xsl:template name="processTopLevelCategory">
    <xsl:param name="reference" select="()" />
    <xsl:param name="normalized" select="()" />
    <xsl:param name="categoryGroupingElement" select="()" />
    <xsl:param name="headingLabels" select="('ID', 'Type')" />
    
    <div class="topLevelCategoryTable">
      <table class="grid tablesorter" cellspacing="0">
        <colgroup>
          <col width="70%"/>
          <col width="30%"/>
        </colgroup>
        <thead>
          <tr>
            <xsl:for-each select="$headingLabels">
              <th class="header">
                <xsl:value-of select="." />
              </th>
            </xsl:for-each>
          </tr>
        </thead>
        <tbody>
          <xsl:for-each select="$categoryGroupingElement/*[@idref]">
            <!-- <xsl:sort select="cybox:Observable_Composition" order="descending"/> -->
            <xsl:variable name="evenOrOdd" select="if(position() mod 2 = 0) then 'even' else 'odd'" />
            <xsl:call-template name="printGenericItemForTopLevelCategoryTable">
              <xsl:with-param name="reference" select="$reference" />
              <xsl:with-param name="normalized" select="$normalized" />
              <xsl:with-param name="evenOrOdd" select="$evenOrOdd"/>
            </xsl:call-template>
          </xsl:for-each>
          
          <xsl:for-each select="$categoryGroupingElement/stix:Kill_Chains">
            <thead><tr><th colspan="2">Kill Chains</th></tr></thead>
            <xsl:for-each select="./stixCommon:Kill_Chain">
                <!-- <tr><td colspan="2">kill chain <xsl:value-of select="fn:data(./@idref)"/></td></tr> -->
              
              <xsl:variable name="evenOrOdd" select="if(position() mod 2 = 0) then 'even' else 'odd'" />
              <xsl:call-template name="printGenericItemForTopLevelCategoryTable">
                <xsl:with-param name="reference" select="$reference" />
                <xsl:with-param name="normalized" select="$normalized" />
                <xsl:with-param name="evenOrOdd" select="$evenOrOdd"/>
              </xsl:call-template>
              
            </xsl:for-each>
          </xsl:for-each>
        </tbody>
      </table>    
    </div>
  </xsl:template>
  
  <!--
    Print one of the "items" (Obserbale, Indicator, TTP, etc) for the "reference" list.
    
    This will always have the immediate contents of the "item".
    
    [This is related to printGenericItemForTopLevelCategoryTable, which prints
    the generic items for the top level tables.  It should be noted that that
    template never prints contents, as they will be looked up by id from the
    reference list, as printed by this template.]
  -->
  <xsl:template name="printGenericItemForReferenceList">
    <xsl:param name="reference" select="()" />
    <xsl:param name="normalized" select="()" />
    
    <xsl:variable name="originalItem" select="." />
    <xsl:variable name="originalItemId" as="xs:string?" select="fn:data($originalItem/@id)" />
    <xsl:variable name="originalItemIdref" as="xs:string?" select="fn:data($originalItem/@idref)" />
    <!--
    <xsl:message>
      original item id: <xsl:value-of select="$originalItemId"/>; original item idref: <xsl:value-of select="$originalItemIdref"/>; 
    </xsl:message>
    -->
    <xsl:variable name="actualItem"  as="element()?" select="if ($originalItemId) then ($originalItem) else ($reference/*[@id = $originalItemIdref])" />
    
    <xsl:variable name="expandedContentId" select="generate-id(.)"/>
    
    <xsl:variable name="id" select="fn:data($actualItem/@id)" />
    
    <xsl:choose>
      <xsl:when test="fn:empty($actualItem)">
        <div id="{fn:data($actualItem/@id)}" class="nonExpandable">
          <div class="externalReference objectReference">
            <xsl:value-of select="$actualItem/@id"/>
            [EXTERNAL]
            <!--
            <xsl:call-template name="itemHeadingOnly">
              <xsl:with-param name="reference" select="$reference" />
              <xsl:with-param name="normalized" select="$normalized" />
            </xsl:call-template>
            -->
            
          </div>
        </div>
          
      </xsl:when>
      <xsl:otherwise>
        <div id="{fn:data($actualItem/@id)}" class="expandableContainer expandableSeparate collapsed">
          <!-- <div class="expandableToggle objectReference" onclick="toggle(this.parentNode)"> -->
          <div class="expandableToggle objectReference">
            <xsl:attribute name="onclick">embedObject(this.parentElement, '<xsl:value-of select="$id"/>','<xsl:value-of select="$expandedContentId"/>');</xsl:attribute>
            <xsl:value-of select="$actualItem/@id"/>
            <xsl:call-template name="itemHeadingOnly">
              <xsl:with-param name="reference" select="$reference" />
              <xsl:with-param name="normalized" select="$normalized" />
            </xsl:call-template>
            
          </div>
          
          <div id="{$expandedContentId}" class="expandableContents">
            <xsl:choose>
              <xsl:when test="self::cybox:Observable|self::indicator:Observable">
                <xsl:call-template name="processObservableContents" />
              </xsl:when>
              <xsl:when test="self::stix:Indicator">
                <xsl:call-template name="processIndicatorContents" />
              </xsl:when>
              <xsl:when test="self::stix:TTP">
                <xsl:call-template name="processTTPContents" />
              </xsl:when>
              <xsl:when test="self::stixCommon:Kill_Chain_Phase">
                <xsl:apply-templates select="." />
              </xsl:when>
              <xsl:when test="self::stix:Campaign">
                <xsl:call-template name="processCampaignContents" />
              </xsl:when>
              <xsl:when test="self::stix:Incident">
                <xsl:call-template name="processIncidentContents" />
              </xsl:when>
              <xsl:when test="self::stix:Threat_Actor">
                <xsl:call-template name="processThreatActorContents" />
              </xsl:when>
              <xsl:when test="self::stixCommon:Exploit_Target">
                <xsl:call-template name="processExploitTargetContents" />
              </xsl:when>
            </xsl:choose>
          </div>
        </div>
      </xsl:otherwise>
    </xsl:choose>
    
  </xsl:template>
  
  
</xsl:stylesheet>
