<?xml version="1.0" encoding="UTF-8"?>
<!--
  Copyright (c) 2013 – The MITRE Corporation
  All rights reserved. See LICENSE.txt for complete terms.
 -->
<!--
CybOX XML to HTML transform v2.0
Compatible with CybOX v2.0

This is an xslt to transform a cybox 2.0 document of observables into html for
easy viewing.  The series of observables are turned into collapsible elements
on the screen.  Details about each observable's contents are displayed in a
format representing the nested structure of the original document.

Below the main observable, Object, Event, and Observable_Composition are
displayed.  For composite observables, the nested structure of the composition
and the logical relationships is displayed via nested tables with operators
("and" and "or) on the left and then a series of component expressions on rows
on the right.

Objects which are referred to by reference can be expanded within the context
of the parent object, unless the reference points to an external document

This is a work in progress.  Feedback is most welcome!

requirements:
 - XSLT 2.0 engine (this has been tested with Saxon 9.5)
 - a CybOX 2.0 input xml document

Updated 2013
mcoarr@mitre.org & mdunn@mitre.org

Updated 9/11/2012
ikirillov@mitre.org
  
-->
<xsl:stylesheet 
    version="2.0"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:Common="http://cybox.mitre.org/common-2"
    xmlns:stixCommon="http://stix.mitre.org/common-1"
    
    xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:incident="http://stix.mitre.org/Incident-1"
    
    xmlns:coa="http://stix.mitre.org/CourseOfAction-1"
    
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:fn="http://www.w3.org/2005/xpath-functions"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    
    xmlns:ttp='http://stix.mitre.org/TTP-1'
    xmlns:ta="http://stix.mitre.org/ThreatActor-1"
    xmlns:et="http://stix.mitre.org/ExploitTarget-1"
    xmlns:stix='http://stix.mitre.org/stix-1'
    
    xmlns:AddressObject='http://cybox.mitre.org/objects#AddressObject-2'
    xmlns:URIObject='http://cybox.mitre.org/objects#URIObject-2'
    xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
    exclude-result-prefixes="cybox Common xsi fn EmailMessageObj AddressObject URIObject coa ttp ta et">


    <xsl:output method="html" omit-xml-declaration="yes" indent="yes" media-type="text/html" version="4.0" />
  

    <!--
      Shared function to convert CamelCaseText to standard word formatting.
    -->
    <xsl:function name="cybox:camelCase" as="xs:string" >
        <xsl:param name="arg" as="xs:string?"/> 
        
        <xsl:choose>
            <xsl:when test="matches($arg, '^\p{Ll}+$')">
                <xsl:sequence select="concat(substring($arg,1,1),replace(substring($arg,2),'(\p{Lu})',concat(' ', '$1')))" />    
            </xsl:when>
            <xsl:otherwise>
                <xsl:sequence select="$arg" />
            </xsl:otherwise>
        </xsl:choose>
    </xsl:function>

    <!--
      Shared function that is used to calculate what type or title to show in
      the top level category table, depending on the type of the generic
      "item" element.
    -->
    <xsl:template name="calculateColumn1Content">
        <xsl:param name="reference" select="()" />
        <xsl:param name="actualItem" select="()" />
        
        <xsl:choose>
            <xsl:when test="$actualItem/cybox:Observable_Composition">
                Composition
            </xsl:when>
            <xsl:when test="$actualItem/cybox:Event">
                Event
            </xsl:when>
            <xsl:when test="$actualItem/cybox:Object">
                <xsl:variable name="objectItem" select="$reference/*[@id = fn:data($actualItem/cybox:Object/@idref)]" />
               
                <xsl:choose>
                    <xsl:when test="$objectItem/cybox:Properties/@xsi:type" xml:space="preserve">
                        <xsl:value-of select="cybox:camelCase(fn:substring-before(fn:local-name-from-QName(fn:resolve-QName($objectItem/cybox:Properties/@xsi:type, $objectItem)),'ObjectType'))" />
                    </xsl:when>
                    <xsl:when test="$objectItem/cybox:Properties/@xsi:type and not($objectItem/cybox:Properties/@xsi:type)">
                        Object (no properties set)
                    </xsl:when>
                    <xsl:otherwise>
                        [Object, no ID]
                    </xsl:otherwise>
                </xsl:choose>
               
            </xsl:when>
            
            <!-- stix -->
            <xsl:when test="$actualItem[contains(@xsi:type,'IndicatorType')]"  xml:space="preserve">
                <xsl:variable name="output" select="if ($actualItem/indicator:Title) then $actualItem/indicator:Title/text() else ('[Indicator, no Title]')" />
                <xsl:value-of select="$output" />
            </xsl:when>
            <xsl:when test="$actualItem[contains(@xsi:type,'ThreatActorType')]"  xml:space="preserve">
                <xsl:variable name="output" select="if ($actualItem/indicator:Title) then $actualItem/indicator:Title/text() else ('[ThreatActor, no Title]')" />
                <xsl:value-of select="$output" />
            </xsl:when>
            <xsl:when test="$actualItem[contains(@xsi:type,'TTPType')]"  xml:space="preserve">
                <xsl:variable name="output" select="if ($actualItem/ttp:Title) then $actualItem/ttp:Title/text() else ('[TTP, no Title]')" />
                <xsl:value-of select="$output" />
            </xsl:when>
            <xsl:when test="$actualItem[contains(@xsi:type,'COAType')]"  xml:space="preserve">
                <xsl:variable name="output" select="if ($actualItem/coa:Type) then $actualItem/coa:Type/text() else ('[TTP, no Type]')" />
                <xsl:value-of select="$output" />
            </xsl:when>
            <xsl:when test="$actualItem[contains(@xsi:type,'IncidentType')]"  xml:space="preserve">
                <xsl:variable name="output" select="if ($actualItem/coa:Type) then $actualItem/coa:Type/text() else ('[Incident, no Type]')" />
                <xsl:value-of select="$output" />
            </xsl:when>
            <!-- /stix -->
            <xsl:otherwise>
                Other
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    

    <!--
      Shared function that is used to calculate what type or title to show in
      the top level category table, depending on the type of the generic
      "item" element.
    -->
    <xsl:template name="calculateColumn2Content">
        <xsl:param name="reference" select="()" />
        <xsl:param name="actualItem" select="()" />
        
        <xsl:choose>
            <!-- stix -->
            <xsl:when test="$actualItem[contains(@xsi:type,'IndicatorType')]/indicator:Composite_Indicator_Expression">
                <td>
                    [Composition]
                </td>
            </xsl:when>
            <xsl:when test="$actualItem[contains(@xsi:type,'IndicatorType')]/indicator:Observable">
                <td>
                    <xsl:variable name="observableItem" select="$reference/*[@id = fn:data($actualItem/indicator:Observable/@idref)]" />
                    <xsl:variable name="output" select="if ($observableItem/cybox:Title) then $observableItem/cybox:Title/text()  else ('[Observable, no Title]')" />
                    <xsl:value-of select="$output" />
                </td>
            </xsl:when>
            <!-- /stix -->
            <xsl:otherwise>
                <td colspan="2">
                    <xsl:value-of select="./@idref"/>
                </td>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <!--
      Shared function that is used to calculate what type or title to show in
      the top level category table, depending on the type of the generic
      "item" element.
    -->
    <xsl:template name="calculateColumn3Content">
        <xsl:param name="reference" select="()" />
        <xsl:param name="actualItem" select="()" />
        
        <xsl:variable name="currentItem" select="." />
        <xsl:variable name="actualItem2" select="$reference/*[@id = fn:data($currentItem/@idref)]" />
        
        <xsl:choose>
            <!-- stix -->
            <xsl:when test="$actualItem2[contains(@xsi:type,'IndicatorType')]">
                <td>
                    <xsl:value-of select="$actualItem2/indicator:Type/text()" />
                </td>
            </xsl:when>
            <!-- /stix -->
            <xsl:otherwise>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    

    <!--
      print one of the "items" (Obserbale, Indicator, TTP, etc) for the top
      level category table.
      
      the same javascript and css logic for expand and collapse that is used
      for nested indicators and observables is now also used here in the top
      level category tables.
    -->
    <xsl:template name="printGenericItemForTopLevelCategoryTable">
        <xsl:param name="reference" select="()" />
        <xsl:param name="normalized" select="()" />
        <xsl:param name="colCount" select="2" />

        <xsl:variable name="originalItem" select="." />
        <!--
        <xsl:message>
          <processed-item>
            <context-has-id><xsl:value-of select="exists($originalItem/@id)"></xsl:value-of></context-has-id>
            <id><xsl:value-of select="fn:data($originalItem/@id)"/></id>
            <context-has-idref><xsl:value-of select="exists($originalItem/@idref)"></xsl:value-of></context-has-idref>
            <idref><xsl:value-of select="fn:data($originalItem/@idref)"/></idref>
            <looked-up>
              <xsl:copy-of select="$reference/*[@id = fn:data($originalItem/@idref)]" copy-namespaces="no"/>
            </looked-up>
          </processed-item>
        </xsl:message>
        -->
        <xsl:variable name="actualItem"  as="element()?" select="if ($originalItem/@id) then ($originalItem) else ($reference/*[@id = fn:data($originalItem/@idref)])" />
        <xsl:variable name="id" select="fn:data($actualItem/@id)" />
        <xsl:variable name="expandedContentId" select="generate-id(.)"/>
        
        <xsl:variable name="contentVar" select="concat(count(ancestor::node()), '00000000', count(preceding::node()))"/>
        
        <tbody class="expandableContainer expandableSeparate collapsed" data-stix-content-id="{$id}">
            <tr>
                <td>
                    <div class="expandableToggle objectReference" onclick="embedObject()toggle(this.parentNode.parentNode.parentNode)">
                        <xsl:attribute name="onclick">embedObject(this.parentNode.parentNode.parentNode, '<xsl:value-of select="$id"/>','<xsl:value-of select="$expandedContentId"/>');</xsl:attribute>
                        <xsl:call-template name="calculateColumn1Content">
                            <xsl:with-param name="reference" select="$reference" />
                            <xsl:with-param name="actualItem" select="$actualItem" />
                        </xsl:call-template>
                    </div>
                </td>
                    <xsl:call-template name="calculateColumn2Content">
                        <xsl:with-param name="reference" select="$reference" />
                        <xsl:with-param name="actualItem" select="$actualItem" />
                    </xsl:call-template>
                    <xsl:call-template name="calculateColumn3Content">
                        <xsl:with-param name="reference" select="$reference" />
                        <xsl:with-param name="actualItem" select="$actualItem" />
                    </xsl:call-template>
            </tr>
            <tr>
                <td colspan="{$colCount}">
                    <div id="{$expandedContentId}" class="expandableContents">
                        EXPANDABLE CONTENT HERE
                    </div>
                </td>
            </tr>
        </tbody>
    </xsl:template>
    
    <!-- REFERENCE: HELP_UPDATE_STEP_1E -->
    <xsl:template name="printObjectForReferenceList">
        <xsl:param name="reference" select="()" />
        <xsl:param name="normalized" select="()" />
        
        <xsl:variable name="originalObject" select="." />
        <xsl:variable name="actualObject"  as="element()?" select="if ($originalObject/@id) then $originalObject else if ($originalObject/@idref) then ($reference/*[@id = fn:data($originalObject/@idref)]) else if ($originalObject/@object_reference) then $reference/*[@id = fn:data($originalObject/@object_reference)] else ()" />
        
        <xsl:variable name="expandedContentId" select="generate-id(.)"/>
        
        <xsl:variable name="id" select="fn:data($actualObject/@id)" />
        
        <div id="{fn:data($actualObject/@id)}" class="expandableContainer expandableSeparate collapsed">
            <!-- <div class="expandableToggle objectReference" onclick="toggle(this.parentNode)"> -->
            <div class="expandableToggle objectReference">
                <xsl:attribute name="onclick">embedObject(this.parentElement, '<xsl:value-of select="$id"/>','<xsl:value-of select="$expandedContentId"/>');</xsl:attribute>
                <xsl:value-of select="$actualObject/@id"/>
                <xsl:call-template name="itemHeadingOnly">
                    <xsl:with-param name="reference" select="$reference" />
                    <xsl:with-param name="normalized" select="$normalized" />
                </xsl:call-template>
                
            </div>
            
            <div id="{$expandedContentId}" class="expandableContents">
                <xsl:apply-templates select="$actualObject" mode="#default" />
            </div>
        </div>
    </xsl:template>
  
    <!-- CANDIDATE FOR DELETION -->
    <xsl:template name="processObservableInline">
        <xsl:variable name="localName" select="local-name()"/>
        <!-- <xsl:variable name="identifierName" select="if ($localName = 'Object') then 'object' else if ($localName = 'Event') then 'event' else if ($localName = 'Related_Object') then 'relatedObject' else if ($localName = 'Associated_Object') then 'associatedObject' else ''" /> -->
        <xsl:variable name="identifierName">Observable</xsl:variable>
        <xsl:variable name="friendlyName" select="fn:replace($localName, '_', ' ')" />
        <xsl:variable name="headingName" select="fn:upper-case($friendlyName)" />
        <xsl:variable name="includeHeading" select="fn:true()" />
        
        <xsl:variable name="targetId" select="fn:data(@id)" />
        <xsl:variable name="idVar" select="generate-id(.)"/>
        
        <!-- create hidden div which will contain a fresh copy of the object at runtime -->
        <xsl:if test="@id">
            <div style="overflow:hidden; display:none; padding:0px 0px;" class="copyobj">
                <xsl:attribute name="id">copy-<xsl:value-of select="@id" />
                </xsl:attribute>
            </div>
        </xsl:if>

        <div> <!-- container div -->
            <!--
              The following is important - it makes this object "linkable" with
              an id. This means the idref links can be resolved to show linked
              objects.  This is the object that will be highlighted when a link
              is clicked.
            -->
            <!--
            <xsl:if test="@id and $includeHeading">
                <xsl:attribute name="id" select="@id"/>
            </xsl:if>
            -->
            <xsl:attribute name="class">
                <!-- <xsl:text>baseobj </xsl:text> -->
                <!--
                <xsl:text>container </xsl:text>
                <xsl:value-of select="$identifierName" />
                <xsl:text> </xsl:text>
                <xsl:value-of select="$identifierName" /><xsl:text>Container </xsl:text>
                -->
                expandableContainer expandableSeparate collapsed
            </xsl:attribute>
            
            <xsl:if test="@id">
                <xsl:variable name="targetId" select="string(@id)"/>
                <xsl:variable name="targetObject" select="."/>
                
                <xsl:variable name="relationshipOrAssociationType" select="cybox:Relationship|cybox:Association_Type" />

                <div class="expandableToggle objectReference">
                    <!-- <xsl:attribute name="onclick">toggle(this.parentElement)</xsl:attribute> -->
                    <xsl:attribute name="onclick">embedObject(this.parentElement, '<xsl:value-of select="$targetId"/>','<xsl:value-of select="$idVar"/>');</xsl:attribute>
                    <xsl:call-template name="clickableIdref">
                        <xsl:with-param name="targetObject" select="$targetObject" />
                        <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType"/>
                        <xsl:with-param name="idref" select="$targetId"/>
                    </xsl:call-template>
                </div>
                
                <div class="expandableContents">
                    <xsl:attribute name="id"><xsl:value-of select="$idVar"/></xsl:attribute>
                </div>
                
                <!--
                <xsl:call-template name="headerAndExpandableContent">
                    <xsl:with-param name="targetId" select="$targetId"/>
                    <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType" />
                </xsl:call-template>
                -->
            </xsl:if>
            <!--
              If this "object" is an object reference (an "idref link")
              print out the link that will jump to the original object.
            -->
            <xsl:if test="@idref">
                
                <xsl:variable name="targetId" select="string(@idref)"/>
                <xsl:variable name="targetObject" select="//*[@id = $targetId]"/>
                
                <xsl:variable name="relationshipOrAssociationType" select="cybox:Relationship|cybox:Association_Type" />
                
                <xsl:variable name="idGen">
                    <xsl:choose>
                        <xsl:when test="@idgen">
                            <xsl:value-of select="@idGen" />
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:value-of select="''" />
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:variable>
                
                <xsl:call-template name="headerAndExpandableContent">
                    <xsl:with-param name="targetId" select="string(@idref)"/>
                    <xsl:with-param name="isIDGenerated" select="$idGen" />
                    <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType" />
                </xsl:call-template>
            </xsl:if>
            
            
            <!--
            <div class="expandableToggle objectReference">
                <xsl:attribute name="onclick">embedObject(this.parentElement, '<xsl:value-of select="$targetId"/>','<xsl:value-of select="$idVar"/>');</xsl:attribute>
                
                <xsl:call-template name="inlineObjectHeading">
                    <xsl:with-param name="currentObject" select="." />
                    <xsl:with-param name="relationshipOrAssociationType" select="cybox:Relationship|cybox:Association_Type"/>
                    <xsl:with-param name="id" select="@id"/>
                </xsl:call-template>
            </div>
            -->
            
            <!--
            <xsl:call-template name="processObservableCommon" />
            -->
            
        </div>
        
        <xsl:call-template name="processObservableContents" />
        
        <div>
            
            
            <!--
              The following is important - it makes this object "linkable" with
              an id. This means the idref links can be resolved to show linked
              objects.  This is the object that will be highlighted when a link
              is clicked.
            -->
            <!--
            <xsl:if test="@id and $includeHeading">
                <xsl:attribute name="id" select="@id"/>
                <div>CONTENT HERE</div>
                <xsl:call-template name="processObservableCommon" />
            </xsl:if>
            -->
            
        </div>
    </xsl:template>
  
  
  <xsl:template name="processObservableContents">
    <xsl:if test="cybox:Title">
        <div id="section">
            <table class="one-column-emphasis">
                <colgroup>
                    <col class="oce-first-obs" />
                </colgroup>
                <tbody>
                    <tr>
                        <td>Title</td>
                        <td>
                            <xsl:for-each select="cybox:Title">
                                <xsl:value-of select="."/>
                            </xsl:for-each>
                        </td>
                    </tr>
                </tbody>
            </table> 
        </div>
    </xsl:if>              
    <xsl:if test="not(cybox:Observable_Composition)">
        <div id="section">
            <table class="one-column-emphasis">
                <colgroup>
                    <col class="oce-first-obs" />
                </colgroup>
                <tbody>
                    <tr>
                        <td>
                            <xsl:apply-templates select="cybox:Object|cybox:Event"></xsl:apply-templates>
                        </td>
                    </tr>
                </tbody>
            </table> 
        </div>
    </xsl:if>
    <xsl:if test="cybox:Observable_Composition">
        <div id="section">
            <table class="one-column-emphasis">
                <colgroup>
                    <col class="oce-first-obs" />
                </colgroup>
                <tbody>
                    <tr>
                        <td>Observable Composition</td>
                        <td>
                            <xsl:for-each select="cybox:Observable_Composition">
                                <xsl:call-template name="processObservableCompositionSimple" />
                            </xsl:for-each>
                        </td>
                    </tr>
                </tbody>
            </table> 
        </div>
    </xsl:if>
  </xsl:template>
    
    <!--
      Produce the details for an observable composition.
      
      This creates a table with a big cell on the left that includes the binary
      operator ("and" or "or").  Then on the right is a sequence of rows
      representing the expressions that are joined by the operator.
      
      This is visualized with colored backgrounds via css.
    -->
    <xsl:template name="processObservableCompositionSimple">
        <table class="compositionTableOperator">
            <colgroup>
                <xsl:choose>
                    <xsl:when test="@operator='AND'">
                        <col class="oce-first-obscomp-and"/>
                    </xsl:when>
                    <xsl:when test="@operator='OR'">
                        <col class="oce-first-obscomp-or"/>
                    </xsl:when>
                </xsl:choose>
            </colgroup>
            <tbody>
                <tr>
                    <th>
                        <xsl:attribute name="rowspan"><xsl:value-of select="count(cybox:Observable)"/></xsl:attribute>
                        <span><xsl:value-of select="@operator"/></span>
                    </th>
                    <td>
                        <table class="compositionTableOperand">
                            <xsl:for-each select="cybox:Observable">
                                <tr>
                                    <td>
                                        <xsl:call-template name="processObservableInObservableCompositionSimple" />
                                    </td>
                                </tr>
                                
                            </xsl:for-each>
                            <tr>
                            </tr>
                        </table>
                    </td>
                </tr>
                
            </tbody>
        </table> 
    </xsl:template>
    
    <!--
      Print out the heading for an object instance.  This is not expandable or anything.  It can be used in different contexts.
      
      It follows the format:
        [relationship_or_association type] (circle) [current_object_type] (circle)
        
      Usually, the object id is printed out immediately before this.
    -->
    <xsl:template name="itemHeadingOnly">
        <xsl:param name="reference" select="()" />
        <xsl:param name="normalized" select="()" />
        
        <xsl:param name="currentObject" select="." />
        <xsl:param name="id" select="if ($currentObject/@id) then (fn:data($currentObject/@id)) else (fn:data($currentObject/@idref))"/>
        
        <xsl:variable name="originalObservable" select="$currentObject" />
        <xsl:variable name="actualObservable"  as="element()?" select="if ($originalObservable/@id) then ($originalObservable) else (../*[@id = fn:data($originalObservable/@idref)])" />
        
        <xsl:variable name="relationshipOrAssociationType" select="$actualObservable/(cybox:Relationship|cybox:Association_Type)"/>
        
        <xsl:variable name="currentObjectType">
            <xsl:choose>
                <!-- case 1: cybox objects have a cybox:Properties child with an xsi type,
                     or an observable has a child that is an object that has cybox:Properties
                -->
                <xsl:when test="($currentObject/cybox:Properties|$currentObject/cybox:*/cybox:Properties)/@xsi:type">
                    <xsl:value-of select="fn:local-name-from-QName(fn:resolve-QName(($currentObject/cybox:Properties|$currentObject/cybox:*/cybox:Properties)/@xsi:type, ($currentObject/cybox:Properties|$currentObject/cybox:*/cybox:Properties)))"/>
                </xsl:when>
                <!-- case 2: the current item is a cybox event or an observable that contains an event  -->
                <xsl:when test="$currentObject/cybox:Type|$currentObject/cybox:Event/cybox:Type">
                    <xsl:value-of select="($currentObject/cybox:Type|$currentObject/cybox:Event/cybox:Type)/text()" />
                </xsl:when>
                <!-- catch all -->
                <xsl:otherwise></xsl:otherwise>
            </xsl:choose>
        </xsl:variable>
      
        <xsl:if test="$relationshipOrAssociationType or $currentObjectType">
          <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
        
        <xsl:if test="$relationshipOrAssociationType">
            <xsl:value-of select="$relationshipOrAssociationType/text()" />
            <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
        
        <xsl:if test="$currentObjectType">
            <xsl:text> </xsl:text>
            <xsl:value-of select="$currentObjectType" />
            <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
    </xsl:template>

    
    <!--
      Print out the heading for an inline object instance (it has an id
      attribute and does not have an idref attribute).
    -->
    <xsl:template name="inlineObjectHeading">
        <xsl:param name="type"/>
        <xsl:param name="currentObject"/>
        <xsl:param name="relationshipOrAssociationType" select="''"/>
        <xsl:param name="id"/>
        
        <xsl:variable name="currentObjectType">
            <xsl:choose>
                <!-- case 1: cybox objects have a cybox:Properties child with an xsi type,
                     or an observable has a child that is an object that has cybox:Properties
                -->
                <xsl:when test="($currentObject/cybox:Properties|$currentObject/cybox:*/cybox:Properties)/@xsi:type"><xsl:value-of select="fn:local-name-from-QName(fn:resolve-QName(($currentObject/cybox:Properties|$currentObject/cybox:*/cybox:Properties)/@xsi:type, ($currentObject/cybox:Properties|$currentObject/cybox:*/cybox:Properties)))"/></xsl:when>
                <!-- case 2: the current item is a cybox event or an observable that contains an event  -->
                <xsl:when test="$currentObject/cybox:Type|$currentObject/cybox:Event/cybox:Type"><xsl:value-of select="($currentObject/cybox:Type|$currentObject/cybox:Event/cybox:Type)/text()"/></xsl:when>
                <!-- catch all -->
                <xsl:otherwise></xsl:otherwise>
            </xsl:choose>
        </xsl:variable>
        
        <xsl:if test="$relationshipOrAssociationType">
            <xsl:value-of select="$relationshipOrAssociationType/text()" />
            <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
        
        <xsl:if test="$currentObjectType">
            <xsl:text> </xsl:text>
            <xsl:value-of select="$currentObjectType" />
            <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
        
        <xsl:element name="span">
            <xsl:attribute name="class" select="'inlineObject'" />
            
            <!-- THIS IS THE MAIN LINK TEXT -->
            "<xsl:value-of select="$id"/>"
            
        </xsl:element>
        <xsl:text> </xsl:text>
    </xsl:template>
    
    <!--
      This generates a "link" for an idref.  The link is really just text with
      an onclick event listener that calls highlightTarget().  
      
      When the user clicks the link, the referenced object (any element) will
      be found, it's parent top-level observable will be expanded.
    -->
    <xsl:template name="clickableIdref">
        <xsl:param name="targetObject"/>
        <xsl:param name="relationshipOrAssociationType" select="''"/>
        <xsl:param name="idref"/>
        
        <xsl:variable name="targetObjectType">
            <xsl:choose>
                <!-- case 0: targetObject not present -->
                <xsl:when test="not($targetObject)"></xsl:when>
                <!-- case 1: cybox objects have a cybox:Properties child with an xsi type,
                     or an observable has a child that is an object that has cybox:Properties
                -->
                <xsl:when test="($targetObject/cybox:Properties|$targetObject/cybox:*/cybox:Properties)/@xsi:type">
                    <xsl:value-of select="fn:local-name-from-QName(fn:resolve-QName(($targetObject/cybox:Properties|$targetObject/cybox:*/cybox:Properties)/@xsi:type, ($targetObject/cybox:Properties|$targetObject/cybox:*/cybox:Properties)))"/>
                </xsl:when>
                <!-- case 2: cybox event with a name  -->
                <xsl:when test="$targetObject/cybox:Name|$targetObject/cybox:Event/cybox:Name">
                    <xsl:value-of select="($targetObject/cybox:Name|$targetObject/cybox:Event/cybox:Name)/text()"/>
                </xsl:when>
                <!-- case 3: the current item is a cybox event or an observable that contains an event  -->
                <xsl:when test="$targetObject/cybox:Type|$targetObject/cybox:Event/cybox:Type">
                    <xsl:value-of select="($targetObject/cybox:Type|$targetObject/cybox:Event/cybox:Type)/text()"/>
                </xsl:when>
                <!-- catch all -->
                <xsl:otherwise></xsl:otherwise>
            </xsl:choose>
        </xsl:variable>
        
        <xsl:if test="$relationshipOrAssociationType">
           <xsl:value-of select="$relationshipOrAssociationType/text()" />
           <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
        
        <xsl:if test="not($targetObject)">
            <xsl:text> </xsl:text><span class="externalLinkWarning">[external]</span>
        </xsl:if>

        <xsl:if test="$targetObjectType">
            <xsl:text> </xsl:text>
            <xsl:value-of select="$targetObjectType" />
            <xsl:text> &#x25CB; </xsl:text>
        </xsl:if>
        
        <!-- THIS IS THE MAIN LINK TEXT -->
        <xsl:if test="$idref!='[No ID]'">"</xsl:if>
        <xsl:value-of select="$idref"/>
        <xsl:if test="$idref!='[No ID]'">"</xsl:if>

        <xsl:text> </xsl:text>
        
    </xsl:template>

    <!--
      This template formats the output for an observable that is contained
      within an observable composition.
      
      If it's an idref link, it will produce a clickable "link".
      
      If it's actual content, it will call the template
      processObservableCompositionSimple to print it out.
    -->
    <xsl:template name="processObservableInObservableCompositionSimple">
        <xsl:if test="@idref">
            <div class="foreignObservablePointer">
                <!-- <xsl:variable name="targetId" select="string(@idref)"/> -->
                <xsl:variable name="relationshipOrAssociationType" select="''" />
                
                <xsl:variable name="idGen">
                    <xsl:choose>
                        <xsl:when test="@idgen">
                            <xsl:value-of select="@idGen" />
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:value-of select="''" />
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:variable>
                
                
                <xsl:call-template name="headerAndExpandableContent">
                    <xsl:with-param name="targetId" select="string(@idref)"/>
                    <xsl:with-param name="isIDGenerated" select="$idGen" />
                    <xsl:with-param name="isComposition" select="fn:true()"/>
                    <xsl:with-param name="relationshipOrAssociationType" select="''" />
                </xsl:call-template>
            </div>
        </xsl:if>
        
        <xsl:for-each select="cybox:Observable_Composition">
            <xsl:call-template name="processObservableCompositionSimple" />
        </xsl:for-each>
   </xsl:template>
    
    <xsl:template name="headerAndExpandableContent">
        <xsl:param name="targetId" />
        <xsl:param name="isIDGenerated" />
        <xsl:param name="isComposition" select="fn:false()" />
        <xsl:param name="targetObject" select="//*[@id = $targetId]" />
        <xsl:param name="relationshipOrAssociationType" select="$targetObject/(cybox:Relationship|cybox:Association_Type)" />
        
         <xsl:choose>
            <xsl:when test="$targetObject">
                <div class="expandableContainer expandableSeparate collapsed" data-stix-content-id="{$targetId}">
                    <xsl:variable name="idVar" select="generate-id(.)"/>

                    <xsl:variable name="displayID">
                        <xsl:choose>
                            <xsl:when test="$isIDGenerated='true'">
                                <xsl:value-of select="'[No ID]'" />
                            </xsl:when>
                            <xsl:otherwise>
                                <xsl:value-of select="$targetId" />
                            </xsl:otherwise>
                        </xsl:choose>
                    </xsl:variable>

                    <xsl:choose>
                        <xsl:when test="$isComposition">
                            <div class="expandableToggle objectReference">
                                <xsl:attribute name="onclick">embedObject(this.parentElement, '<xsl:value-of select="$targetId"/>','<xsl:value-of select="$idVar"/>');</xsl:attribute>
                                <xsl:call-template name="clickableIdref">
                                    <xsl:with-param name="targetObject" select="$targetObject" />
                                    <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType"/>
                                    <xsl:with-param name="idref" select="$displayID"/>
                                </xsl:call-template>
                            </div>
                            
                            <div class="expandableContents">
                                <xsl:attribute name="id"><xsl:value-of select="$idVar"/></xsl:attribute>
                            </div>
                            <!--
                            <div class="copyobserv expandableContents">
                                <xsl:attribute name="id">copy-<xsl:value-of select="$targetId"/></xsl:attribute>
                            </div>
-->
                        </xsl:when>
                        <xsl:otherwise>
                            <div class="expandableToggle objectReference">
                                <xsl:attribute name="onclick">embedObject(this.parentElement, '<xsl:value-of select="$targetId"/>','<xsl:value-of select="$idVar"/>');</xsl:attribute>
                                <xsl:call-template name="clickableIdref">
                                    <xsl:with-param name="targetObject" select="$targetObject" />
                                    <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType"/>
                                    <xsl:with-param name="idref" select="$displayID"/>
                                </xsl:call-template>
                            </div>
                            
                            <div class="expandableContents">
                                <xsl:attribute name="id"><xsl:value-of select="$idVar"/></xsl:attribute>
                            </div>
                        </xsl:otherwise>
                    </xsl:choose>
                </div>
            </xsl:when>
            <xsl:otherwise>
                <div class="objectReference nonexpandableContainer">
                  <xsl:call-template name="clickableIdref">
                      <xsl:with-param name="targetObject" select="$targetObject" />
                      <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType"/>
                      <xsl:with-param name="idref" select="$targetId"/>
                  </xsl:call-template>
                </div>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    
    
    
    <!--
      Simple template to print out the xsi:type in parenthesis.  This is used
      in several places including printing out Actions and cybox:Properties.
    -->
    <xsl:template match="@xsi:type"> (<xsl:value-of select="."/>)</xsl:template>
    
    <!--
      template to print out the list of related or related objects (prints
      the heading and call the template to print out actual related/associated
      objects).
    -->
    <xsl:template match="cybox:Related_Objects|cybox:Associated_Objects|ttp:Related_TTPs">
        <xsl:variable name="relatedOrAssociated" select="if (local-name() = 'Related_Objects') then ('related') else if (local-name() = 'Associated_Objects') then ('associated') else ('other')" />
        <xsl:variable name="relatedOrAssociatedCapitalized" select="if (local-name() = 'Related_Objects') then ('Related') else if (local-name() = 'Associated_Objects') then ('Associated') else ('Other')" />
        <div class="container {$relatedOrAssociated}Objects">
            <div class="heading {$relatedOrAssociated}Objects">
                <xsl:value-of select="$relatedOrAssociatedCapitalized"/> Objects
            </div>
            <div class="contents {$relatedOrAssociated}Objects">
                <xsl:apply-templates select="cybox:Related_Object|cybox:Associated_Object|ttp:Related_TTP"></xsl:apply-templates>
            </div>
        </div>
    </xsl:template>

  <!--
    Template to turn any items with an idref into an expandable content toggle.
    
    IMPORTANT: Add elements to the match clause here to expand this functionality to other elements.
    
    See also the similar template in cybox_common.xsl.
  -->
  <!-- REFERENCE: HELP_UPDATE_STEP_3 -->
  <xsl:template match="cybox:Object[@idref]|cybox:Event[@idref]|cybox:Related_Object[@idref]|cybox:Associated_Object[@idref]|stixCommon:Course_Of_Action[@idref]|stix:Course_Of_Action[@idref]|cybox:Action[@idref]|cybox:Action_Reference[@idref]">
      <!-- [object link here - - <xsl:value-of select="fn:data(@idref)" />] -->
    
      <xsl:variable name="idGen">
          <xsl:choose>
              <xsl:when test="@idgen">
                  <xsl:value-of select="@idgen" />
              </xsl:when>
              <xsl:otherwise>
                  <xsl:value-of select="''" />
              </xsl:otherwise>
          </xsl:choose>
      </xsl:variable>

      <xsl:call-template name="headerAndExpandableContent">
          <xsl:with-param name="targetId" select="fn:data(@idref)" />
          <xsl:with-param name="isIDGenerated" select="$idGen" />
      </xsl:call-template>
  </xsl:template>
  
  
    <!--
      This is the consolidated Swiss Army knife template that prints object
      type data.
      
      This prints out objects that are:
       * Object
       * Event
       * Related Object
       * Associated Object
       
       It also prints out either original inline objects (with an id) or object references (with and idref).
    -->
    <!--<xsl:template match="cybox:Object[@id]|cybox:Event[@id]|cybox:Related_Object[@id]|cybox:Associated_Object[@id]|cybox:Action_Reference[@id]">-->
    <xsl:template match="cybox:Object|cybox:Event|cybox:Related_Object|cybox:Associated_Object|cybox:Action_Reference">
        <xsl:variable name="localName" select="local-name()"/>
        <xsl:variable name="identifierName" select="if ($localName = 'Object') then 'object' else if ($localName = 'Event') then 'event' else if ($localName = 'Related_Object') then 'relatedObject' else if ($localName = 'Associated_Object') then 'associatedObject' else ''" />
        <xsl:variable name="friendlyName" select="fn:replace($localName, '_', ' ')" />
        <xsl:variable name="headingName" select="fn:upper-case($friendlyName)" />
      
        <div class="debug">NOT THERE</div>
        
        <div class="container {$identifierName}Container {$identifierName}">
            <div class="contents {$identifierName}Contents {$identifierName}">
                <!-- Print the description if one is available (often they are not) -->
                <xsl:if test="cybox:Description">
                    <div class="{$identifierName}Description description">
                        <xsl:value-of select="cybox:Description"/>
                    </div>
                </xsl:if>
                
                <!--
                  If this is an Event, we need to print out the list of Actions
                 -->               
                <xsl:if test="cybox:Actions/cybox:Action">
                    <div class="container">
                        <div class="heading actions">Actions</div>
                        <div class="contents actions">
                            <xsl:apply-templates select="cybox:Actions/cybox:Action" />
                        </div>
                    </div>
                </xsl:if>
                
                <!-- print out defined object type information if it's available -->
                <xsl:if test="cybox:Defined_Object/@xsi:type">
                    <div id="defined_object_type_label">defined object type: <xsl:value-of select="cybox:Defined_Object/@xsi:type"/></div>
                </xsl:if>
                
                <!--
                  print out the all-important cybox:Properties.  Lots of details in here!!
                -->
                <div>
                    <xsl:apply-templates select="cybox:Properties"></xsl:apply-templates>
                </div>
                
                <!--
                  Associated Objects need to have any Related Objects printed out
                -->
                <xsl:apply-templates select="cybox:Related_Objects"></xsl:apply-templates>
            </div>
        </div>
    </xsl:template>
  
    <!-- REFERENCE: HELP_UPDATE_STEP_2 -->
    <xsl:template match="cybox:Action">
        <xsl:variable name="localName" select="local-name()"/>
        <xsl:variable name="identifierName" select="'action'"/>
        <xsl:variable name="friendlyName" select="fn:replace($localName, '_', ' ')"/>
        <xsl:variable name="headingName" select="fn:upper-case($friendlyName)"/>

        <div>
            <xsl:choose>
                <xsl:when test="@id">
                    <xsl:attribute name="id">
                        <xsl:value-of select="@id"/>
                    </xsl:attribute>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:attribute name="id">
                        <xsl:value-of select="generate-id(.)"/>
                    </xsl:attribute>
                </xsl:otherwise>
            </xsl:choose>

            <div class="container {$identifierName}Container {$identifierName}">
                <div class="contents {$identifierName}Contents {$identifierName}">
                    <!-- Print the description if one is available (often they are not) -->

                    <xsl:if test="cybox:Description">
                        <xsl:copy-of select="stix:printNameValueTable('Description', cybox:Description)"/>
                    </xsl:if>
                    <xsl:if test="cybox:Action_Aliases">
                        <xsl:variable name="contents">
                            <xsl:apply-templates select="cybox:Action_Aliases"/>
                        </xsl:variable>
                        <xsl:copy-of select="stix:printNameValueTable('Action Aliases', $contents)"/>
                    </xsl:if>
                    <xsl:if test="cybox:Action_Arguments">
                        <xsl:variable name="contents">
                            <xsl:apply-templates select="cybox:Action_Arguments"/>
                        </xsl:variable>
                        <xsl:copy-of select="stix:printNameValueTable('Action Arguments', $contents)"/>
                    </xsl:if>
                    <xsl:if test="cybox:Discovery_Method">
                        <xsl:variable name="contents">
                            <xsl:apply-templates select="cybox:Discovery_Method"/>
                        </xsl:variable>
                        <xsl:copy-of select="stix:printNameValueTable('Discovery Method', $contents)"/>
                    </xsl:if>
                    <xsl:if test="cybox:Frequency">
                        <xsl:copy-of select="stix:printNameValueTable('Frequency', cybox:Frequency)"/>
                    </xsl:if>

                    <!--
                        Associated Objects need to have any Related Objects printed out
                    -->
                    <xsl:if test="cybox:Associated_Objects/cybox:Associated_Object">
                        <xsl:variable name="contents">
                            <xsl:apply-templates select="cybox:Associated_Objects/cybox:Associated_Object"/>
                        </xsl:variable>
                        <xsl:copy-of select="stix:printNameValueTable('Associated Objects', $contents)"/>
                    </xsl:if>

                    <xsl:if test="cybox:Relationships/cybox:Relationship">
                        <xsl:variable name="contents">
                            <xsl:apply-templates select="cybox:Relationships/cybox:Relationship"/>
                        </xsl:variable>
                        <xsl:copy-of select="stix:printNameValueTable('Relationships', $contents)"/>
                    </xsl:if>
                </div>
            </div>
        </div>
    </xsl:template>
  
  <xsl:template match="cybox:Relationship">
    <xsl:variable name="localName" select="local-name()"/>
    <xsl:variable name="identifierName" select="cybox:elementLocalNameToIdentifier($localName)" />
    <xsl:variable name="friendlyName" select="fn:replace($localName, '_', ' ')" />
    <xsl:variable name="headingName" select="fn:upper-case($friendlyName)" />
        
    <div class="container {$identifierName}Container {$identifierName}">
      <div class="heading {$identifierName}Heading {$identifierName}">
        <xsl:value-of select="cybox:Type/text()" />
      </div>
      <div class="contents {$identifierName}Contents {$identifierName}">
        <xsl:apply-templates select="cybox:Action_Reference" />
      </div>
    </div>
  </xsl:template>
  
  <xsl:function name="cybox:elementLocalNameToIdentifier" as="xs:string?">
    <xsl:param name="localName" />
    <xsl:choose>
      <xsl:when test="$localName eq 'Object'" ><xsl:text>object</xsl:text></xsl:when>
      <xsl:when test="$localName eq 'Event'" ><xsl:text>event</xsl:text></xsl:when>
      <xsl:when test="$localName eq 'Related_Object'" ><xsl:text>relatedObject</xsl:text></xsl:when>
      <xsl:when test="$localName eq 'Associated_Object'" ><xsl:text>associatedObject</xsl:text></xsl:when>
      <xsl:otherwise><xsl:text>unknownObject</xsl:text></xsl:otherwise>
    </xsl:choose>
    
    <!-- <xsl:variable name="identifierName" select="if ($localName = 'Object') then 'object' else if ($localName = 'Event') then 'event' else if ($localName = 'Related_Object') then 'relatedObject' else if ($localName = 'Associated_Object') then 'associatedObject' else ''" /> -->
  </xsl:function>
    
    <!--
      Print the details of an action.
      
      TODO: Merge this into the master object template.
    -->
    <!-- <xsl:template name="processAction"> -->
  <!--
    <xsl:template match="cybox:Action">
        <div>AHAH!!</div>
        <div class="container action">
            <div class="heading action">ACTION <xsl:value-of select="cybox:Type/text()" /> (xsi type: <xsl:value-of select="cybox:Type/@xsi:type" />)</div>
            <div class="contents action">
                <xsl:apply-templates select="cybox:Associated_Objects"></xsl:apply-templates>
            </div>
        </div>
    </xsl:template>
    -->
    
    <!--
      Print out the details of cybox:Properties.
      
      For each property, print out the name, value, and constrains.
      
      Normally, the name is the element local name, the value is the text value
      of the context property element (all its descendent text nodes
      concatenated together), and the constrains is a list of all the
      attributes on the properties element (the element that is a direct
      child of cybox:Properties).
      
      This is customizable by writing custom templates for specific properties.
    -->
    <xsl:template match="cybox:Properties|ttp:Behavior|ta:Identity|ta:Type|ta:Motivation|et:Vulnerability|stixCommon:Course_Of_Action|stix:Course_Of_Action">
        <fieldset>
            <legend>
                <xsl:if test="./self::cybox:Properties">cybox properties</xsl:if>
                <xsl:if test="./self::ttp:Behavior">behavior</xsl:if>
                <xsl:if test="./self::ta:Identity">identity</xsl:if>
                <xsl:if test="./self::ta:Type">type</xsl:if>
                <xsl:if test="./self::ta:Motivation">motivation</xsl:if>
                <xsl:if test="./self::et:Vulnerability">vulnerability</xsl:if>
                <xsl:if test="./self::stixCommon:Course_Of_Action|./self::stix:Course_Of_Action">course of action</xsl:if>
                <xsl:if test="@xsi:type">
                    (type: <xsl:value-of select="local-name-from-QName(fn:resolve-QName(fn:data(@xsi:type), .))"/>)
                </xsl:if>
              <xsl:apply-templates select="@*[not((fn:QName(namespace-uri(), local-name()) = fn:QName('http://www.w3.org/2001/XMLSchema-instance', 'type')) or (fn:QName(namespace-uri(), local-name()) = fn:QName('', 'id')))]" mode="cyboxProperties" />
            </legend>
            <xsl:apply-templates select="*" mode="cyboxProperties"></xsl:apply-templates>
            
        </fieldset>
    </xsl:template>

    <!--
        The following are a series of custom formatters for commonly-used Cybox types.  Each of these 
        templates deviate from the default Cybox Properies output format (above) to simplify 
        schema-related complexity.
    -->
    
    <!--
        To extend support to a custom-defined object type, ensure that you have added your namespace
        to the main <xsl:stylesheet> element at the top of this document and be sure to add your
        prefix to the 'exclude-result-prefixes' attribute.  Next, define a template which matches an 
        xpath expression of the elements/attributes you'd like to handle.
        
        For example, to output the mileage per gallon for red trucks in bold: 
        
        <xsl:template match="vehicles:Truck[@color='red']/MPG">
            <div class="container truckProperties">
                <strong><xsl:value-of select="." /></strong>
            </div>
        </xsl:template>
    -->

    <!--
      Show email raw headers wrapped in a div with a class that is css styled
      to preserve wrapping in the original content.
    -->
    <xsl:template match="EmailMessageObj:Raw_Header/text()|EmailMessageObj:Raw_Body/text()" mode="cyboxProperties">
        <div class="verbatim">
            <xsl:value-of select="fn:data(.)" />
        </div>
    </xsl:template>
  
    <xsl:template match="text()[../self::*:Description[@structuring_format='HTML5']]" mode="cyboxProperties">
      <xsl:variable name="content" select="fn:data(.)" />
      <div class="htmlContainer" data-stix-content="{$content}" />
    </xsl:template>
  
    <!--
      Output hash value without unnecessary nested schema tree structure
    -->
    <xsl:template match="Common:Hash" mode="cyboxProperties">
        <div class="container cyboxPropertiesContainer cyboxProperties">
            <span class="cyboxPropertiesName"><xsl:value-of select="local-name()"/> </span>
            <span class="cyboxPropertiesValue">
                <xsl:value-of select="./Common:Type"/> = 
                <xsl:value-of select="./Common:Simple_Hash_Value|./Common:Fuzzy_Hash_Value"/>
            </span>            
        </div>
    </xsl:template>

    <!--
      Output URI & Link value without unnecessary nested schema tree structure
    -->
    <xsl:template match="cybox:Properties[contains(@xsi:type,'URIObjectType')]|cybox:Properties[contains(@xsi:type,'LinkObjectType')]">
        <fieldset>
            <legend>URI</legend>
            <div class="container cyboxPropertiesContainer cyboxProperties">
                <div class="heading cyboxPropertiesHeading cyboxProperties">
                    <xsl:apply-templates select="URIObject:Value" mode="cyboxProperties" />
                </div>
            </div>
        </fieldset>
    </xsl:template>
    <xsl:template match="URIObject:Value" mode="cyboxProperties">
        Value <xsl:value-of select="Common:Defanged(@is_defanged, @defanging_algorithm_ref)" />
        <xsl:choose>
            <xsl:when test="@condition!=''"><xsl:value-of select="Common:ConditionType(@condition)" /></xsl:when>
            <xsl:otherwise> = </xsl:otherwise>
        </xsl:choose>
        <xsl:value-of select="." />
    </xsl:template>

    <!--
      Output Port value without unnecessary nested schema tree structure
    -->
    <xsl:template match="*:Port[contains(@xsi:type,'PortObjectType')]|*:Port[./*:Port_Value]" mode="cyboxProperties">
        <div class="container cyboxPropertiesContainer cyboxProperties">
            <div class="heading cyboxPropertiesHeading cyboxProperties">
                Port <xsl:choose>
                    <xsl:when test="@condition!=''"><xsl:value-of select="Common:ConditionType(@condition)" /></xsl:when>
                    <xsl:otherwise> = </xsl:otherwise>
                </xsl:choose>
                <xsl:value-of select="." />
            </div>
        </div>
    </xsl:template>
    
    <!--
      Output Address value without unnecessary nested schema tree structure
    -->
    <xsl:template match="cybox:Properties[contains(@xsi:type,'AddressObjectType')]">
        <xsl:call-template name="Common:Address">
            <xsl:with-param name="context" select="."/>
        </xsl:call-template>
    </xsl:template>
    <xsl:template match="*:IP_Address" mode="cyboxProperties">
        <xsl:call-template name="Common:Address">
            <xsl:with-param name="context" select="."/>
        </xsl:call-template>
    </xsl:template>
    <xsl:template name="Common:Address">
        <xsl:param name="context" />
        <div class="container cyboxPropertiesContainer cyboxProperties">
            <div class="heading cyboxPropertiesHeading cyboxProperties">
                <xsl:if test="$context/@isSource='true'">(source) </xsl:if>
                <xsl:if test="$context/@isDestination='true'">(destination) </xsl:if>
                <xsl:value-of select="Common:Category($context/@category)" />
                <xsl:apply-templates mode="cyboxProperties" />
            </div>
        </div>
    </xsl:template>
    <xsl:function name="Common:Category">
        <xsl:param name="category" />
        <xsl:choose>
            <xsl:when test="$category='ipv4-addr'">IPv4 </xsl:when>
            <xsl:when test="$category='ipv4-net'">IPv4 network </xsl:when>
            <xsl:when test="$category='ipv4-net-mask'">IPv4 netmask</xsl:when>
            <xsl:when test="$category='ipv6-addr'">IPv6 </xsl:when>
            <xsl:when test="$category='ipv6-addr'">IPv6 network </xsl:when>
            <xsl:when test="$category='ipv6-net-mask'">IPv6 netmask </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="$category" />
            </xsl:otherwise>
        </xsl:choose>
    </xsl:function>
    <xsl:template match="AddressObject:Address_Value" mode="cyboxProperties">
        Address <xsl:value-of select="Common:Defanged(@is_defanged, @defanging_algorithm_ref)" />
        <xsl:choose>
            <xsl:when test="@condition!=''"><xsl:value-of select="Common:ConditionType(@condition)" /></xsl:when>
            <xsl:otherwise> = </xsl:otherwise>
        </xsl:choose>
        <xsl:value-of select="." />
    </xsl:template>
    <xsl:function name="Common:ConditionType">
        <xsl:param name="condition" />
        <xsl:choose>
            <xsl:when test="$condition='Equals'"> = </xsl:when>
            <xsl:when test="$condition='DoesNotEqual'"> != </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="$condition" />: 
            </xsl:otherwise>
        </xsl:choose>
    </xsl:function>
    <xsl:function name="Common:Defanged">
        <xsl:param name="is_defanged" />
        <xsl:param name="defanging_algorithm_ref" />
        <xsl:if test="$is_defanged='true'">
            (defanged 
            <xsl:if test="$defanging_algorithm_ref!=''">
                with <xsl:value-of select="$defanging_algorithm_ref" />
            </xsl:if>
            )
        </xsl:if>
    </xsl:function>
    
    <!--
      default template for outputting hierarchical cybox:Properties names/values/constraints
    -->
    <xsl:template match="element()" mode="cyboxProperties">
        <div class="container cyboxPropertiesContainer cyboxProperties">
            <div class="heading cyboxPropertiesHeading cyboxProperties">
                <span class="cyboxPropertiesName"><xsl:value-of select="local-name()"/> </span>
                <span class="cyboxPropertiesConstraints"><xsl:apply-templates select="@*[not(node-name(.) = fn:QName('', 'id')) and not(node-name(.) = fn:QName('', 'idref')) and not(node-name(.) = fn:QName('', 'object_reference'))][not(node-name(.) = fn:QName('http://www.w3.org/2001/XMLSchema-instance', 'type'))]" mode="#current"/></span>
                <xsl:if test="text()">
                    <span class="cyboxPropertiesNameValueSeparator"> &#x2192; </span>
                </xsl:if>
                <span class="cyboxPropertiesValue">
                    <xsl:apply-templates select="text()" mode="#current"/>
                </span>
                <div class="cyboxPropertiesLink">
                    <xsl:apply-templates select="@*[node-name(.) = fn:QName('', 'object_reference')]" mode="#current"></xsl:apply-templates>
                </div>
            </div>
            <div class="contents cyboxPropertiesContents cyboxProperties">
                <div class="idOrIdrefInsideCyboxProperties">
                    <xsl:apply-templates select="@*[(node-name(.) = fn:QName('', 'id')) or (node-name(.) = fn:QName('', 'idref')) or (node-name(.) = fn:QName('', 'object_reference'))]" mode="#current"/>
                </div>
                <xsl:apply-templates select="*" mode="#current"></xsl:apply-templates>
            </div>
        </div>
    </xsl:template>
    
    <xsl:template match="text()" mode="cyboxProperties">
        <xsl:choose>
            <xsl:when test="string-length() gt 200">
                <div class="longText expandableContainer expandableToggle expandableContents collapsed expandableSame" onclick="toggle(this)"><xsl:value-of select="fn:data(.)" /></div>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="fn:data(.)" />
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    
    <!--
      default template for printing out constraints associated with cybox:Properties entries
    -->
    <xsl:template match="attribute()" mode="cyboxProperties">
        <span class="cyboxPropertiesSingleConstraint">
          <xsl:if test="position() = 1"> [</xsl:if>
          <xsl:value-of select="local-name()"/>=<xsl:value-of select="fn:data(.)"/>
          <xsl:if test="position() != last()">, </xsl:if>
          <xsl:if test="position() = last()">]</xsl:if>
        </span>
    </xsl:template>

    <!--
       do not show the type on cybox:Properties entries
    -->
    <xsl:template match="@xsi:type" mode="cyboxProperties">
    </xsl:template>
    
    <!--
      print out object reference links
    -->
    <xsl:template match="@object_reference|@idref" mode="cyboxProperties">
        <!-- <xsl:variable name="targetId" select="fn:data(.)"/> -->
        
        <xsl:variable name="idGen">
            <xsl:choose>
                <xsl:when test="..[@idgen]">
                    <xsl:value-of select="..[@idGen]" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="''" />
                </xsl:otherwise>
            </xsl:choose>
        </xsl:variable>
        
        <xsl:variable name="relationshipOrAssociationType" select="()" />
        <xsl:call-template name="headerAndExpandableContent">
            <xsl:with-param name="targetId" select="fn:data(.)"/>
            <xsl:with-param name="isIDGenerated" select="$idGen" />
            <xsl:with-param name="relationshipOrAssociationType" select="$relationshipOrAssociationType" />
        </xsl:call-template>
    </xsl:template>   
  
  
  <!--
    Simple function used all over the place to add a name/value table to the output content.
    
    This is used largely in the top level category tables to indicate which
    field/subelement and its corresponding value.
    
    The value can be any complex content.  A complex node can be used to include rich html.
  -->
  <xsl:function name="stix:printNameValueTable">
    <xsl:param name="title" />
    <xsl:param name="value" />
    
    <div class="nameValueTable">
      <table class="one-column-emphasis indicator-sub-table">
        <colgroup>
          <col class="oce-first-obs heading-column" />
          <col class="details-column" />
        </colgroup>
        <tbody>
          <tr>
            <td><xsl:value-of select="$title" /></td>
            <td>
              <xsl:copy-of select="$value"/>
            </td>
          </tr>
        </tbody>
      </table> 
    </div>
  </xsl:function>
  
</xsl:stylesheet>
