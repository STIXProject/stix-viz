<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="2.0"
  xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:Common="http://cybox.mitre.org/common-2"
  xmlns:stixCommon="http://stix.mitre.org/common-1"
  
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:incident="http://stix.mitre.org/Incident-1"
  xmlns:threat-actor='http://stix.mitre.org/ThreatActor-1'
  
  xmlns:coa="http://stix.mitre.org/CourseOfAction-1"
  
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:fn="http://www.w3.org/2005/xpath-functions"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  
  xmlns:ttp='http://stix.mitre.org/TTP-1'
  xmlns:ta="http://stix.mitre.org/ThreatActor-1"
  xmlns:et="http://stix.mitre.org/ExploitTarget-1"
  xmlns:stix='http://stix.mitre.org/stix-1'
  
  xmlns:campaign="http://stix.mitre.org/Campaign-1"
  
  xmlns:AddressObject='http://cybox.mitre.org/objects#AddressObject-2'
  xmlns:URIObject='http://cybox.mitre.org/objects#URIObject-2'
  xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
  exclude-result-prefixes="cybox Common xsi fn EmailMessageObj AddressObject URIObject coa ttp ta et"
  >

  <xsl:template name="processAllTopLevelTables">
    <xsl:param name="reference" tunnel="yes" />
    <xsl:param name="normalized" tunnel="yes" />
    
    <!--
      MAIN TOP LEVEL CATEGORY TABLES
    -->
    <div class="topLevelCategoryTables">
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement" select="$normalized/(stix:Observables|cybox:Observables)"/>
        <xsl:with-param name="headingLabels" select="('Title', 'Type', 'ID')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', 'typeColumn', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Observables'"/>
        <xsl:with-param name="categoryIdentifier" select="'observables'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Indicators"/>
        <xsl:with-param name="headingLabels" select="('Title', 'Type', 'Id')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', 'typeColumn', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Indicators'"/>
        <xsl:with-param name="categoryIdentifier" select="'indicators'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:TTPs"/>
        <xsl:with-param name="headingLabels" select="('Title', 'Intended Effect', 'ID')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', 'intendedEffectColumn', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'TTPs'"/>
        <xsl:with-param name="categoryIdentifier" select="'ttps'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement"
          select="$normalized/stix:Exploit_Targets"/>
        <xsl:with-param name="headingLabels" select="('Title', '', 'ID')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', '', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Exploit Targets'"/>
        <xsl:with-param name="categoryIdentifier" select="'exploitTargets'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Incidents"/>
        <xsl:with-param name="headingLabels" select="('Title', '', 'ID')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', '', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Incidents'"/>
        <xsl:with-param name="categoryIdentifier" select="'incidents'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement"
          select="$normalized/stix:Courses_Of_Action"/>
        <xsl:with-param name="headingLabels" select="('Title', 'Type', 'ID')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', 'typeColumn', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Courses of Action'"/>
        <xsl:with-param name="categoryIdentifier" select="'coursesOfAction'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Campaigns"/>
        <xsl:with-param name="headingLabels" select="('Title/Name', 'Intended Effect', 'Id')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', 'intendedEffectColumn', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Campaigns'"/>
        <xsl:with-param name="categoryIdentifier" select="'campaigns'"/>
      </xsl:call-template>
      
      <xsl:call-template name="processTopLevelCategory">
        <xsl:with-param name="reference" select="$reference"/>
        <xsl:with-param name="normalized" select="$normalized"/>
        <xsl:with-param name="categoryGroupingElement" select="$normalized/stix:Threat_Actors"/>
        <xsl:with-param name="headingLabels" select="('Title', '', 'Id')"/>
        <xsl:with-param name="headingColumnStyles" select="('titleColumn', '', 'idColumn')"/>
        <xsl:with-param name="categoryLabel" select="'Threat Actors'"/>
        <xsl:with-param name="categoryIdentifier" select="'threatActors'"/>
      </xsl:call-template>
    </div>
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
    <xsl:param name="reference" select="()" tunnel="yes" />
    <xsl:param name="normalized" select="()" tunnel="yes" />
    <xsl:param name="categoryGroupingElement" select="()"/>
    <xsl:param name="headingLabels" select="('Type', 'ID')"/>
    <xsl:param name="headingColumnStyles" select="('typeColumn', 'idColumn')"/>
    <xsl:param name="categoryLabel"/>
    <xsl:param name="categoryIdentifier"/>
    
    <xsl:if test="$categoryGroupingElement/*">
      <div class="topLevelCategoryContainer {$categoryIdentifier}"
        id="{$categoryIdentifier}TopLevelCategoryContainer">
        <h2>
          <a name="{$categoryIdentifier}TopLevelCategoryHeadingAnchor">
            <xsl:value-of select="$categoryLabel"/>
          </a>
        </h2>
        <div class="expandAll" onclick="expandAll(this.parentNode);">[toggle all <xsl:value-of
          select="$categoryLabel"/>]</div>
        <table class="topLevelCategory {$categoryIdentifier}" cellspacing="0">
          <colgroup>
            <xsl:for-each select="$headingColumnStyles">
              <col class="{.}"/>
            </xsl:for-each>
          </colgroup>
          <thead>
            <tr>
              <xsl:for-each select="$headingLabels">
                <th class="header">
                  <xsl:value-of select="."/>
                </th>
              </xsl:for-each>
            </tr>
          </thead>
          <xsl:for-each select="$categoryGroupingElement/*[@idref]">
            <!-- <xsl:sort select="cybox:Observable_Composition" order="descending"/> -->
            <xsl:variable name="evenOrOdd" select="if(position() mod 2 = 0) then 'even' else 'odd'"/>
            <xsl:call-template name="printGenericItemForTopLevelCategoryTable">
              <xsl:with-param name="reference" select="$reference"/>
              <xsl:with-param name="normalized" select="$normalized"/>
              <xsl:with-param name="colCount" select="count($headingLabels)"/>
            </xsl:call-template>
          </xsl:for-each>
          
          <xsl:for-each select="$categoryGroupingElement/stix:Kill_Chains">
            <thead>
              <tr>
                <th colspan="3">Kill Chains</th>
              </tr>
            </thead>
            <xsl:for-each select="./stixCommon:Kill_Chain">
              <!-- <tr><td colspan="2">kill chain <xsl:value-of select="fn:data(./@idref)"/></td></tr> -->
              
              <xsl:call-template name="printGenericItemForTopLevelCategoryTable">
                <xsl:with-param name="reference" select="$reference"/>
                <xsl:with-param name="normalized" select="$normalized"/>
                <xsl:with-param name="colCount" select="count($headingLabels)"/>
              </xsl:call-template>
              
            </xsl:for-each>
          </xsl:for-each>
        </table>
      </div>
    </xsl:if>
  </xsl:template>
  
  

  <!--
      print one of the "items" (Obserbale, Indicator, TTP, etc) for the top
      level category table.
      
      the same javascript and css logic for expand and collapse that is used
      for nested indicators and observables is now also used here in the top
      level category tables.
    -->
  <xsl:template name="printGenericItemForTopLevelCategoryTable">
    <xsl:param name="reference" select="()" tunnel="yes" />
    <xsl:param name="normalized" select="()" tunnel="yes" />
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
    
    <xsl:variable name="allColumnsSequence" select="cybox:calculateAllColumns($actualItem, $reference)"/>
    
    <xsl:variable name="column1" select="if ($actualItem) then $allColumnsSequence[1] else fn:data($originalItem/@idref)" />
    <xsl:variable name="column2" select="$allColumnsSequence[2]" />
    <xsl:variable name="column3" select="$allColumnsSequence[3]" />
    
    <tbody class="expandableContainer expandableSeparate collapsed" data-stix-content-id="{$id}">
      <tr>
        <td>
          <div class="expandableToggle objectReference" onclick="embedObject()toggle(this.parentNode.parentNode.parentNode)">
            <xsl:attribute name="onclick">embedObject(this.parentNode.parentNode.parentNode, '<xsl:value-of select="$id"/>','<xsl:value-of select="$expandedContentId"/>');</xsl:attribute>
            <xsl:text> </xsl:text>
            <xsl:value-of select="fn:normalize-space($column1)" />
          </div>
        </td>
        <td>
          <xsl:if test="$column2">
            <xsl:copy-of select="$column2" />
          </xsl:if>
        </td>
        <td>
          <xsl:if test="$column3">
            <xsl:copy-of select="$column3" />
          </xsl:if>
        </td>
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
  
  <xsl:function name="cybox:calculateAllColumns">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:choose>
      <xsl:when test="$actualItem[self::*:Observable]">
        <xsl:sequence select="cybox:calculateAllColumnsObservable($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Indicator]">
        <xsl:sequence select="cybox:calculateAllColumnsIndicator($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:TTP]">
        <xsl:sequence select="cybox:calculateAllColumnsTTP($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Exploit_Target]">
        <xsl:sequence select="cybox:calculateAllColumnsExploitTarget($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Incident]">
        <xsl:sequence select="cybox:calculateAllColumnsIncident($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Course_Of_Action]">
        <xsl:sequence select="cybox:calculateAllColumnsCourseOfAction($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Campaign]">
        <xsl:sequence select="cybox:calculateAllColumnsCampaign($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Threat_Actor]">
        <xsl:sequence select="cybox:calculateAllColumnsThreatActor($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::*:Object|self::*:Associated_Object|self::*:Related_Object]">
        <xsl:sequence select="cybox:calculateAllColumnsObject($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::cybox:Event]">
        <xsl:sequence select="cybox:calculateAllColumnsEvent($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::cybox:Action]">
        <xsl:sequence select="cybox:calculateAllColumnsAction($actualItem, $reference)" />
      </xsl:when>
      <xsl:when test="$actualItem[self::stixCommon:Kill_Chain|self::stixCommon:Kill_Chain_Phase]">
        <xsl:sequence select="cybox:calculateAllColumnsKillChainOrKillChainPhase($actualItem, $reference)" />
      </xsl:when>
      <xsl:otherwise>
        <xsl:sequence select="cybox:calculateAllColumnsOtherItems($actualItem, $reference)" />
      </xsl:otherwise>
    </xsl:choose>
    
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsOtherItems">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/(*:Title|*:Name)) then (($actualItem/(*:Title|*:Name))[1]) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:if test="$actualItem/*:Type">
        <xsl:value-of select="$actualItem/*:Type" />
      </xsl:if>
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
    
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsObservable">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/cybox:Title) then ($actualItem/cybox:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:choose>
        <xsl:when test="$actualItem/cybox:Observable_Composition">
          Composition
        </xsl:when>
        <xsl:when test="$actualItem/cybox:Event">
          Event
        </xsl:when>
        <xsl:when test="$actualItem/cybox:Object">
          <xsl:variable name="object" select="$reference/*[@id=$actualItem/cybox:Object/@idref]" />
          <xsl:variable name="objectThreeFields" select="cybox:calculateAllColumnsObject($object, $reference)" />
          <xsl:variable name="objectType" select="$objectThreeFields[1]" />
          
          Object<xsl:if test="$objectType">/<xsl:value-of select="$objectType" /></xsl:if>
          <!--
          <xsl:variable name="objectItem" select="if ((not($reference instance of element()*)) or (not($actualItem instance of element()*))) then () else  $reference/*[@id = fn:data($actualItem/cybox:Object/@idref)]" />
          
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
          -->
        </xsl:when>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsObject">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:choose>
        <xsl:when test="not($actualItem/cybox:Properties/@xsi:type)">[no type]</xsl:when>
        <xsl:otherwise>
          <xsl:variable name="localName" select="fn:local-name-from-QName(fn:resolve-QName($actualItem/cybox:Properties/@xsi:type, $actualItem/cybox:Properties))" />
          <xsl:variable name="humanReadableName" select="stix:convertObjectTypeNameToLabel($localName)" />
          <xsl:value-of select="$humanReadableName" />
        </xsl:otherwise>
      </xsl:choose>
      
    </xsl:variable>
    <xsl:variable name="column2" />
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsEvent">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/cybox:Type) then ($actualItem/cybox:Type/text()) else '[untyped event]'" />
    </xsl:variable>
    <xsl:variable name="column2" />
    
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsAction">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/cybox:Name) then ($actualItem/cybox:Name/text()) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:value-of select="if ($actualItem/cybox:Type) then ($actualItem/cybox:Type/text()) else '[no type]'" />
    </xsl:variable>
    
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsIndicator">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/indicator:Title) then ($actualItem/indicator:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:if test="$actualItem/indicator:Type">
        <xsl:value-of select="$actualItem/indicator:Type" />
      </xsl:if>
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsTTP">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/ttp:Title) then ($actualItem/ttp:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:if test="$actualItem/ttp:Intended_Effect/stixCommon:Value">
        <xsl:value-of select="$actualItem/ttp:Intended_Effect/stixCommon:Value" />
      </xsl:if>
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsExploitTarget">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/et:Title) then ($actualItem/et:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsIncident">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/incident:Title) then ($actualItem/incident:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsCourseOfAction">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/coa:Title) then ($actualItem/coa:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:if test="$actualItem/coa:Type">
        <xsl:value-of select="$actualItem/coa:Type" />
      </xsl:if>
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsCampaign">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/campaign:Title) then ($actualItem/campaign:Title) else if ($actualItem/campaign:Names/campaign:Name) then fn:string-join($actualItem/campaign:Names/campaign:Name, '; ') else '[no title or name]'" />
      
    </xsl:variable>
    <xsl:variable name="column2">
      <xsl:if test="$actualItem/campaign:Intended_Effect/stixCommon:Value">
        <xsl:value-of select="$actualItem/campaign:Intended_Effect/stixCommon:Value" />
      </xsl:if>
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsThreatActor">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/ta:Title) then ($actualItem/ta:Title) else '[no title]'" />
    </xsl:variable>
    <xsl:variable name="column2">
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
  <xsl:function name="cybox:calculateAllColumnsKillChainOrKillChainPhase">
    <xsl:param name="actualItem" />
    <xsl:param name="reference" />
    
    <xsl:variable name="column1">
      <xsl:value-of select="if ($actualItem/@name) then (fn:data($actualItem/@name)) else '[no name]'" />
    </xsl:variable>
    <xsl:variable name="column2">
    </xsl:variable>
    <xsl:variable name="column3">
      <xsl:value-of select="fn:data($actualItem/@id)" />
    </xsl:variable>
    
    <xsl:sequence select="$column1,$column2,$column3" />
  </xsl:function>
  
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
    function to convert cybox object type names (xml schema names) into human readable names.
     * remove the namespace prefix if it's there
     * remove "ObjectType" from the end of the string if it's there
     * convert the non-space-separated string into space separated strings
       based on each new capital letter ("WindowsRegistryKey" would become
       "Windows Registry Key")
  -->
  <xsl:function name="stix:convertObjectTypeNameToLabel">
    <xsl:param name="objectTypeName" as="xs:string" />
    
    <xsl:variable name="short" select="fn:replace($objectTypeName, '^([^:]+:)?(.+?)(ObjectType)?$', '$2')" />
    
    <xsl:variable name="humanReadable" select="fn:normalize-space(fn:replace($short, '[\p{Lu}][^\p{Lu}]+', '$0 '))" />
    
    <xsl:value-of select="$humanReadable" />
  </xsl:function>

  <xsl:function name="stix:convertElementNameToLabel">
    <xsl:param name="elementName" as="xs:string" />
    
    <xsl:variable name="humanReadable" select="fn:normalize-space(fn:replace($elementName, '_', ' '))" />
    
    <xsl:value-of select="$humanReadable" />
  </xsl:function>
  

</xsl:stylesheet>