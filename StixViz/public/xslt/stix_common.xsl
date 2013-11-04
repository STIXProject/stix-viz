<?xml version="1.0" encoding="UTF-8"?>
<!--
  Copyright (c) 2013 – The MITRE Corporation
  All rights reserved. See LICENSE.txt for complete terms.
  
  This styleshseet has logic that can be reused by various components in the
  stix-to-html transformation.
 -->

<xsl:stylesheet 
    version="2.0"
    xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:fn="http://www.w3.org/2005/xpath-functions"
    
    xmlns:stixCommon="http://stix.mitre.org/common-1"
    xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:campaign="http://stix.mitre.org/Campaign-1"
    xmlns:incident="http://stix.mitre.org/Incident-1"
    xmlns:ta="http://stix.mitre.org/ThreatActor-1"
    xmlns:et="http://stix.mitre.org/ExploitTarget-1"
    xmlns:TTP="http://stix.mitre.org/TTP-1"
    xmlns:COA="http://stix.mitre.org/CourseOfAction-1"
    xmlns:capec="http://stix.mitre.org/extensions/AP#CAPEC2.5-1"
    xmlns:marking="http://data-marking.mitre.org/Marking-1"
    xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1"
    xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
    xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1"

    xmlns:ttp='http://stix.mitre.org/TTP-1'
    >
    
    <xsl:output method="html" omit-xml-declaration="yes" indent="yes" media-type="text/html" version="4.0" />
  
    <!-- this depends on some of the templates in the cybox-to-html transform -->
    <xsl:include href="cybox_common.xsl"/>

    <!--
      Print the "stix header" table (this shows up in the output below the
      metadata table).
    -->
    <xsl:template name="processHeader">
        <xsl:for-each select="//stix:STIX_Package/stix:STIX_Header">        
            <div class="stixHeader">
              <table class="grid topLevelCategory tablesorter" cellspacing="0">
                    <colgroup>
                        <col width="30%"/>
                        <col width="70%"/>
                    </colgroup>
                    <thead>
<!--
                      <tr>
                            <th class="header"></th>
                            <th class="header"></th>
                      </tr>
-->
                    </thead>
                    <tbody>
                        <xsl:variable name="evenOrOdd" select="if(position() mod 2 = 0) then 'even' else 'odd'" />
                        <xsl:for-each select="child::*">
                            <xsl:call-template name="processStixHeaderNameValue"><xsl:with-param name="evenOrOdd" select="$evenOrOdd"/></xsl:call-template>
                        </xsl:for-each>
                    </tbody>
                </table>    
            </div>
        </xsl:for-each>
    </xsl:template>

    <!--
      Designed for use in the STIX_HEADER, at least.
      
      Does not yet take into consideration Handling/Marking complexity.
      
      For handling, the text value of simpleMarking:Statement is printed.
      
      For information source, the whole element is printed out in
      cyboxProperties mode.
    -->
    <xsl:template name="processStixHeaderNameValue">
        <xsl:param name="evenOrOdd" />
        <tr><xsl:attribute name="class"><xsl:value-of select="$evenOrOdd" /></xsl:attribute>
                <td class="Stix{local-name()}Name">
                  <xsl:value-of select="fn:local-name(.)"/>
                </td>
                <td class="Stix{local-name()}Value">
                    <xsl:variable name="class" select="if (self::stix:Description) then ('longText expandableContainer expandableToggle expandableContents expandableSame collapsed') else ('') " />
                    <div>
                        <xsl:if test="$class">
                            <xsl:attribute name="class" select="$class"/>
                            <xsl:attribute name="onclick">toggle(this);</xsl:attribute>
                        </xsl:if>
                        <!--
                          for now, just show the text of simpleMarking:Statement & TLP
                          
                          <marking:Marking_Structure color="GREEN" xsi:type="tlpMarking:TLPMarkingStructureType"/>
                          
                          TODO: customization toggle whether to show simpleMarking
                        -->
                        <xsl:choose>
                          <xsl:when test="self::stix:Handling">
                            <xsl:variable name="isSimple" select="'simpleMarking:SimpleMarkingStructureType'"/>
                            <xsl:variable name="isTLP" select="'tlpMarking:TLPMarkingStructureType'"/>
                            <xsl:choose>
                              <xsl:when test=".//marking:Marking_Structure/@xsi:type = $isSimple">
                                <xsl:value-of select=".//simpleMarking:Statement/text()"/>
                              </xsl:when>
                              <xsl:when test=".//marking:Marking_Structure/@xsi:type = $isTLP">
                                <xsl:if test="lower-case(.//marking:Marking_Structure/@color)='red'"><xsl:attribute name="class" select="'tlpred'"/></xsl:if>
                                <xsl:if test="lower-case(.//marking:Marking_Structure/@color)='amber'"><xsl:attribute name="class" select="'tlpamber'"/></xsl:if>
                                <xsl:if test="lower-case(.//marking:Marking_Structure/@color)='green'"><xsl:attribute name="class" select="'tlpgreen'"/></xsl:if>
                                <xsl:if test="lower-case(.//marking:Marking_Structure/@color)='white'"><xsl:attribute name="class" select="'tlpwhite'"/></xsl:if>
                                Traffic Light Protocol (TLP): <xsl:value-of select=".//marking:Marking_Structure/@color"/>
                              </xsl:when>
                            </xsl:choose>
                          </xsl:when>
                          <xsl:when test="self::stix:Information_Source">
                            <xsl:apply-templates mode="cyboxProperties" />
                          </xsl:when>
                          
                          <!-- 
                            html content is saved as an escaped attribute
                            "data-stix-content" and will be later parsed and
                            expanded via javascript
                          -->
                          <xsl:when test="self::*[@structuring_format='HTML5']">
                            <xsl:variable name="content" select="./text()" />
                            <div class="htmlContainer" data-stix-content="{$content}" />
                          </xsl:when>
                          <xsl:otherwise>
                            <xsl:value-of select="self::node()[text()]"/>
                          </xsl:otherwise>
                        </xsl:choose>
                        
                    </div>
                </td>
            </tr>
    </xsl:template>    



  <!--
    The process*Contents templates are used to convert the top level catgory "items" into html.
    
    This one processes campaigns.
  -->
  <xsl:template name="processCampaignContents">
    
    <div>
      <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
            
      <!--
      <xsl:attribute name="class">
        <xsl:if test="@id">container baseobj</xsl:if>
      </xsl:attribute>
      -->
      
      <xsl:if test="campaign:Title">
        <xsl:copy-of select="stix:printNameValueTable('Title', campaign:Title)" />
      </xsl:if>              
      <xsl:if test="campaign:Status">
        <xsl:copy-of select="stix:printNameValueTable('Status', campaign:Status)" />
      </xsl:if>              
      <xsl:if test="campaign:Related_Incidents/campaign:Related_Incident">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Related_Incidents/campaign:Related_Incident" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related Incidents', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Related_TTPs/campaign:Related_TTP">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Related_TTPs/campaign:Related_TTP" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related TTPs', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Related_Indicators/campaign:Related_Indicator">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Related_Indicators/campaign:Related_Indicator" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related Indicators', $contents)" />
      </xsl:if>
      
    </div>
  </xsl:template>

  <xsl:template match="campaign:Related_Incident">
    <div>
      <xsl:apply-templates select="stixCommon:Incident" />
    </div>
  </xsl:template>
  
  <xsl:template match="campaign:Related_TTP">
    <div>
      <xsl:apply-templates select="stixCommon:TTP" />
    </div>
  </xsl:template>
  
  <xsl:template match="campaign:Related_Indicator">
    <div>
      <xsl:apply-templates select="stixCommon:Indicator" />
    </div>
  </xsl:template>

  <!--
    The process*Contents templates are used to convert the top level catgory "items" into html.
    
    This one processes incidents.
  -->
  <xsl:template name="processIncidentContents">
    <div>
      <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
      
      <!--
      <xsl:attribute name="class">
        <xsl:if test="@id">container baseobj</xsl:if>
      </xsl:attribute>
      -->
      
      <xsl:if test="incident:Description">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Description" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Description', $contents)" />
      </xsl:if>              
      <xsl:if test="incident:Status">
        <xsl:copy-of select="stix:printNameValueTable('Status', incident:Status)" />
      </xsl:if>              
      <xsl:if test="incident:Related_Observables/incident:Related_Observable">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Related_Observables/incident:Related_Observable" mode="cyboxProperties" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related Observables', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Leveraged_TTPs/incident:Leveraged_TTP">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Leveraged_TTPs/incident:Leveraged_TTP" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related TTPs', $contents)" />
      </xsl:if>
    </div>
  </xsl:template>
  <xsl:template match="cybox:Observable[not(@id) and not(@idref)]|stixCommon:Observable[not(@id) and not(@idref)]">
    <xsl:call-template name="processObservableContents"/>
  </xsl:template>
  
  <xsl:template match="incident:Related_Observable">
    <div>
      <xsl:call-template name="processObservableContents" />
    </div>
  </xsl:template>
  <xsl:template match="incident:Leveraged_TTP">
    <div>
      <xsl:apply-templates select="stixCommon:TTP" />
    </div>
  </xsl:template>

  <!--
    The process*Contents templates are used to convert the top level catgory "items" into html.
    
    This one processes threat actors.
  -->
  <xsl:template name="processThreatActorContents">
    <div>
      <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
      
      <!--
      <xsl:attribute name="class">
        <xsl:if test="@id">container baseobj</xsl:if>
      </xsl:attribute>
      -->
      
      <xsl:if test="ta:Title">
        <xsl:copy-of select="stix:printNameValueTable('Title', ta:Title)" />
      </xsl:if>              
      <xsl:if test="ta:Identity">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Identity" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Identity', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Type">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Type" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Types', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Motivation">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Motivation" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Motivations', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Observed_TTPs/ta:Observed_TTP">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Observed_TTPs/ta:Observed_TTP" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Observed TTPs', $contents)" />
      </xsl:if>
    </div>
  </xsl:template>
  <xsl:template match="ta:Observed_TTP">
    <div>
      <xsl:apply-templates select="stixCommon:TTP" />
    </div>
  </xsl:template>
  
  <!--
    The process*Contents templates are used to convert the top level catgory "items" into html.
    
    This one processes exploit targets.
  -->
  <xsl:template name="processExploitTargetContents">
    <div>
      <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
      
      <!--
      <xsl:attribute name="class">
        <xsl:if test="@id">container baseobj</xsl:if>
      </xsl:attribute>
      -->
      
      <xsl:if test="et:Title">
        <xsl:copy-of select="stix:printNameValueTable('Title', et:Title)" />
      </xsl:if>              
      <xsl:if test="et:Vulnerability">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Vulnerability" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Vulnerabilities', $contents)" />
      </xsl:if>
    </div>
  </xsl:template>
  
  <!--
    The process*Contents templates are used to convert the top level catgory "items" into html.
    
    This one processes indicator.
  -->
  
    <xsl:template name="processIndicatorContents">
      
      <div>
      <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
      
      <!-- set empty class for non-composition observables -->
      
      <!-- <span style="color: red; background-color: yellow;">INDICATOR CONTENTS HERE</span> -->
      
        <!--
        <xsl:attribute name="class">
          <xsl:if test="not(indicator:Composite_Indicator_Expression)">baseindicator </xsl:if>
          <xsl:if test="@id">container baseobj</xsl:if>
        </xsl:attribute>
        -->
        
        <xsl:if test="indicator:Title">
          <xsl:copy-of select="stix:printNameValueTable('Title', indicator:Title)" />
        </xsl:if>              
        <xsl:if test="indicator:Description">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Description" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Description', $contents)" />
        </xsl:if>              
        <xsl:if test="indicator:Valid_Time_Position">
          <xsl:copy-of select="stix:printNameValueTable('Valid Time Position', fn:concat('(', indicator:Valid_Time_Position/indicator:Start_Time/text(), ' to ', indicator:Valid_Time_Position/indicator:End_Time/text(), ')'))" />
        </xsl:if>
        <xsl:if test="indicator:Suggested_COAs/indicator:Suggested_COA">
          <xsl:variable name="coaContents">
            <xsl:apply-templates select="indicator:Suggested_COAs/indicator:Suggested_COA" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Suggested COAs', $coaContents)" />
        </xsl:if>
        <xsl:if test="not(indicator:Composite_Indicator_Expression)">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Observable" mode="cyboxProperties" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Observable', $contents)" />

          <!--
          <xsl:variable name="observableContents">
            <xsl:apply-templates select="indicator:Observable" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Observable', $observableContents)" />
          -->
        </xsl:if>
        <xsl:if test="indicator:Composite_Indicator_Expression">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Composite_Indicator_Expression" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Indicator Composition', $contents)" />
        </xsl:if>
      <xsl:if test="indicator:Indicated_TTP">
        <xsl:variable name="contents">
          <xsl:apply-templates select="indicator:Indicated_TTP" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Indicated TTP', $contents)" />
      </xsl:if>
      <xsl:if test="indicator:Kill_Chain_Phases">
        <xsl:variable name="contents">
          <xsl:apply-templates select="indicator:Kill_Chain_Phases" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Kill Chain Phases', $contents)" />
      </xsl:if> 
      <xsl:if test="indicator:Confidence">
        <xsl:variable name="contents">
          <xsl:apply-templates select="indicator:Confidence" mode="cyboxProperties" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Confidence', $contents)" />
      </xsl:if> 
      </div>
    </xsl:template>
    
    
    <!--
      This template produces the table displaying composite indicator expressions.
      
      This is similar to how the composite observables are produced.
    -->
    <xsl:template match="indicator:Composite_Indicator_Expression">
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
                            <xsl:for-each select="indicator:Indicator">
                                <tr>
                                    <td>
                                        <xsl:apply-templates select="." mode="composition" />
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
      This template display the simple indicator within a composite indicator
      expression (one of the operands).
    -->
    <xsl:template match="indicator:Indicator" mode="composition">
        <xsl:if test="@idref">
            <div class="foreignObservablePointer">
                <xsl:variable name="targetId" select="string(@idref)"/>
                <xsl:variable name="relationshipOrAssociationType" select="''" />
                
                <!-- (indicator within composition - - idref: <xsl:value-of select="fn:data(@idref)"/>) -->
                <xsl:call-template name="headerAndExpandableContent">
                    <xsl:with-param name="targetId" select="$targetId"/>
                    <xsl:with-param name="isComposition" select="fn:true()"/>
                    <xsl:with-param name="relationshipOrAssociationType" select="''" />
                </xsl:call-template>
            </div>
        </xsl:if>
        
        <xsl:for-each select="cybox:Observable_Composition|indicator:Composite_Indicator_Expression">
            <xsl:apply-templates select="." mode="#default" />
        </xsl:for-each>
    </xsl:template>
    
    
    <!--
      This template display an observable contained within an indicator.
    -->
    <xsl:template match="indicator:Observable">
        
        <xsl:choose>
            <xsl:when test="@id">
                <xsl:call-template name="processObservableInline" />
            </xsl:when>
            <xsl:when test="@idref">
                <xsl:call-template name="processObservableInObservableCompositionSimple" />
            </xsl:when>
        </xsl:choose>
    </xsl:template>
  
    <xsl:template match="indicator:Indicated_TTP">
        <div>
        <!-- <div>(indicator Indicated TTP)</div> -->
        <div>
            <xsl:apply-templates/>
        </div>
        </div>
    </xsl:template>
    
    <xsl:template match="indicator:Kill_Chain_Phases">
        <div>
            <!-- <div>Kill Chain Phases</div> -->
            <div>
                <xsl:apply-templates />
            </div>
        </div>
    </xsl:template>

    <!--
      This template makes sure that TTP elements that have neither an id nor
      an idref are printed out inline.
    -->
    <xsl:template match="stixCommon:TTP[not(@id) and not(@idref)]|stix:TTP[not(@id) and not(@idref)]">
      <xsl:call-template name="processTTPContents" />
    </xsl:template>
  
    
    <!--
      The process*Contents templates are used to convert the top level catgory "items" into html.
      
      This one processes TTPs.
    -->
    <xsl:template name="processTTPContents">
      <div>
        <div>
          <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
          
          <!-- set empty class for non-composition observables -->
          
          <!-- <span style="color: red; background-color: yellow;">INDICATOR CONTENTS HERE</span> -->
          
          <!--
          <xsl:attribute name="class">
            <!- - <xsl:if test="not(indicator:Composite_Indicator_Expression)">baseindicator </xsl:if> - ->
            <xsl:if test="@id">container baseobj</xsl:if>
          </xsl:attribute>
          -->
          <xsl:if test="ttp:Description">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Description" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Description', $contents)" />
          </xsl:if>  

          <xsl:if test="ttp:Intended_Effect">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Intended_Effect" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Intended Effect', $contents)" />
          </xsl:if>  
          
          <xsl:if test="ttp:Behavior">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Behavior" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Behavior', $contents)" />
          </xsl:if>
          
          <xsl:if test="ttp:Resources">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Resources" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Resources', $contents)" />
          </xsl:if>  
          
          <xsl:if test="ttp:Victim_Targeting">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Victim_Targeting" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Victim Targeting', $contents)" />
          </xsl:if>  
          
          <xsl:if test="ttp:Exploit_Targets">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Exploit_Targets" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Exploit Targets', $contents)" />
          </xsl:if>  
          
          <xsl:if test="ttp:Related_TTPs/ttp:Related_TTP">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Related_TTPs/ttp:Related_TTP" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Related TTPs', $contents)" />
          </xsl:if> 
          <xsl:if test="ttp:Kill_Chain_Phases/stixCommon:Kill_Chain_Phase">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Kill_Chain_Phases" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Kill Chain Phases', $contents)" />
          </xsl:if> 
          
        </div>
      </div>
    </xsl:template>
    
  <!--
    Print out the root kill chain and its child kill chain phases.
    
    At least within TTPs, this will be for the kill chains mentioned in
    stix:TTPs/stix:Kill_Chains
  -->
  <xsl:template match="stixCommon:Kill_Chain[@id]" priority="30.0">
    <xsl:variable name="localName" select="local-name()"/>
    <xsl:variable name="identifierName" select="'killChain'" />
    <xsl:variable name="friendlyName" select="fn:replace($localName, '_', ' ')" />
    <xsl:variable name="headingName" select="fn:upper-case($friendlyName)" />
    
    <div class="container {$identifierName}Container {$identifierName}">
      <div class="contents {$identifierName}Contents {$identifierName}">
        <!-- Print the description if one is available (often they are not) -->
        
        <xsl:call-template name="printNameValue">
          <xsl:with-param name="identifier" select="$identifierName" />
          <xsl:with-param name="label" select="'Name'" as="xs:string?" />
          <xsl:with-param name="value" select="@name" as="xs:string?" />
        </xsl:call-template>
        
        <xsl:call-template name="printNameValue">
          <xsl:with-param name="identifier" select="$identifierName" />
          <xsl:with-param name="label" select="'Definer'" as="xs:string?" />
          <xsl:with-param name="value" select="@definer" as="xs:string?" />
        </xsl:call-template>
        
        <xsl:call-template name="printNameValue">
          <xsl:with-param name="identifier" select="$identifierName" />
          <xsl:with-param name="label" select="'Reference'" as="xs:string?" />
          <xsl:with-param name="value" select="@reference" as="xs:string?" />
        </xsl:call-template>
        
        <xsl:if test="stixCommon:Kill_Chain_Phase">
          <xsl:apply-templates select="stixCommon:Kill_Chain_Phase" />
        </xsl:if>
      </div>
    </div>
  </xsl:template>
  
  
  <!--
    Print out the root kill chain and its child kill chain phases.
    
    At least within TTPs, this will be for the kill chains mentioned in
    stix:TTPs/stix:Kill_Chains/stixCommon:Kill_Chain_Phase.  The normalization
    process changes those @phase_id attributes to @id attributes.
    
    In TTPs, there will also be kill chain phases at
    stix:TTP/ttp:Kill_Chain_Phases.  The normalization process changes
    @phase_id attributes to @idref.
  -->
  <xsl:template match="stixCommon:Kill_Chain_Phase[@id]">
    <div class="debug">DEBUG kill chain phase w/ id</div>
    <div class="container killChainPhase">
      <div class="heading killChainPhase">
        Kill Chain Phase
      </div>
      <div class="contents killChainPhase killChainPhaseContents">
        <div class="contentsCurrent">
          <xsl:call-template name="printNameValue">
            <xsl:with-param name="identifier" select="'name'" />
            <xsl:with-param name="label" select="'Name'" as="xs:string?" />
            <xsl:with-param name="value" select="@name" as="xs:string?" />
          </xsl:call-template>
          
          <xsl:call-template name="printNameValue">
            <xsl:with-param name="identifier" select="'ordinality'" />
            <xsl:with-param name="label" select="'Ordinality'" as="xs:string?" />
            <xsl:with-param name="value" select="@ordinality" as="xs:string?" />
          </xsl:call-template>
          
          
        </div>
        <div class="contentsChildren">
          <xsl:apply-templates />
        </div>
      </div> <!-- end of div contents -->
    </div> <!-- end of div container -->
  </xsl:template>
  
  <!--
    Display related TTP by showing the relationship and the underlying TTP.
  -->
  <xsl:template match="ttp:Related_TTP">
    <div>
      Related TTP Relationship: <xsl:value-of select="stixCommon:Relationship/text()" />
    </div>
    <div>
      <xsl:apply-templates select="stixCommon:TTP" />
    </div>
  </xsl:template>
  
  <!--
    Template to turn any items with an idref into an expandable content toggle.
    
    IMPORTANT: Add elements to the match clause here to expand this functionality to other elements.
    
    See also the similar template in cybox_common.xsl.
  -->
  <xsl:template match="stixCommon:Kill_Chain_Phase[@idref]|stixCommon:TTP[@idref]|stixCommon:Incident[@idref]|stixCommon:Indicator[@idref]">
    <div class="debug">DEBUG kill chain phase w/ idref</div>
    <!-- [object link here - - <xsl:value-of select="fn:data(@idref)" />] -->
    
    <xsl:call-template name="headerAndExpandableContent">
      <xsl:with-param name="targetId" select="fn:data(@idref)" />
      <xsl:with-param name="relationshipOrAssociationType" select="()" />
    </xsl:call-template>
  </xsl:template>

  <!--
    Simple template to print a name/value pair in simple html.
    
    Also looks to see if the value starts with http://, https://, or ftp://
    and if so, turns it into a <a href="url">text</a> link.
  -->
  <xsl:template name="printNameValue" >
    <xsl:param name="identifier" select="''" as="xs:string?" />
    <xsl:param name="label" select="''" as="xs:string?" />
    <xsl:param name="value" select="''" as="xs:string?" />
    
    <xsl:if test="@name">
      <div class="{$identifier}KeyValue keyValue">
        <span class="key"><xsl:value-of select="$label"/>:</span>
        <xsl:text> </xsl:text>
        <span class="key">
          <xsl:choose>
            <xsl:when test="fn:starts-with($value, 'http://') or fn:starts-with($value, 'https://') or fn:starts-with($value, 'ftp://')">
              <a href="{$value}"><xsl:value-of select="$value"/></a>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="$value"/>
            </xsl:otherwise>
          </xsl:choose>
        </span>
      </div>
    </xsl:if>
  </xsl:template>  
  
  <xsl:template match="indicator:Suggested_COA">
    <xsl:apply-templates />
  </xsl:template>
</xsl:stylesheet>
