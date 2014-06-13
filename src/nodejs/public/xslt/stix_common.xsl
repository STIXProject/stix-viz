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
    xmlns:terms="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1"

    xmlns:ttp='http://stix.mitre.org/TTP-1'
    >
    
    <xsl:output method="html" omit-xml-declaration="yes" indent="yes" media-type="text/html" version="4.0" />
  
    <!-- this depends on some of the templates in the cybox-to-html transform -->
    <xsl:include href="cybox_common.xsl"/>
    <xsl:include href="stix_objects.xsl" />
    <xsl:include href="stix_objects__customized.xsl" />

    <!--
      Print the "stix header" table (this shows up in the output below the
      metadata table).
    -->
    <xsl:template name="processHeader">
        <xsl:for-each select="//stix:STIX_Package/stix:STIX_Header">        
            <div class="stixHeader">
              <table class="grid topLevelCategory tablesorter" cellspacing="0">
                    <colgroup>
                      <col class="stixHeaderColumnHeadings" />
                      <col class="stixHeaderColumnValues" />
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
                            <xsl:apply-templates select="."/>
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
  
  <xsl:template match="stix:Handling|indicator:Handling">
    <xsl:if test="marking:Marking">
      <div class="cyboxPropertiesConstraints">WARNING: Handling of marking data is not fully supported in stix-to-html yet.</div>
    </xsl:if>
    <xsl:apply-templates />
  </xsl:template>
  
  <xsl:template match="marking:Marking">
    <div class="marking">
      <!-- TODO display marking's control structure or apply to xml -->
      <xsl:if test="marking:Controlled_Structure">
        <div class="markingControlStructure cyboxPropertiesConstraints">
          <xsl:choose>
            <xsl:when test="marking:Controlled_Structure/text() = '//node()'">
              marking for whole document:
            </xsl:when>
            <xsl:when test="not(marking:Controlled_Structure/text()) or (fn:normalize-space(marking:Controlled_Structure/text()) = '')">
              no marking control structure specified:
            </xsl:when>
            <xsl:otherwise>
              marking for (xpath): <xsl:value-of select="marking:Controlled_Structure" />
            </xsl:otherwise>
          </xsl:choose>
        </div>
      </xsl:if>
      <xsl:if test="marking:Marking_Structure[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1', 'SimpleMarkingStructureType')]">
        <div class="markingSimple">
          <xsl:value-of select="marking:Marking_Structure/simpleMarking:Statement/text()"/>
        </div>
      </xsl:if>
      <xsl:if test="marking:Marking_Structure[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1', 'TLPMarkingStructureType')]">
        <div class="markingTlp">
          <xsl:if test="lower-case(marking:Marking_Structure/@color)='red'"><xsl:attribute name="class" select="'tlpred'"/></xsl:if>
          <xsl:if test="lower-case(marking:Marking_Structure/@color)='amber'"><xsl:attribute name="class" select="'tlpamber'"/></xsl:if>
          <xsl:if test="lower-case(marking:Marking_Structure/@color)='green'"><xsl:attribute name="class" select="'tlpgreen'"/></xsl:if>
          <xsl:if test="lower-case(marking:Marking_Structure/@color)='white'"><xsl:attribute name="class" select="'tlpwhite'"/></xsl:if>
          Traffic Light Protocol (TLP): <xsl:value-of select="marking:Marking_Structure/@color"/>
        </div>
      </xsl:if>
      <xsl:if test="marking:Marking_Structure[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1', 'TermsOfUseMarkingStructureType')]">
        <div class="markingTermsOfUse">
          <xsl:value-of select="marking:Marking_Structure/terms:Terms_Of_Use/text()"/>
        </div>
      </xsl:if>
    </div>
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
      
      <xsl:if test="campaign:Names">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Names" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Names', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Status">
        <xsl:copy-of select="stix:printNameValueTable('Status', campaign:Status)" />
      </xsl:if>              
      <xsl:if test="campaign:Intended_Effect">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Intended_Effect" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Intended Effect', $contents)" />
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
      <xsl:if test="campaign:Attribution/*">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Attribution" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Attribution', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Associated_Campaigns">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Associated_Campaigns" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Associated Campaigns', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Confidence">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Confidence" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Confidence', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Activity">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Activity" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Activity', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Information_Source">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Information_Source" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Information Source', $contents)" />
      </xsl:if>
      <xsl:if test="campaign:Handling">
        <xsl:variable name="contents">
          <xsl:apply-templates select="campaign:Handling" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
      </xsl:if>
    </div>
  </xsl:template>

  <xsl:template match="stixCommon:Relationship">
    <div>Relationship: <xsl:apply-templates /></div>
  </xsl:template>
  
  <xsl:template match="cybox:Related_Object/cybox:Relationship">
    <div>Relationship: <xsl:apply-templates /></div>
  </xsl:template>
  
  <xsl:template match="*:Intended_Effect">
    <div class="stixCommonValue">
      <xsl:apply-templates select="stixCommon:Value" />
    </div>
    <div class="stixCommonDescription">
      <xsl:apply-templates select="stixCommon:Description" />
    </div>
  </xsl:template>
  
  <xsl:template match="campaign:Attribution">
    <xsl:variable name="threatActorCount" select="count(campaign:Attributed_Threat_Actor/stixCommon:Threat_Actor)" />
    <xsl:if test="$threatActorCount gt 0">
      <div class="stixSectionTitle">Attributed Threat Actor<xsl:if test="$threatActorCount ge 2">s</xsl:if></div>
    </xsl:if>
    <xsl:apply-templates select="campaign:Attributed_Threat_Actor/stixCommon:Threat_Actor"/>
  </xsl:template>
  
  <xsl:template match="campaign:Associated_Campaigns">
    <xsl:variable name="associatedCampaignCount" select="count(campaign:Associated_Campaign/stixCommon:Campaign)" />
    <xsl:if test="$associatedCampaignCount gt 0">
      <div class="stixSectionTitle">Associated Campaign<xsl:if test="$associatedCampaignCount ge 2">s</xsl:if></div>
    </xsl:if>
    <xsl:apply-templates select="campaign:Associated_Campaign/stixCommon:Campaign"/>
  </xsl:template>
  
  <xsl:template match="stixCommon:Threat_Actor[@idref]|stixCommon:Campaign[@idref]|marking:Marking[@idref]">
    <div class="">
      <xsl:variable name="targetId" select="string(@idref)"/>
      <xsl:variable name="relationshipOrAssociationType" select="''" />
      
      <!-- (indicator within composition - - idref: <xsl:value-of select="fn:data(@idref)"/>) -->
      <xsl:call-template name="headerAndExpandableContent">
        <xsl:with-param name="targetId" select="$targetId"/>
        <xsl:with-param name="isComposition" select="fn:false()"/>
        <xsl:with-param name="relationshipOrAssociationType" select="''" />
      </xsl:call-template>
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
      
      <xsl:if test="incident:Time">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Time/*" mode="cyboxProperties" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Time', $contents)" />
      </xsl:if>
      <xsl:if test="incident:External_ID">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:External_ID" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('External ID', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Description">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Description" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Description', $contents)" />
      </xsl:if>              
      <xsl:if test="incident:Categories/incident:Category">
        <xsl:variable name="label" select="if (count(incident:Categories/incident:Category) ge 2) then ('Categories') else ('Category')" />
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Categories/incident:Category" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable($label, $contents)" />
      </xsl:if>
      <xsl:if test="incident:Reporter">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Reporter" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Reporter', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Responder">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Responder" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Responder', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Coordinator">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Coordinator" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Coordinator', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Victim">
        <xsl:variable name="label" select="if (count(incident:Victim) ge 2) then ('Victims') else ('Victim')" />
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Victim" mode="cyboxProperties" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable($label, $contents)" />
      </xsl:if>

      <xsl:if test="incident:Affected_Assets">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Affected_Assets" mode="cyboxProperties" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Affected Assets', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Impact_Assessment">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Impact_Assessment" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Impact Assessment', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Status">
        <xsl:copy-of select="stix:printNameValueTable('Status', incident:Status)" />
      </xsl:if>              
      
      <xsl:if test="incident:Related_Indicators/*">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Related_Indicators/*" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related Indicators', $contents)" />
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
        <xsl:copy-of select="stix:printNameValueTable('Leveraged TTPs', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Attributed_Threat_Actors/incident:Threat_Actor">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Attributed_Threat_Actors/incident:Threat_Actor" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Attributed Threat Actors', $contents)" />
      </xsl:if>
      
      <xsl:if test="incident:Intended_Effect">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Intended_Effect" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Intended Effect', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Security_Compromise">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Security_Compromise" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Security Compromise', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Discovery_Method">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Discovery_Method" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Discovery Method', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Related_Incidents/*">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Related_Incidents" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related Incidents', $contents)" />
      </xsl:if>
      <xsl:if test="incident:COA_Requested">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:COA_Requested" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('COA Requested', $contents)" />
      </xsl:if>
      <xsl:if test="incident:COA_Taken">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:COA_Taken" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('COA Taken', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Confidence">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Confidence" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Confidence', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Contact">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Contact" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Contact', $contents)" />
      </xsl:if>
      <xsl:if test="incident:History">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:History" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('History', $contents)" />
      </xsl:if>
      <xsl:if test="incident:Handling">
        <xsl:variable name="contents">
          <xsl:apply-templates select="incident:Handling" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
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
      <xsl:if test="ta:Intended_Effect">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Intended_Effect" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Intended Effect', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Planning_And_Operational_Support">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Planning_And_Operational_Support" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Planning And Operational Support', $contents)" />
      </xsl:if>
      
      <xsl:if test="ta:Observed_TTPs/ta:Observed_TTP">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Observed_TTPs/ta:Observed_TTP" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Observed TTPs', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Associated_Campaigns/ta:Associated_Campaign">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Associated_Campaigns/ta:Associated_Campaign" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Associated Campaigns', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Associated_Actors/ta:Associated_Actor/stixCommon:Threat_Actor">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Associated_Actors/ta:Associated_Actor/stixCommon:Threat_Actor" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Associated Actors', $contents)" />
      </xsl:if>

      <xsl:if test="ta:Handling">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Handling" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Confidence">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Confidence" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Confidence', $contents)" />
      </xsl:if>
      <xsl:if test="ta:Information_Source">
        <xsl:variable name="contents">
          <xsl:apply-templates select="ta:Information_Source" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Information Source', $contents)" />
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
      
      <xsl:if test="et:Vulnerability">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Vulnerability" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Vulnerabilities', $contents)" />
      </xsl:if>
      <xsl:if test="et:Weakness">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Weakness" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Weakness', $contents)" />
      </xsl:if>
      <xsl:if test="et:Configuration">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Configuration" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Configuration', $contents)" />
      </xsl:if>
      <xsl:if test="et:Potential_COAs">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Potential_COAs" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Potential COAs', $contents)" />
      </xsl:if>
      <xsl:if test="et:Information_Source">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Information_Source" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Information Source', $contents)" />
      </xsl:if>
      <xsl:if test="et:Handling">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Handling" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
      </xsl:if>
      <xsl:if test="et:Related_Exploit_Targets">
        <xsl:variable name="contents">
          <xsl:apply-templates select="et:Related_Exploit_Targets" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Related Expooit Targets', $contents)" />
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
        
        <xsl:if test="indicator:Description">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Description" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Description', $contents)" />
        </xsl:if>              
        <xsl:if test="indicator:Valid_Time_Position">
          <xsl:copy-of select="stix:printNameValueTable('Valid Time Position', fn:concat('(', indicator:Valid_Time_Position/indicator:Start_Time/text(), ' to ', indicator:Valid_Time_Position/indicator:End_Time/text(), ')'))" />
        </xsl:if>
        
        <xsl:if test="indicator:Alternative_ID">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Alternative_ID" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Alternative ID', $contents)" />
        </xsl:if>
        
        <xsl:if test="indicator:Observable">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Observable/@*" mode="cyboxProperties" />
            <xsl:apply-templates select="indicator:Observable/*" mode="cyboxProperties" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Observable', $contents)" />
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
      <xsl:if test="indicator:Sightings/indicator:Sighting">
        <xsl:variable name="contents">
          <xsl:apply-templates select="indicator:Sightings" />
        </xsl:variable>
        <xsl:copy-of select="stix:printNameValueTable('Sightings', $contents)" />
      </xsl:if> 

        <xsl:if test="indicator:Test_Mechanisms">
          <xsl:variable name="contents">
            <xsl:apply-templates select="Test_Mechanisms" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Test Mechanisms', $contents)" />
        </xsl:if> 
        <xsl:if test="indicator:Likely_Impact">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Likely_Impact" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Likely Impact', $contents)" />
        </xsl:if> 
        <xsl:if test="indicator:Suggested_COAs">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Suggested_COAs" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Suggested COAs', $contents)" />
        </xsl:if> 
        <xsl:if test="indicator:Handling">
          <xsl:variable name="contents">
            <div>name: <xsl:value-of select="local-name(.)"/></div>
            <xsl:apply-templates select="indicator:Handling" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
        </xsl:if> 
        <xsl:if test="indicator:Related_Indicators">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Related_Indicators" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Related Indicators', $contents)" />
        </xsl:if>
        <xsl:if test="indicator:Related_Campaigns">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Related_Campaigns" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Related Campaigns', $contents)" />
        </xsl:if>
        <xsl:if test="indicator:Producer">
          <xsl:variable name="contents">
            <xsl:apply-templates select="indicator:Producer" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Producer', $contents)" />
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

          <xsl:if test="ttp:Behavior">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Behavior/*" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Behavior', $contents)" />
          </xsl:if>
          
          <xsl:if test="ttp:Resources">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Resources/*" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Resources', $contents)" />
          </xsl:if>  
          
          <xsl:if test="ttp:Victim_Targeting">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Victim_Targeting/*" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Victim Targeting', $contents)" />
          </xsl:if>  
          
          <xsl:if test="ttp:Exploit_Targets">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Exploit_Targets" />
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
          
          <xsl:if test="ttp:Information_Source">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Information_Source/*" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Information Source', $contents)" />
          </xsl:if>  

          <xsl:if test="ttp:Handling">
            <xsl:variable name="contents">
              <xsl:apply-templates select="ttp:Handling/*" mode="cyboxProperties" />
            </xsl:variable>
            <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
          </xsl:if>  
        </div>
      </div>
    </xsl:template>
  
  <xsl:template match="ttp:Exploit_Target">
    <div class="container containerTtpExploitTarget">
      <div><xsl:apply-templates select="stixCommon:Relationship" /></div>
      <div><xsl:apply-templates select="stixCommon:Exploit_Target" /></div>
    </div>
  </xsl:template>
  
  <xsl:template name="processCOAContents">
    <div>
      <div>
        <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
        
        <!-- set empty class for non-composition observables -->
        
        <!-- <span style="color: red; background-color: yellow;">INDICATOR CONTENTS HERE</span> -->
        
        <xsl:if test="COA:Stage">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Stage" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Stage', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Type">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Type" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Type', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Description">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Description" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Description', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Objective">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Objective" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Objective', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Structured_COA">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Structured_COA" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Structured COA', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Impact">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Impact" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Impact', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Cost">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Cost" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Cost', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Efficacy">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Efficacy" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Efficacy', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Handling">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Handling" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Handling', $contents)" />
        </xsl:if>
        <xsl:if test="COA:Related_COAs">
          <xsl:variable name="contents">
            <xsl:apply-templates select="COA:Related_COAs" />
          </xsl:variable>
          <xsl:copy-of select="stix:printNameValueTable('Related COAs', $contents)" />
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

  <!--
    purpose: format incident reported times
    this shows up mostly as incident:Time/incident:Incident_Reported
  -->
  <xsl:template match="incident:Incident_Reported">
    <xsl:variable name="incidentReportedTime" select="text()" />
    <div class="incidentReportedTime">
      reported <xsl:value-of select="$incidentReportedTime" />
    </div>
  </xsl:template>
  
  
  <xsl:template match="incident:Category">
    <xsl:variable name="categoryName" select="text()" />
    
    <div class="incidentCategory">
      <xsl:value-of select="$categoryName" />
    </div>
  </xsl:template>

  <xsl:template match="stixCommon:Name">
    <xsl:variable name="name" select="text()" />
    
    <div class="stixCommonName">
      <xsl:value-of select="$name" />
    </div>
  </xsl:template>
  
  <xsl:template match="incident:Victim">
    <xsl:apply-templates mode="cyboxProperties" />
  </xsl:template>

  <xsl:template match="ta:Identity|stixCommon:Identity">
    <xsl:apply-templates select="." mode="cyboxProperties" />
  </xsl:template>
  
  <xsl:template match="ttp:Attack_Pattern">
    <xsl:apply-templates select="*" mode="cyboxProperties" />
  </xsl:template>
  <xsl:template match="ttp:Attack_Pattern[@id]" mode="cyboxProperties">
    <xsl:apply-templates select="*" mode="cyboxProperties" />
  </xsl:template>
  
</xsl:stylesheet>

