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
    
    xmlns:ns_extend="http://ns.adobe.com/Extensibility/1.0/"
    xmlns:ns_ai="http://ns.adobe.com/AdobeIllustrator/10.0/"
    xmlns:ns_graphs="http://ns.adobe.com/Graphs/1.0/"
    xmlns:ns_vars="http://ns.adobe.com/Variables/1.0/"
    xmlns:ns_imrep="http://ns.adobe.com/ImageReplacement/1.0/"
    xmlns:ns_sfw="http://ns.adobe.com/SaveForWeb/1.0/"
    xmlns:ns_custom="http://ns.adobe.com/GenericCustomNamespace/1.0/"
    xmlns:ns_adobe_xpath="http://ns.adobe.com/XPath/1.0/">
  
    <xsl:param name="iconReferenceStyleVariable" select="''" />
    <xsl:param name="iconExternalImageBaseUriVariable" select="''" />

    <xsl:function name="stix:generateIconGeneric">
    
      <xsl:param name="class" as="xs:string" />
      <xsl:param name="baseFilename" as="xs:string" />
     
      <div>
        <xsl:attribute name="class" select="string-join(('itemCategoryIcon', $class), ' ')" />
        
        <!--
          iconReferenceStyle:
          * inlineLiteralXml
          * dataUri
          * relativeUri 
        -->
        <xsl:choose>
          <xsl:when test="$iconReferenceStyleVariable = 'inlineLiteralXml'">
            <xsl:copy-of select="doc(concat('images/', $baseFilename, '.svg'))" />
          </xsl:when>
          
          <xsl:when test="$iconReferenceStyleVariable = 'dataUri'">
            <xsl:variable name="base64Data" select="unparsed-text(concat('images/', $baseFilename, '.svg.base64'))" />
            <img><xsl:attribute name="src" select="concat('data:image/svg+xml;base64,', $base64Data)" /></img>
          </xsl:when>
            
          <xsl:when test="$iconReferenceStyleVariable = 'relativeUri'">
            <img><xsl:attribute name="src" select="concat($iconExternalImageBaseUriVariable, '/', $baseFilename, '.svg')" /></img>
          </xsl:when>
          
          <xsl:otherwise>(icon reference style parameter set to invalid option</xsl:otherwise>
        </xsl:choose>
        
      </div>
    </xsl:function>
    
    <xsl:template name="iconCampaigns">
      <xsl:copy-of select="stix:generateIconGeneric('iconCampaigns', 'campaign')" />
    </xsl:template>
    
    <xsl:template name="iconCOAs">
      <xsl:copy-of select="stix:generateIconGeneric('iconCoa', 'course_of_action')" />
    </xsl:template>

    <xsl:template name="iconDataMarkings">
      <xsl:copy-of select="stix:generateIconGeneric('iconDataMarkings', 'data_marking')" />
    </xsl:template>
  
    <xsl:template name="iconExploitTargets">
      <xsl:copy-of select="stix:generateIconGeneric('iconExploitTargets', 'exploit_target')" />
    </xsl:template>
  
    <xsl:template name="iconIncidents">
      <xsl:copy-of select="stix:generateIconGeneric('iconIncidents', 'incident')" />
    </xsl:template>
  
    <xsl:template name="iconIndicators">
      <xsl:copy-of select="stix:generateIconGeneric('iconIndicators', 'indicator')" />
    </xsl:template>
  
    <xsl:template name="iconObservables">
      <xsl:copy-of select="stix:generateIconGeneric('iconObservables', 'observable')" />
    </xsl:template>
  
    <xsl:template name="iconThreatActors">
      <xsl:copy-of select="stix:generateIconGeneric('iconThreatActors', 'threat_actor')" />
    </xsl:template>
  
    <xsl:template name="iconTTPs">
      <xsl:copy-of select="stix:generateIconGeneric('iconTTPs', 'ttp')" />
    </xsl:template>
  
</xsl:stylesheet>