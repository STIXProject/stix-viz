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

    <xsl:template name="iconCampaigns">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/campaign.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconCOAs">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/course_of_action.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconDataMarkings">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/data_marking.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconExploitTargets">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/exploit_target.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconIncidents">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/incident.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconIndicators">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/indicator.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconObservables">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/observable.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconThreatActors">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/threat_actor.svg')" />
      </div>
    </xsl:template>
    <xsl:template name="iconTTPs">
      <div class="itemCategoryIcon">
        <xsl:copy-of select="doc('images/ttp.svg')" />
      </div>
    </xsl:template>
</xsl:stylesheet>