<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:fn="http://www.w3.org/2005/xpath-functions"
  

  xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:Common="http://cybox.mitre.org/common-2"
  xmlns:stix="http://stix.mitre.org/stix-1"
  xmlns:stixCommon="http://stix.mitre.org/common-1"
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  
  exclude-result-prefixes="cybox Common xsi fn xs stix stixCommon indicator"
  
  version="2.0">
  
  <!--
    ····························································
  -->
  
  <!--
    sample template for displaying sightings and sighting elements
  -->
  <xsl:template match="indicator:Sightings">
    <div class="sightings">
    
      <div>
      <xsl:apply-templates select="indicator:Sighting" />
    </div>
    </div>
  </xsl:template>
  
  <xsl:template match="indicator:Sighting">
    <div class="sighting">
      <div>
        <!-- SIGHTING <xsl:value-of select="position()" /> of <xsl:value-of select="count(../indicator:Sighting)" /> -->
      </div>
      <div>
        <xsl:value-of select="fn:data(@timestamp)" />
      </div>
    </div>
  </xsl:template>
  
  <!--
  ····························································
  -->
  
  <!--
    purpose: template for displaying descriptions from any namespace.  very
    simple, but useful for adding a css class so that they can be styled
    across any content type.
    
    hint: this is used to enable the option to turn on css styles to preserve
    line breaks for preformatted description that show up in some documents.
  -->
  <xsl:template match="*:Description">
    <div class="description">
      <xsl:apply-templates select="text()" />
    </div>
  </xsl:template>
  
  <!--
    purpose: make stixCommon:Reference elements into clickable links in the
    html output.
  -->
  <xsl:template match="stixCommon:Reference" mode="cyboxProperties">
    <xsl:variable name="url" select="fn:data(.)" />
    
    <div class="stixCommonReference">
      <xsl:element name="a">
        <xsl:attribute name="href" select="$url" />
        <xsl:value-of select="$url" />
      </xsl:element>
    </div>
  </xsl:template>
  
  <!--
  ····························································
  -->
  
  <!--
    purpose: placeholder for future template to support maec objects
    
    example:
    <ttp:Malware_Instance xsi:type="maecInstance:MAEC4.0InstanceType" />
  -->
  <xsl:template match="*[some $ns in ('http://stix.mitre.org/extensions/Malware#MAEC4.0-1', 'http://stix.mitre.org/extensions/Malware#MAEC4.1-1') satisfies $ns = fn:namespace-uri-from-QName(fn:resolve-QName(fn:data(@xsi:type), .))]" mode="cyboxProperties">
    PLACEHOLDER -- STIX-TO-HTML WILL SUPPORT MAEC CONTENT IN THE NEXT RELEASE.
  </xsl:template>
  
  <!--
  <xsl:template match="*:Type[count(../*:Type) ge 2]" mode="cyboxProperties">
    <xsl:apply-templates mode="#current" /> <xsl:text> %% </xsl:text>
  </xsl:template>
  -->
  
    
</xsl:stylesheet>