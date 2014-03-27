<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  exclude-result-prefixes="xs"
  version="2.0">
  <xsl:import href="stix_to_html.xsl" />
  
  <xsl:template name="customHeader">
    <div class="customHeader">
      For Limited Release
    </div>
  </xsl:template>
  
  <xsl:template name="customTitle">
    <div class="customTitle">
      <h1>STIX report produced by ACME GmbH</h1>
    </div>
  </xsl:template>

  <xsl:template name="customFooter">
    <div class="customFooter">
      &#xA9; ACME GmbH
    </div>
  </xsl:template>
  
  <!--
    if your company wants to customize the css styling, override this template
    
    the easiest thing to do is to reference an external stylesheet to be included:
    
      <style type="text/css">
        <xsl:value-of select="unparsed-text('custom.css')" />
      </style>
      
    OR
    
    use inline styles:
    
    <style type="text/css">
    .customHeader { color: red; }
    .customFooter { color: blue; }
    </style>
    
  -->
  <xsl:template name="customCss">
    <style type="text/css">
      <![CDATA[
      .customHeader { color: red; }
      .customFooter { color: blue; }
      ]]>
    </style>
  </xsl:template>
  
</xsl:stylesheet>