<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:fn="http://www.w3.org/2005/xpath-functions"
  

  xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:Common="http://cybox.mitre.org/common-2"
  xmlns:stixCommon="http://stix.mitre.org/common-1"

  xmlns:AddressObject='http://cybox.mitre.org/objects#AddressObject-2'
  xmlns:URIObject='http://cybox.mitre.org/objects#URIObject-2'
  xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
  xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
  xmlns:registry='http://cybox.mitre.org/objects#WinRegistryKeyObject-2'
  
  xmlns:http='http://cybox.mitre.org/objects#HTTPSessionObject-2'
  
  exclude-result-prefixes="cybox Common xsi fn EmailMessageObj AddressObject URIObject xs registry"
  
  version="2.0">
  
  <!-- EXAMPLE TEMPLATE FOR EMAIL OBJECT -->
  <!--
  <xsl:template match="cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#EmailMessageObject-2', 'EmailMessageObjectType')]" priority="20000">
    <div>#####</div>
    <div>CUSTOM EMAIL TEMPLATE</div>
    <div>#####</div>
  </xsl:template>
  -->
  
  <!-- EXAMPLE TEMPLATE FOR EMAIL OBJECT (doing something with the "from" address -->
  <!--
  <xsl:template match="cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#EmailMessageObject-2', 'EmailMessageObjectType')]" priority="20000">
    <div>#####</div>
    <div>CUSTOM EMAIL TEMPLATE</div>
    <xsl:variable name="from" select="EmailMessageObj:Header/EmailMessageObj:From/AddressObj:Address_Value" />
    <xsl:if test="$from">
      <xsl:variable name="fromText" select="$from/text()" />
      <xsl:variable name="fromCondition" select="fn:data($from/@condition)" />
      <div>From <xsl:value-of select="$fromCondition"/> "<xsl:value-of select="$fromText"/>"</div>
    </xsl:if>
    <div>#####</div>
  </xsl:template>
  -->
  


</xsl:stylesheet>