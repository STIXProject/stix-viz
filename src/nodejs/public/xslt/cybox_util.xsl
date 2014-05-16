<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  exclude-result-prefixes="xs"
  xmlns:Common="http://cybox.mitre.org/common-2"
  version="2.0">
  
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
  
  
</xsl:stylesheet>