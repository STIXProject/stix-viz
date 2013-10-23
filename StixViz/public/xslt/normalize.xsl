<?xml version="1.0" encoding="UTF-8"?>
<!--
  Copyright (c) 2013 – The MITRE Corporation
  All rights reserved. See LICENSE.txt for complete terms.
 -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:fn="http://www.w3.org/2005/xpath-functions" xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xd="http://www.oxygenxml.com/ns/doc/xsl" xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:ttp="http://stix.mitre.org/TTP-1" exclude-result-prefixes="xs xd" version="2.0"
    xmlns:saxon="http://saxon.sf.net/">

    <!-- 
  This stylesheet is responsible for cleaning up a stix document and getting it ready for processing.
  
  It creates two data structures that become the main input for the primary transform:
  
   - "reference": This is a sequence of all elements with an id in the source
     document.  Every item from the source document with an id is deep copied
     down through its descendants until an item with an @id or @idref is
     reached, then the rest of that tree is pruned (it will itself become an
     item in this sequence).  At this pruning point, the @id attribute is
     renamed to @idref.  This means every item in this sequence will have an
     @id on the top level element and will not have any descendants with @id
     attributes..   

   - "normalized": This is a copy of the top level content in the original
     document deep copied down to any element with an @id attribute.  Again,
     the children of this node are pruned off and the @id attribute is
     renamed to @idref.  Ths "normalized" variable will be used by the main
     transform which items should show up in the top level category tables
     (Observables, Indicators, TTPs, etc).
-->

    <xsl:output method="html" omit-xml-declaration="yes" indent="yes" media-type="text/html" version="4.0"/>
    <!-- <xsl:output indent="yes" saxon:indent-spaces="2" method="xml" /> -->

    <!--
  purpose: the following commented out root tranform can be used for
  development purposes to do an xml-to-xml transform on the source document to
  see what the "reference" and "normalized" variables look like.
  
  To use it, change the output method to xml and apply this tranform to any
  stix document.
-->

    <!--
    <xsl:template match="/">
        <root>
            <original> </original>

            <!- -
            <normalized>
                <xsl:apply-templates select="/stix:STIX_Package/*" mode="createNormalized"
                > </xsl:apply-templates>
            </normalized>

            <reference-before-cleaning>
                <xsl:apply-templates select="/stix:STIX_Package//*[@id]" mode="verbatim"/>
            </reference-before-cleaning>
            - ->

            <reference>
                <xsl:apply-templates
                    select="/stix:STIX_Package//*[@id or @phase_id[../../self::stixCommon:Kill_Chain] or self::cybox:Action or self::cybox:Associated_Object]"
                    mode="createReference">
                    <xsl:with-param name="isTopLevel" select="fn:true()"/>
                    <xsl:with-param name="isRoot" select="fn:true()"/>
                </xsl:apply-templates>
            </reference>

            <!- -
            <xsl:for-each
                select="/stix:STIX_Package/stix:Observables/cybox:Observable/(cybox:Event|cybox:Object)">
                <xsl:apply-templates mode="oneDeep" select="."/>
            </xsl:for-each>
            - ->
        </root>
    </xsl:template>
    -->

    <xsl:template match="node()" mode="createNormalized" priority="10.0">

        <xsl:copy copy-namespaces="no">
            <!-- pull in all the attributes -->
            <xsl:apply-templates select="@*" mode="createNormalized"/>

            <!-- cut off the children of items having an id attribute (it will be replaced with an idref) -->
            <xsl:if test="not(@id) and not(@idref)">
                <xsl:apply-templates select="node()" mode="createNormalized"/>
            </xsl:if>
        </xsl:copy>
    </xsl:template>

    <xsl:template match="@*" mode="createNormalized" priority="10.0">
        <xsl:copy copy-namespaces="no"/>
    </xsl:template>

    <xsl:template match="@id" mode="createNormalized" priority="20.0">
        <xsl:attribute name="idref" select="fn:data(.)"/>
    </xsl:template>

    <!--
        recursively copy all nodes, except stop copying when an element with an id
        attribute comes up and for that element, change the id to an idref (and all
        of its children are left off, as they will be listed as their own reference
        nodes).
    -->
    <xsl:template match="node()" mode="createReference" priority="10.0">
        <xsl:param name="isTopLevel" select="fn:false()"/>
        <xsl:param name="isRoot" select="fn:false()"/>

        <xsl:copy copy-namespaces="yes">

            <!-- for debugging, label each element with an attribute indicating if
                 it's the top level or a descendant
            -->
            <!--
            <xsl:attribute name="level">
                <xsl:if test="$isTopLevel">TOP</xsl:if>
                <xsl:if test="not($isTopLevel)">DESCENDENT</xsl:if>
            </xsl:attribute>
            -->
            
            <xsl:if test="$isRoot and not(@id) and not(@idref) and not(@action_id)">
                <xsl:attribute name="idgen"><xsl:value-of select="true()" /></xsl:attribute>
                <xsl:attribute name="id"><xsl:value-of select="generate-id(.)" /></xsl:attribute>
            </xsl:if>
            
            <xsl:variable name="cutOff" select="$isTopLevel or self::cybox:Object or self::cybox:Event or self::cybox:Related_Object 
                or self::cybox:Associated_Object or self::cybox:Action_Reference or self::cybox:Action or self::cybox:Associated_Object" />

            <!-- pull in all the attributes -->
            <xsl:apply-templates select="@*" mode="createReference">
                <xsl:with-param name="isTopLevel" select="$isTopLevel"/>
            </xsl:apply-templates>
            
            <xsl:choose>
                <xsl:when test="$cutOff and not($isRoot)">
                <!-- call template applying idref -->
                    <xsl:message select="local-name(.)"></xsl:message>
                    
                    <xsl:if test="not(@id) and not(@idref) and not(@action_id)">
                        <xsl:attribute name="idgen"><xsl:value-of select="true()" /></xsl:attribute>
                        <xsl:attribute name="idref"><xsl:value-of select="generate-id(.)" /></xsl:attribute>
                    </xsl:if>
                </xsl:when>

                <xsl:when test="$cutOff or not(@id)">
                    <xsl:apply-templates select="node()" mode="createReference">
                        <xsl:with-param name="isTopLevel" select="fn:false()"/>
                        <xsl:with-param name="isRoot" select="fn:false()"/>
                    </xsl:apply-templates>
                </xsl:when>
            </xsl:choose>
        </xsl:copy>
    </xsl:template>

    <!-- copy all attributes (excpet @id which will be handled in the
     following template with a higher priority
    -->
    <xsl:template match="@*" mode="createReference" priority="10.0">
        <xsl:param name="isTopLevel" select="fn:false()"/>

        <xsl:copy copy-namespaces="no"> </xsl:copy>
    </xsl:template>

    <xsl:template match="@id" mode="createReference" priority="20.0">
        <xsl:param name="isTopLevel" select="fn:false()"/>
        <xsl:choose>
            <xsl:when test="not($isTopLevel)">
                <xsl:attribute name="idref" select="fn:data(.)"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:attribute name="id" select="fn:data(.)"/>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <!--
    NOT NEEDED - - NORMALIZATION FIXES THIS BEFORE THIS POINT
    <xsl:template match="@object_reference" mode="createReference" priority="20.0">
        <xsl:attribute name="idref" select="fn:data(.)" />
    </xsl:template>
    -->
    <!-- REFERENCE: HELP_UPDATE_STEP_1B -->
    <xsl:template match="@object_reference|@action_id" mode="createReference" priority="20.0">
        <xsl:attribute name="idref" select="fn:data(.)"/>
    </xsl:template>

    <xsl:template match="@phase_id[../../self::stixCommon:Kill_Chain]" mode="createReference"
        priority="20.0">
        <xsl:param name="isTopLevel" select="fn:false()"/>
        <xsl:choose>
            <xsl:when test="$isTopLevel">
                <xsl:attribute name="id" select="fn:data(.)"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:attribute name="idref" select="fn:data(.)"/>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template match="@phase_id[not(../../self::stixCommon:Kill_Chain)]" mode="createReference"
        priority="20.0">
        <xsl:attribute name="idref" select="fn:data(.)"/>
    </xsl:template>

    <!--
    <xsl:template match="stix:TTPs/stix:Kill_Chains/stixCommon:Kill_Chain/stixCommon:Kill_Chain_Phase[@phase_id]" mode="createReference" priority="20.0">
        <xsl:copy copy-namespaces="no">
            <xsl:apply-templates select="@*|node()" mode="createReference" />
        </xsl:copy>
    </xsl:template>        

    <xsl:template match="@phase_id" mode="createReference" priority="20.0">
        <xsl:attribute name="id" select="fn:data(.)" />
    </xsl:template>
    -->


    <!--
    <xsl:template match="stix:TTPs/stix:TTP/ttp:Kill_Chain_Phases/stixCommon:Kill_Chain_Phase[@phase_id]" mode="createReference" priority="20.0">
        <!- - <xsl:attribute name="idref" select="fn:data(.)" /> - ->
    </xsl:template>
    -->

    <xsl:template match="@*|node()" mode="verbatim">
        <xsl:copy copy-namespaces="no">
            <xsl:apply-templates select="@*|node()" mode="verbatim"/>
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>