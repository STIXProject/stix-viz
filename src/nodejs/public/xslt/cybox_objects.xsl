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
  xmlns:registry='http://cybox.mitre.org/objects#WinRegistryKeyObject-2'
  
  xmlns:http='http://cybox.mitre.org/objects#HTTPSessionObject-2'
  
  exclude-result-prefixes="cybox Common xsi fn EmailMessageObj AddressObject URIObject xs registry"
  
  version="2.0">
  
  <xsl:include href="cybox_util.xsl" />
  
  <!--
    ····························································
  -->
  
  <!--
      Output URI & Link value without unnecessary nested schema tree structure
    -->
  <!-- //cybox:Observable//cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName("http://cybox.mitre.org/objects#URIObject-2", "URIObjectType")]  -->
  <!-- <xsl:template match="cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#URIObject-2', 'URIObjectType')]|cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#URIObject-2', 'LinkObjectType')]"> -->
  <!-- fn:local-name(fn:resolve-QName(fn:data(@xsi:type), .)) -->
  <!-- <xsl:template match="cybox:Properties[some $currentXsiType in ('URIObjectType', 'LinkObjectType') satisfies $currentXsiType = fn:local-name(fn:resolve-QName(fn:data(@xsi:type), .))]"> -->
  <!-- <xsl:template match="cybox:Properties['URIObjectType' = fn:local-name(fn:resolve-QName(fn:data(@xsi:type), .))]"> -->
  
  <xsl:template match="cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#URIObject-2', 'URIObjectType')]|cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#URIObject-2', 'LinkObjectType')]"><fieldset>
    <legend>URI</legend>
    <div class="container cyboxPropertiesContainer cyboxProperties">
      <div class="heading cyboxPropertiesHeading cyboxProperties">
        <xsl:apply-templates select="URIObject:Value" mode="cyboxProperties" />
      </div>
    </div>
  </fieldset>
  </xsl:template>
  <xsl:template match="URIObject:Value" mode="cyboxProperties">
    Value <xsl:value-of select="Common:Defanged(@is_defanged, @defanging_algorithm_ref)" />
    <xsl:choose>
      <xsl:when test="@condition!=''"><xsl:value-of select="Common:ConditionType(@condition)" /></xsl:when>
      <xsl:otherwise> = </xsl:otherwise>
    </xsl:choose>
    <xsl:value-of select="." />
  </xsl:template>
  
  <!--
    ····························································
  -->
  
  <!--
    <cybox:Properties xsi:type="WinRegistryKeyObject:WindowsRegistryKeyObjectType">
			<WinRegistryKeyObject:Key condition="Equals">SOFTWARE\Microsoft\Windows\CurrentVersion\Run</WinRegistryKeyObject:Key>
			<WinRegistryKeyObject:Hive condition="Equals">HKLM</WinRegistryKeyObject:Hive>
			<WinRegistryKeyObject:Values>
				<WinRegistryKeyObject:Value>
					<WinRegistryKeyObject:Data condition="FitsPattern">rundll32\.exe C:\\DOCUME~1\\USER\\LOCALS~1\\Temp\\[^.]+\.dll&comma;XMLResFunc [^ ]+ 0</WinRegistryKeyObject:Data>
				</WinRegistryKeyObject:Value>
			</WinRegistryKeyObject:Values>
		</cybox:Properties>    
  -->
  <xsl:template match="cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#WinRegistryKeyObject-2', 'WindowsRegistryKeyObjectType')]">
    <xsl:variable name="hive" as="xs:string?" select="registry:Hive" />
    <xsl:variable name="key" as="xs:string?" select="registry:Key" />
    <xsl:variable name="valueDataSequence" as="element()*" select="registry:Values/registry:Value/registry:Data" />
    
    <table class="windowsRegistryTable">
      <thead>
        <tr>
          <th rowspan="2">Location</th>
          <th>Hive:</th>
          <td><xsl:value-of select="$hive" /></td>
        </tr>
        <tr>
          <th>Key:</th>
          <td><xsl:value-of select="$key" /></td>
        </tr>
      </thead>
      <tbody>
        <tr>
          <th colspan="3">Value<xsl:value-of select="if (count($valueDataSequence) > 1) then 's' else ''" /></th>
        </tr>
        <xsl:for-each select="$valueDataSequence">
          <tr>
            <td colspan="3">
              <xsl:value-of select="text()" />
            </td>
          </tr>
        </xsl:for-each>
        
      </tbody>
    </table>
    
  </xsl:template>  
  <!--
    ····························································
  -->
  <xsl:template match="http:HTTP_Request_Response|cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#HTTPSessionObject-2', 'HTTP_Request_Response')]" mode="cyboxProperties">
    <xsl:apply-templates select="." />
  </xsl:template>
  
  <xsl:template match="http:HTTP_Request_Response|cybox:Properties[fn:resolve-QName(fn:data(@xsi:type), .)=fn:QName('http://cybox.mitre.org/objects#HTTPSessionObject-2', 'HTTP_Request_Response')]">
    <xsl:variable name="mainRequestResponse" as="element()*" select="." />
    <xsl:variable name="mainRequest" as="element()?" select="$mainRequestResponse/http:HTTP_Client_Request" />
    <xsl:variable name="mainResponse" as="element()?" select="$mainRequestResponse/http:HTTP_Server_Response" />
    
    <xsl:variable name="requestLine" select="$mainRequest/http:HTTP_Request_Line" />
    <xsl:variable name="method" select="$requestLine/http:HTTP_Method" />
    <xsl:variable name="value" select="$requestLine/http:Value" />
    
    <table class="httpRequestResponseTable">
      <thead>
        <tr>
          <th>what?</th>
          <th>header/field name</th>
          <th>value</th>
        </tr>
        <xsl:if test="$mainRequest">
          
          <tbody class="requestResponseHeaderRow">
            <tr>
              <th colspan="3">request</th>
            </tr>
          </tbody>            
          <tbody class="httpRequestDetails">
            <tr>
              <th>method</th>
              <td colspan="2"><xsl:value-of select="$method/text()" /></td>          
            </tr>
          
            <xsl:for-each select="$mainRequest/http:HTTP_Request_Header">
              <xsl:for-each select="http:Parsed_Header">'
                <xsl:variable name="parsedHeader" select="." />
                <xsl:variable name="parsedHeaderChild" select="$parsedHeader/*" />
                <tr>
                  <th>header</th>
                  <td><xsl:value-of select="local-name($parsedHeaderChild)" /></td>
                  <td><xsl:value-of select="$parsedHeaderChild/text()" /></td>
                </tr>
              </xsl:for-each>
            </xsl:for-each>
            
          </tbody> <!-- end of tbody.httpRequestDetails -->
        </xsl:if> <!-- end of if($mainRequest) -->
        
        <xsl:if test="$mainResponse">
          <xsl:variable name="httpResponseMessageBody" select="$mainResponse/http:HTTP_Message_Body" />
          <xsl:variable name="responseMessageBody" select="$httpResponseMessageBody/http:Message_Body" />
          
          <tbody class="requestResponseHeaderRow">
            <tr>
              <th colspan="3">response</th>
            </tr>
          </tbody>            
          <tbody class="httpResponseDetails">
            <tr>
              <th>message body</th>
              <td colspan="2"><xsl:value-of select="$responseMessageBody/text()" /></td>          
            </tr>
          </tbody>
        </xsl:if>
      </thead>
    </table>
  </xsl:template>
  <!--
  <xsl:template match="*[@condition]/text()" mode="cyboxProperties" priority="30000">
    <xsl:variable name="text" select="fn:data(.)" />
    <xsl:variable name="tokens" select="fn:tokenize($text, '##comma##')" />
    
    <div>OPTION #1</div>
    <xsl:for-each select="$tokens">
      <div>
        <xsl:value-of select="." />
      </div>
    </xsl:for-each>
  </xsl:template>
  -->

<!--
  <xsl:template match="text()" mode="createReference" priority="30000">
    <xsl:variable name="text" select="fn:data(.)" />
    <xsl:variable name="tokens" select="fn:tokenize($text, '###comma###')" />
    
    <div>OPTION #2</div>
    <xsl:for-each select="$tokens">
      <div>
        <xsl:value-of select="." />
      </div>
    </xsl:for-each>
  </xsl:template>
  
  <xsl:template match="text()" priority="30000">
    <xsl:variable name="text" select="fn:data(.)" />
    <xsl:variable name="tokens" select="fn:tokenize($text, '###comma###')" />
    
    <div>OPTION #3</div>
    <xsl:for-each select="$tokens">
      <div>
        <xsl:value-of select="." />
      </div>
    </xsl:for-each>
  </xsl:template>
  -->
  
</xsl:stylesheet>