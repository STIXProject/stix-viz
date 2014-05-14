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
  xmlns:cyboxEmail="http://cybox.mitre.org/objects#EmailMessageObject-2"
  xmlns:registry='http://cybox.mitre.org/objects#WinRegistryKeyObject-2'
  
  xmlns:http='http://cybox.mitre.org/objects#HTTPSessionObject-2'
  
  exclude-result-prefixes="cybox Common xsi fn cyboxEmail AddressObject URIObject xs registry"
  
  version="2.0">
  
  <xsl:include href="cybox_util.xsl" />
  
  <!--
    ····························································
  -->
  
  <!--
      Output URI & Link value without unnecessary nested schema tree structure
    -->
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
    purpose: template for processing windows registry entry with more common
    sense output formatting [making use of hive, key, and value(s)].
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
  
  <!--
    purpose: templates for process http request-response objects
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
    purpose: for cybox:Properties descendant text nodes that are delimited by
      ##comma##, tokenize the item. For items that have a InclusiveBetween or
      ExclusiveBetween, they are ranges and should be labeled as such.
  -->
  <xsl:template match="cybox:Properties//text()[fn:contains(., '##comma##')]" mode="cyboxProperties">
    <xsl:variable name="text" select="fn:data(.)" />
    <xsl:variable name="tokens" select="fn:tokenize($text, '##comma##')" />
    
    <xsl:choose>
      <!-- when this is a range -->
      <xsl:when test="../@condition='InclusiveBetween' or ../@condition='ExclusiveBetween'">
        <xsl:variable name="from" select="$tokens[1]" />
        <xsl:variable name="to" select="$tokens[2]" />
        <span class="cyboxPropertiesRange">
          <xsl:value-of select="concat($from, ' - ', $to)" />
          <xsl:if test="../@condition='InclusiveBetween'"> (inclusive)</xsl:if>
          <xsl:if test="../@condition='ExclusiveBetween'"> (exclusive)</xsl:if>
        </span>
      </xsl:when>
      
      <!-- otherwise, this is just a tokenized list, not a range -->
      <xsl:otherwise>
        <xsl:variable name="condition" select="if (../@condition) then (fn:data(../@condition)) else ('Equals')" />
        <xsl:variable name="applyCondition" select="if (../@apply_condition) then (fn:data(../@apply_condition)) else ('Any')" />
        
        <div class="conditionClause"><xsl:value-of select="concat($condition, ' ', $applyCondition, ':')"/></div>
        <ul class="cyboxPropertiesTokenizedList">
         <xsl:for-each select="$tokens">
           <li>
             <xsl:value-of select="." />
           </li>
         </xsl:for-each>
        </ul>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!--
    purpose: sample custom template for email messages.  This default template only shows raw headers and raw body.
    
    TODO: extend for parsed headers.
  -->
  <xsl:template match="cybox:Properties[contains(@xsi:type,'EmailMessageObjectType')]" priority="1000">
    <div class="emailCustomTemplate">
      <!-- <img style="width: 200px; height: 200px;" src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzdmcgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOmNjPSJodHRwOi8vd2ViLnJlc291cmNlLm9yZy9jYy8iIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIGlkPSJzdmc3MTA2IiBoZWlnaHQ9IjY4LjJwdCIgd2lkdGg9IjEwNS40cHQiIHZlcnNpb249IjEuMCI+CiA8ZGVmcyBpZD0iZGVmczMiPgogIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyR3JhZGllbnQ2OTA3Ij4KICAgPHN0b3AgaWQ9InN0b3A2OTA5IiBzdG9wLWNvbG9yPSIjZGNlN2VjIiBvZmZzZXQ9IjAiLz4KICAgPHN0b3AgaWQ9InN0b3A2OTExIiBzdG9wLWNvbG9yPSIjODM5Mjk3IiBvZmZzZXQ9IjEiLz4KICA8L2xpbmVhckdyYWRpZW50PgogIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyR3JhZGllbnQyNDMwIiB4MT0iNjQzLjYiIHhsaW5rOmhyZWY9IiNsaW5lYXJHcmFkaWVudDY5MDciIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiB5MT0iMzkwLjE0IiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEuNTg0IDAgMCAuNjU4MjAgLTk0OS42OCAtMjE0Ljg3KSIgeDI9IjY0My42IiB5Mj0iNDY0Ljc0Ii8+CiAgPGxpbmVhckdyYWRpZW50IGlkPSJsaW5lYXJHcmFkaWVudDI0MzMiIHgxPSIxMTQ3LjIiIHhsaW5rOmhyZWY9IiNsaW5lYXJHcmFkaWVudDY5MDciIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiB5MT0iMTk4LjkiIGdyYWRpZW50VHJhbnNmb3JtPSJtYXRyaXgoLjkxMTk4IDAgMCAxLjE0MzIgLTk0OS42OCAtMjE0Ljg3KSIgeDI9IjExNDcuMiIgeTI9IjI2Mi4yMyIvPgogIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyR3JhZGllbnQyNDM2IiB4MT0iMTA3Ni43IiB4bGluazpocmVmPSIjbGluZWFyR3JhZGllbnQ2OTA3IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeTE9IjIwMi4wMiIgZ3JhZGllbnRUcmFuc2Zvcm09Im1hdHJpeCguOTExOTggMCAwIDEuMTQzMiAtOTQ5LjY4IC0yMTUpIiB4Mj0iMTA3Ni43IiB5Mj0iMjU1LjUyIi8+CiAgPHJhZGlhbEdyYWRpZW50IGlkPSJyYWRpYWxHcmFkaWVudDI0NDIiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiBjeT0iMzE2LjkxIiBjeD0iNzkyLjgxIiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEuMjgzOSAwIDAgLjgxMjA2IC05NDkuNjggLTIxNSkiIHI9IjkxLjQ2OCI+CiAgIDxzdG9wIGlkPSJzdG9wNjk0NSIgc3RvcC1jb2xvcj0iI2ZmZiIgb2Zmc2V0PSIwIi8+CiAgIDxzdG9wIGlkPSJzdG9wNjk0NyIgc3RvcC1jb2xvcj0iIzU4NTg1OCIgb2Zmc2V0PSIxIi8+CiAgPC9yYWRpYWxHcmFkaWVudD4KIDwvZGVmcz4KIDxyZWN0IGlkPSJyZWN0NzE0NSIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIgc3R5bGU9ImNvbG9yOiMwMDAwMDAiIGhlaWdodD0iNzQuNjI1IiB3aWR0aD0iMTE3Ljk4IiBzdHJva2U9IiM2MTZiNmQiIHk9IjUuMDM5MSIgeD0iNi41OTYiIHN0cm9rZS13aWR0aD0iNC4xMjE2IiBmaWxsPSJ1cmwoI3JhZGlhbEdyYWRpZW50MjQ0MikiLz4KIDxwYXRoIGlkPSJwYXRoNzE1MyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIgc3R5bGU9ImNvbG9yOiMwMDAwMDAiIGQ9Im02LjU5NiA1LjExMzV2NjguODZsMC4wMzE4IDUuNjE2IDU4Ljk2Ni0zNy4yMzgtNTguOTM0LTM3LjIzOC0wLjA2NC0wLjAwMDV6IiBzdHJva2U9IiMwMDAiIHN0cm9rZS13aWR0aD0iNC4xMjE2IiBmaWxsPSJ1cmwoI2xpbmVhckdyYWRpZW50MjQzNikiLz4KIDxwYXRoIGlkPSJwYXRoNzE1NSIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIgc3R5bGU9ImNvbG9yOiMwMDAwMDAiIGQ9Im0xMjQuNTggNS4yMzcxdjY4Ljg2bC0wLjAzIDUuNjE2LTU4Ljk2OC0zNy4yMzggNTguOTM4LTM3LjIzOCAwLjA2IDAuMDAwMXoiIHN0cm9rZT0iIzAwMCIgc3Ryb2tlLXdpZHRoPSI0LjEyMTYiIGZpbGw9InVybCgjbGluZWFyR3JhZGllbnQyNDMzKSIvPgogPHBhdGggaWQ9InBhdGg3MTU3IiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBzdHlsZT0iY29sb3I6IzAwMDAwMCIgZD0ibTQ4Ljg4IDM5LjYzNWwtNDIuMjQ2IDQwLjAxNC0wLjAzMjMgMC4xMjhoMTE4bC0wLjA3LTAuMTI4LTQyLjI0Mi00MC4wMTRjLTEwLjY4NS0xMC4xMi0yMi40My0xMC4zOTgtMzMuNDA4IDB6IiBzdHJva2U9IiMwMDAiIHN0cm9rZS13aWR0aD0iNC4xMjE2IiBmaWxsPSJ1cmwoI2xpbmVhckdyYWRpZW50MjQzMCkiLz4KIDxwYXRoIGlkPSJwYXRoNzE0MyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIgc3R5bGU9ImNvbG9yOiMwMDAwMDAiIGQ9Im00OC44NTMgNDEuMTQ2bC00Mi4xOTktMzUuODg1LTAuMDMyLTAuMTE0NWgxMTcuODdsLTAuMDcgMC4xMTQ0LTQyLjE5NyAzNS44ODVjLTEwLjY3MiA5LjA3NS0yMi40MDUgOS4zMjQtMzMuMzcgMHoiIHN0cm9rZT0iIzAwMCIgc3Ryb2tlLXdpZHRoPSI0LjEyMTYiIGZpbGw9IiNjNmQyZDciLz4KIDxtZXRhZGF0YT4KICA8cmRmOlJERj4KICAgPGNjOldvcms+CiAgICA8ZGM6Zm9ybWF0PmltYWdlL3N2Zyt4bWw8L2RjOmZvcm1hdD4KICAgIDxkYzp0eXBlIHJkZjpyZXNvdXJjZT0iaHR0cDovL3B1cmwub3JnL2RjL2RjbWl0eXBlL1N0aWxsSW1hZ2UiLz4KICAgIDxjYzpsaWNlbnNlIHJkZjpyZXNvdXJjZT0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbGljZW5zZXMvcHVibGljZG9tYWluLyIvPgogICAgPGRjOnB1Ymxpc2hlcj4KICAgICA8Y2M6QWdlbnQgcmRmOmFib3V0PSJodHRwOi8vb3BlbmNsaXBhcnQub3JnLyI+CiAgICAgIDxkYzp0aXRsZT5PcGVuY2xpcGFydDwvZGM6dGl0bGU+CiAgICAgPC9jYzpBZ2VudD4KICAgIDwvZGM6cHVibGlzaGVyPgogICA8L2NjOldvcms+CiAgIDxjYzpMaWNlbnNlIHJkZjphYm91dD0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbGljZW5zZXMvcHVibGljZG9tYWluLyI+CiAgICA8Y2M6cGVybWl0cyByZGY6cmVzb3VyY2U9Imh0dHA6Ly9jcmVhdGl2ZWNvbW1vbnMub3JnL25zI1JlcHJvZHVjdGlvbiIvPgogICAgPGNjOnBlcm1pdHMgcmRmOnJlc291cmNlPSJodHRwOi8vY3JlYXRpdmVjb21tb25zLm9yZy9ucyNEaXN0cmlidXRpb24iLz4KICAgIDxjYzpwZXJtaXRzIHJkZjpyZXNvdXJjZT0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjRGVyaXZhdGl2ZVdvcmtzIi8+CiAgIDwvY2M6TGljZW5zZT4KICA8L3JkZjpSREY+CiA8L21ldGFkYXRhPgo8L3N2Zz4K" /> -->
      <div style="border-color: gray; border-style: solid; border-width: thin; padding: 0.2 em; background-repeat: no-repeat; background-image: url('data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzdmcgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOmNjPSJodHRwOi8vd2ViLnJlc291cmNlLm9yZy9jYy8iIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIGlkPSJzdmc3MTA2IiBoZWlnaHQ9IjY4LjJwdCIgd2lkdGg9IjEwNS40cHQiIHZlcnNpb249IjEuMCI+CiA8ZGVmcyBpZD0iZGVmczMiPgogIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyR3JhZGllbnQ2OTA3Ij4KICAgPHN0b3AgaWQ9InN0b3A2OTA5IiBzdG9wLWNvbG9yPSIjZGNlN2VjIiBvZmZzZXQ9IjAiLz4KICAgPHN0b3AgaWQ9InN0b3A2OTExIiBzdG9wLWNvbG9yPSIjODM5Mjk3IiBvZmZzZXQ9IjEiLz4KICA8L2xpbmVhckdyYWRpZW50PgogIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyR3JhZGllbnQyNDMwIiB4MT0iNjQzLjYiIHhsaW5rOmhyZWY9IiNsaW5lYXJHcmFkaWVudDY5MDciIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiB5MT0iMzkwLjE0IiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEuNTg0IDAgMCAuNjU4MjAgLTk0OS42OCAtMjE0Ljg3KSIgeDI9IjY0My42IiB5Mj0iNDY0Ljc0Ii8+CiAgPGxpbmVhckdyYWRpZW50IGlkPSJsaW5lYXJHcmFkaWVudDI0MzMiIHgxPSIxMTQ3LjIiIHhsaW5rOmhyZWY9IiNsaW5lYXJHcmFkaWVudDY5MDciIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiB5MT0iMTk4LjkiIGdyYWRpZW50VHJhbnNmb3JtPSJtYXRyaXgoLjkxMTk4IDAgMCAxLjE0MzIgLTk0OS42OCAtMjE0Ljg3KSIgeDI9IjExNDcuMiIgeTI9IjI2Mi4yMyIvPgogIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyR3JhZGllbnQyNDM2IiB4MT0iMTA3Ni43IiB4bGluazpocmVmPSIjbGluZWFyR3JhZGllbnQ2OTA3IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeTE9IjIwMi4wMiIgZ3JhZGllbnRUcmFuc2Zvcm09Im1hdHJpeCguOTExOTggMCAwIDEuMTQzMiAtOTQ5LjY4IC0yMTUpIiB4Mj0iMTA3Ni43IiB5Mj0iMjU1LjUyIi8+CiAgPHJhZGlhbEdyYWRpZW50IGlkPSJyYWRpYWxHcmFkaWVudDI0NDIiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiBjeT0iMzE2LjkxIiBjeD0iNzkyLjgxIiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEuMjgzOSAwIDAgLjgxMjA2IC05NDkuNjggLTIxNSkiIHI9IjkxLjQ2OCI+CiAgIDxzdG9wIGlkPSJzdG9wNjk0NSIgc3RvcC1jb2xvcj0iI2ZmZiIgb2Zmc2V0PSIwIi8+CiAgIDxzdG9wIGlkPSJzdG9wNjk0NyIgc3RvcC1jb2xvcj0iIzU4NTg1OCIgb2Zmc2V0PSIxIi8+CiAgPC9yYWRpYWxHcmFkaWVudD4KIDwvZGVmcz4KIDxnIG9wYWNpdHk9IjAuMSI+CiA8cmVjdCBpZD0icmVjdDcxNDUiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHN0eWxlPSJjb2xvcjojMDAwMDAwIiBoZWlnaHQ9Ijc0LjYyNSIgd2lkdGg9IjExNy45OCIgc3Ryb2tlPSIjNjE2YjZkIiB5PSI1LjAzOTEiIHg9IjYuNTk2IiBzdHJva2Utd2lkdGg9IjQuMTIxNiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDI0NDIpIi8+CiA8cGF0aCBpZD0icGF0aDcxNTMiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHN0eWxlPSJjb2xvcjojMDAwMDAwIiBkPSJtNi41OTYgNS4xMTM1djY4Ljg2bDAuMDMxOCA1LjYxNiA1OC45NjYtMzcuMjM4LTU4LjkzNC0zNy4yMzgtMC4wNjQtMC4wMDA1eiIgc3Ryb2tlPSIjMDAwIiBzdHJva2Utd2lkdGg9IjQuMTIxNiIgZmlsbD0idXJsKCNsaW5lYXJHcmFkaWVudDI0MzYpIi8+CiA8cGF0aCBpZD0icGF0aDcxNTUiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHN0eWxlPSJjb2xvcjojMDAwMDAwIiBkPSJtMTI0LjU4IDUuMjM3MXY2OC44NmwtMC4wMyA1LjYxNi01OC45NjgtMzcuMjM4IDU4LjkzOC0zNy4yMzggMC4wNiAwLjAwMDF6IiBzdHJva2U9IiMwMDAiIHN0cm9rZS13aWR0aD0iNC4xMjE2IiBmaWxsPSJ1cmwoI2xpbmVhckdyYWRpZW50MjQzMykiLz4KIDxwYXRoIGlkPSJwYXRoNzE1NyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIgc3R5bGU9ImNvbG9yOiMwMDAwMDAiIGQ9Im00OC44OCAzOS42MzVsLTQyLjI0NiA0MC4wMTQtMC4wMzIzIDAuMTI4aDExOGwtMC4wNy0wLjEyOC00Mi4yNDItNDAuMDE0Yy0xMC42ODUtMTAuMTItMjIuNDMtMTAuMzk4LTMzLjQwOCAweiIgc3Ryb2tlPSIjMDAwIiBzdHJva2Utd2lkdGg9IjQuMTIxNiIgZmlsbD0idXJsKCNsaW5lYXJHcmFkaWVudDI0MzApIi8+CiA8cGF0aCBpZD0icGF0aDcxNDMiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHN0eWxlPSJjb2xvcjojMDAwMDAwIiBkPSJtNDguODUzIDQxLjE0NmwtNDIuMTk5LTM1Ljg4NS0wLjAzMi0wLjExNDVoMTE3Ljg3bC0wLjA3IDAuMTE0NC00Mi4xOTcgMzUuODg1Yy0xMC42NzIgOS4wNzUtMjIuNDA1IDkuMzI0LTMzLjM3IDB6IiBzdHJva2U9IiMwMDAiIHN0cm9rZS13aWR0aD0iNC4xMjE2IiBmaWxsPSIjYzZkMmQ3Ii8+CiA8L2c+CiA8bWV0YWRhdGE+CiAgPHJkZjpSREY+CiAgIDxjYzpXb3JrPgogICAgPGRjOmZvcm1hdD5pbWFnZS9zdmcreG1sPC9kYzpmb3JtYXQ+CiAgICA8ZGM6dHlwZSByZGY6cmVzb3VyY2U9Imh0dHA6Ly9wdXJsLm9yZy9kYy9kY21pdHlwZS9TdGlsbEltYWdlIi8+CiAgICA8Y2M6bGljZW5zZSByZGY6cmVzb3VyY2U9Imh0dHA6Ly9jcmVhdGl2ZWNvbW1vbnMub3JnL2xpY2Vuc2VzL3B1YmxpY2RvbWFpbi8iLz4KICAgIDxkYzpwdWJsaXNoZXI+CiAgICAgPGNjOkFnZW50IHJkZjphYm91dD0iaHR0cDovL29wZW5jbGlwYXJ0Lm9yZy8iPgogICAgICA8ZGM6dGl0bGU+T3BlbmNsaXBhcnQ8L2RjOnRpdGxlPgogICAgIDwvY2M6QWdlbnQ+CiAgICA8L2RjOnB1Ymxpc2hlcj4KICAgPC9jYzpXb3JrPgogICA8Y2M6TGljZW5zZSByZGY6YWJvdXQ9Imh0dHA6Ly9jcmVhdGl2ZWNvbW1vbnMub3JnL2xpY2Vuc2VzL3B1YmxpY2RvbWFpbi8iPgogICAgPGNjOnBlcm1pdHMgcmRmOnJlc291cmNlPSJodHRwOi8vY3JlYXRpdmVjb21tb25zLm9yZy9ucyNSZXByb2R1Y3Rpb24iLz4KICAgIDxjYzpwZXJtaXRzIHJkZjpyZXNvdXJjZT0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjRGlzdHJpYnV0aW9uIi8+CiAgICA8Y2M6cGVybWl0cyByZGY6cmVzb3VyY2U9Imh0dHA6Ly9jcmVhdGl2ZWNvbW1vbnMub3JnL25zI0Rlcml2YXRpdmVXb3JrcyIvPgogICA8L2NjOkxpY2Vuc2U+CiAgPC9yZGY6UkRGPgogPC9tZXRhZGF0YT4KPC9zdmc+Cg=='); ">
        <xsl:if test="cyboxEmail:Raw_Header">
          <section class="emailRawHeader emailRaw">
            <h4>raw headers</h4>
            <div style="white-space: pre-line;">
              <xsl:value-of select="cyboxEmail:Raw_Header" />
            </div>
          </section>
        </xsl:if>  
        <xsl:if test="cyboxEmail:Raw_Body">
          <section class="emailRawBody emailRaw">
            <h4>raw body</h4>
            <div style="white-space: pre-line;">
              <xsl:value-of select="cyboxEmail:Raw_Body" />
            </div>
          </section>
        </xsl:if>  
      </div>
    </div>
  </xsl:template>

  <!--
    Output hash value without unnecessary nested schema tree structure
  -->
  <xsl:template match="Common:Hash" mode="cyboxProperties">
    <div class="container cyboxPropertiesContainer cyboxProperties">
      <span class="cyboxPropertiesName"><xsl:value-of select="local-name()"/> </span>
      <span class="cyboxPropertiesValue">
        <xsl:value-of select="./Common:Type"/> = 
        <xsl:value-of select="./Common:Simple_Hash_Value|./Common:Fuzzy_Hash_Value"/>
      </span>            
    </div>
  </xsl:template>
  
  <!--
    Output Port value without unnecessary nested schema tree structure.
    
    note: This only applies within cyboxProperties styled output.
  -->
  <xsl:template match="*:Port[contains(@xsi:type,'PortObjectType')]|*:Port[./*:Port_Value]" mode="cyboxProperties">
    <div class="container cyboxPropertiesContainer cyboxProperties">
      <div class="heading cyboxPropertiesHeading cyboxProperties">
        Port <xsl:choose>
          <xsl:when test="@condition!=''"><xsl:value-of select="Common:ConditionType(@condition)" /></xsl:when>
          <xsl:otherwise> = </xsl:otherwise>
        </xsl:choose>
        <xsl:value-of select="." />
      </div>
    </div>
  </xsl:template>
  
  
</xsl:stylesheet>