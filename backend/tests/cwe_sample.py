"""A tiny CWE catalog with the same shape as MITRE's real file (schema 7, namespaced, with XHTML text).

It includes the awkward cases the parser must handle: a deprecated weakness, a category and a
view (not weaknesses), relationships in other views (ignored), a parent missing from the file,
XHTML paragraphs inside descriptions, and alternate names.
"""
import io
import zipfile

CWE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="4.18" Date="2025-09-09"
    xmlns="http://cwe.mitre.org/cwe-7" xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <Weaknesses>
    <Weakness ID="707" Name="Improper Neutralization" Abstraction="Pillar" Structure="Simple" Status="Incomplete">
      <Description>The product does not ensure or incorrectly ensures that structured messages or data are well-formed.</Description>
    </Weakness>
    <Weakness ID="74" Name="Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')" Abstraction="Class" Structure="Simple" Status="Incomplete">
      <Description>The product constructs all or part of a command using externally-influenced input.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="707" View_ID="1000" Ordinal="Primary"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.</Description>
      <Extended_Description>
        <xhtml:p>There are many flavors of XSS:</xhtml:p>
        <xhtml:ul><xhtml:li>Reflected XSS</xhtml:li><xhtml:li>Stored XSS</xhtml:li></xhtml:ul>
      </Extended_Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000" Ordinal="Primary"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1003" Ordinal="Primary"/>
      </Related_Weaknesses>
      <Applicable_Platforms>
        <Language Class="Not Language-Specific" Prevalence="Undetermined"/>
        <Technology Class="Web Based" Prevalence="Often"/>
      </Applicable_Platforms>
      <Alternate_Terms>
        <Alternate_Term><Term>XSS</Term><Description>A common abbreviation.</Description></Alternate_Term>
        <Alternate_Term><Term>HTML Injection</Term></Alternate_Term>
      </Alternate_Terms>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Common_Consequences>
        <Consequence>
          <Scope>Access Control</Scope><Scope>Confidentiality</Scope>
          <Impact>Bypass Protection Mechanism</Impact><Impact>Read Application Data</Impact>
        </Consequence>
      </Common_Consequences>
      <Potential_Mitigations>
        <Mitigation Mitigation_ID="MIT-43">
          <Phase>Architecture and Design</Phase>
          <Strategy>Libraries or Frameworks</Strategy>
          <Description><xhtml:p>Use a vetted library or framework that does not allow this weakness to occur.</xhtml:p></Description>
        </Mitigation>
        <Mitigation>
          <Phase>Implementation</Phase>
          <Description>Use and specify an output encoding that can be handled by the downstream component.</Description>
          <Effectiveness>High</Effectiveness>
        </Mitigation>
      </Potential_Mitigations>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="63"/>
        <Related_Attack_Pattern CAPEC_ID="588"/>
      </Related_Attack_Patterns>
    </Weakness>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product constructs all or part of an SQL command using externally-influenced input.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="943" View_ID="1000" Ordinal="Primary"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/>
        <Related_Weakness Nature="PeerOf" CWE_ID="79" View_ID="1000"/>
      </Related_Weaknesses>
      <Alternate_Terms>
        <Alternate_Term><Term>SQL injection</Term></Alternate_Term>
        <Alternate_Term><Term>SQLi</Term></Alternate_Term>
      </Alternate_Terms>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
    </Weakness>
    <Weakness ID="20" Name="Improper Input Validation" Abstraction="Class" Structure="Simple" Status="Stable">
      <Description>The product receives input or data, but it does not validate or incorrectly validates that the input has the properties required to process it safely.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="707" View_ID="1000" Ordinal="Primary"/>
        <Related_Weakness Nature="CanPrecede" CWE_ID="89" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="502" Name="Deserialization of Untrusted Data" Abstraction="Base" Structure="Simple" Status="Draft">
      <Description>The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="913" View_ID="1000" Ordinal="Primary"/>
      </Related_Weaknesses>
      <Alternate_Terms>
        <Alternate_Term><Term>Marshaling, Unmarshaling</Term></Alternate_Term>
      </Alternate_Terms>
    </Weakness>
    <Weakness ID="1" Name="DEPRECATED: Location" Abstraction="Class" Structure="Simple" Status="Deprecated">
      <Description>This category has been deprecated.</Description>
    </Weakness>
  </Weaknesses>
  <Categories>
    <Category ID="1218" Name="Memory Buffer Errors" Status="Draft"><Summary>A category, not a weakness.</Summary></Category>
  </Categories>
  <Views>
    <View ID="1000" Name="Research Concepts" Type="Graph" Status="Draft"><Objective>The main hierarchy.</Objective></View>
  </Views>
</Weakness_Catalog>
"""


def zipped(xml: bytes = CWE_XML) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("cwec_v4.18.xml", xml)
    return buffer.getvalue()
