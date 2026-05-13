MATCH (cve:CVE {Name: $cve_id})
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cve)-[:CVSS3_Impact]->(cvss3:CVSS_3)
OPTIONAL MATCH (cve)-[:CVSS2_Impact]->(cvss2:CVSS_2)
OPTIONAL MATCH (cve)-[:applicableIn]->(cpe:CPE)
OPTIONAL MATCH (cve)-[:referencedBy]->(ref:Reference_Data)
RETURN
  cve.Name AS cve,
  cve.Description AS description,
  cve.Published_Date AS published_date,
  cve.Last_Modified_Date AS last_modified_date,
  collect(DISTINCT cwe.Name) AS cwes,
  collect(DISTINCT {
    score: cvss3.Base_Score,
    severity: cvss3.Base_Severity,
    vector: cvss3.Vector_String
  }) AS cvss3,
  collect(DISTINCT {
    score: cvss2.Base_Score,
    severity: cvss2.Severity,
    vector: cvss2.Vector_String
  }) AS cvss2,
  collect(DISTINCT cpe.uri)[0..20] AS cpes,
  collect(DISTINCT {
    url: ref.url,
    source: ref.refSource,
    name: ref.Name
  })[0..20] AS references
