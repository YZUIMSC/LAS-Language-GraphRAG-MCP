MATCH (cve:CVE)-[a:applicableIn]->(cpe:CPE)
WHERE toLower(cpe.uri) CONTAINS toLower($keyword)
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cve)-[:CVSS3_Impact]->(cvss3:CVSS_3)
RETURN
  cve.Name AS cve,
  cpe.uri AS cpe,
  a.Vulnerable AS vulnerable,
  cvss3.Base_Score AS score,
  cvss3.Base_Severity AS severity,
  collect(DISTINCT cwe.Name) AS cwes
ORDER BY score DESC
LIMIT 100
