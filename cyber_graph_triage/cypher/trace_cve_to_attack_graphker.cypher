MATCH (cve:CVE {Name: $cve_id})
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cwe)-[:RelatedAttackPattern]->(capec:CAPEC)
RETURN
  cve.Name AS cve,
  cwe.Name AS cwe,
  cwe.Extended_Name AS cwe_name,
  capec.Name AS capec,
  coalesce(capec.ExtendedName, capec.Extended_Name) AS capec_name
