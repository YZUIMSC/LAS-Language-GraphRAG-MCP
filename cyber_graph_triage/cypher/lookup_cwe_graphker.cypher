MATCH (cwe:CWE {Name: $cwe_id})
OPTIONAL MATCH (cwe)-[rw:Related_Weakness]->(other:CWE)
OPTIONAL MATCH (cwe)-[:RelatedAttackPattern]->(capec:CAPEC)
OPTIONAL MATCH (cwe)-[:hasMitigation]->(mit:Mitigation)
OPTIONAL MATCH (cwe)-[:hasConsequence]->(con:Consequence)
RETURN
  cwe.Name AS cwe,
  cwe.Extended_Name AS name,
  cwe.Description AS description,
  cwe.Abstraction AS abstraction,
  cwe.Structure AS structure,
  cwe.Status AS status,
  collect(DISTINCT {
    nature: rw.Nature,
    target: other.Name,
    target_name: other.Extended_Name
  }) AS related_cwes,
  collect(DISTINCT {
    capec: capec.Name,
    name: coalesce(capec.ExtendedName, capec.Extended_Name)
  }) AS capecs,
  collect(DISTINCT mit.Description)[0..10] AS mitigations,
  collect(DISTINCT con.Scope) AS consequences
