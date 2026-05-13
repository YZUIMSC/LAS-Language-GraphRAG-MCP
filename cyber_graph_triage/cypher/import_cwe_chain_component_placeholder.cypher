MATCH (source:CWE {Name: $source})
MERGE (target:CWE {Name: $target})
ON CREATE SET target.Extended_Name = $target_name,
              target.Status        = "Placeholder",
              target.Source        = "cwe_chain_component_patch"
MERGE (source)-[r:Related_Weakness {Nature: $nature}]->(target)
SET r.Source     = $source_type,
    r.Source_URL = $source_url,
    r.Notes      = $notes,
    r.Imported_By = "cyber_graph_triage",
    r.Imported_At = datetime()
RETURN source.Name         AS source,
       r.Nature            AS nature,
       target.Name         AS target,
       target.Extended_Name AS target_name
