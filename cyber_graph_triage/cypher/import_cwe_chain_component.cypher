MATCH (source:CWE {Name: $source})
MATCH (target:CWE {Name: $target})
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
