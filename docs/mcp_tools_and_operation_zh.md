# Cyber Graph Triage MCP 工具與運作說明

本文說明此 MCP server 對外提供的工具、各工具的輸入與輸出、內部如何查詢 Neo4j 知識圖譜，以及使用結果時必須保留的限制。此服務定位為 SOC triage 的 Mode A，也就是以固定 Cypher 查詢提供可重現、可審查的圖譜查詢能力。

## 1. 系統定位

此 MCP server 的名稱為 `cyber-graph-triage`，入口檔案是 `server.py`。它使用 FastMCP 暴露工具，工具本身再呼叫 `cyber_graph_triage/` 內的 Python 函式。實際資料來源是 Neo4j 中的 GraphKer-style cybersecurity knowledge graph。

整體流程如下：

```text
MCP client
  -> server.py / FastMCP tool wrapper
  -> cyber_graph_triage.tools 或 triage_service
  -> Neo4jClient
  -> Neo4j graph
  -> Python 清理與組裝輸出
  -> MCP JSON response
```

此架構有一個重要特性：MCP server 只是 thin wrapper。CLI、測試與 MCP 工具共用同一批查詢函式，因此行為應保持一致。

## 2. 連線與資料來源

Neo4j 連線由 `cyber_graph_triage/neo4j_client.py` 管理。Driver 採 lazy initialization，第一次工具查詢時才建立連線並呼叫 `verify_connectivity()`。

連線設定來自 `.env` 或環境變數：

```text
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<password>
NEO4J_DATABASE=neo4j
```

需要精確理解的一點是，`NEO4J_URI` 會直接交給官方 Neo4j Python driver。此 MCP server 不會讓 Python driver 自行支援 WebSocket URI。

### 2.1 支援的 Neo4j URI scheme

目前可接受的 URI scheme 為：

| Scheme | 用途 |
|---|---|
| `bolt://` | 直接連到單一 Neo4j 實例，未加密 |
| `bolt+s://` | 直接連到單一 Neo4j 實例，TLS 且要求 CA 簽發憑證 |
| `bolt+ssc://` | 直接連到單一 Neo4j 實例，TLS 且接受 self-signed 憑證 |
| `neo4j://` | 使用 routing 的 Neo4j 連線 |
| `neo4j+s://` | routing + TLS |
| `neo4j+ssc://` | routing + TLS，自簽憑證可接受 |

`ws://` 與 `wss://` 不能直接填入 `NEO4J_URI`。若設定為 `wss://graphker.lab.114514.my.id:443/`，Python driver 會在連線前拒絕該 scheme。這不是 Cloudflare 或遠端 Neo4j 的錯誤，而是 driver API 的邊界。

### 2.2 Cloudflare 連線選項

若目標是透過 Cloudflare 連到遠端 Neo4j，建議先區分三種模式：

| 模式 | MCP server 看到的 URI | 適用情境 |
|---|---|---|
| Cloudflare Access / Tunnel TCP | `bolt://127.0.0.1:<local-port>` | 客戶端可執行 `cloudflared access tcp` |
| Cloudflare Spectrum | `bolt://`、`bolt+s://`、`neo4j://` 或 `neo4j+s://` | 需要公開原生 TCP 入口 |
| 本地 TCP-to-WebSocket bridge | `bolt://127.0.0.1:17687` | 遠端只有 WebSocket-to-Bolt 入口，例如 Neo4j Browser 使用的路徑 |

Cloudflare Access / Tunnel TCP 範例：

```text
cloudflared access tcp --hostname neo4j.example.com --url 127.0.0.1:17687
NEO4J_URI=bolt://127.0.0.1:17687
```

在此模式下，WebSocket 或其他 Cloudflare 封裝由 `cloudflared` 處理，Python driver 仍然只看到本機 TCP。

### 2.3 實驗性 TCP-to-WebSocket bridge

如果遠端已經提供類似 Neo4j Browser 使用的 Bolt-over-WebSocket 入口，但本地 MCP server 仍使用 Python driver，可以啟動本機 bridge。此方案的目的不是讓 Python driver 支援 `wss://`，而是讓 Python driver 連到本機 `bolt://` listener，再由 bridge 將 Bolt bytes 封裝成 WebSocket binary frames。

`.env` 範例：

```text
NEO4J_URI=bolt://127.0.0.1:17687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<password>
NEO4J_DATABASE=neo4j
NEO4J_WS_BRIDGE_TARGET=wss://graphker.lab.114514.my.id:443/
NEO4J_WS_BRIDGE_LISTEN_HOST=127.0.0.1
NEO4J_WS_BRIDGE_LISTEN_PORT=17687
```

啟動順序：

```bash
uv run neo4j-ws-bolt-bridge
uv run python -m cyber_graph_triage.cli schema
uv run python server.py --transport stdio
```

資料流如下：

```text
Neo4j Python driver
  -> local TCP 127.0.0.1:17687
  -> cyber_graph_triage.ws_bolt_bridge
  -> wss://graphker.lab.114514.my.id:443/
  -> remote WebSocket-to-Bolt proxy
  -> Neo4j Bolt endpoint
```

目前已用 `schema_introspection` 與 `lookup-cve CVE-2023-5457` 驗證此路徑可以完成查詢。需要注意的是，此方案假設遠端 WebSocket endpoint 會將 WebSocket binary payload 原樣轉送到 Neo4j Bolt。若遠端需要額外 path、header、subprotocol 或 Cloudflare Access token，目前 bridge 尚未加入這些擴充設定。

如果 Neo4j 無法連線，多數工具會回傳結構化錯誤，而不是直接讓 MCP server 崩潰。例如 `lookup_cve` 會回傳 `found: false` 與 `error` 欄位。

## 3. 圖譜 Schema 假設

工具查詢假設 Neo4j 內存在下列主要節點與關係：

| 類型 | 用途 |
|---|---|
| `CVE` | 漏洞紀錄 |
| `CWE` | 弱點分類 |
| `CPE` | 受影響產品或平台 |
| `CAPEC` | 攻擊模式 |
| `ATTACK` | MITRE ATT&CK technique |
| `CVSS_3`, `CVSS_2` | CVSS 分數節點 |
| `Reference_Data` | advisory、patch 或外部參考 |
| `Mitigation` | CWE mitigation |
| `Consequence` | CWE consequence |

主要關係如下：

```text
(CVE)-[:Problem_Type]->(CWE)
(CVE)-[:applicableIn]->(CPE)
(CVE)-[:CVSS3_Impact]->(CVSS_3)
(CVE)-[:CVSS2_Impact]->(CVSS_2)
(CVE)-[:referencedBy]->(Reference_Data)
(CWE)-[:Related_Weakness]->(CWE)
(CWE)-[:RelatedAttackPattern]->(CAPEC)
(CWE)-[:hasMitigation]->(Mitigation)
(CWE)-[:hasConsequence]->(Consequence)
(CAPEC)-[:Mapped_Attack]->(ATTACK)
```

請注意，CAPEC 到 ATT&CK 的覆蓋率本來就可能很稀疏。沒有 ATT&CK path 不等於沒有風險，也不等於攻擊不存在。

## 4. MCP 工具總覽

此 MCP server 對外提供六個工具：

| 工具 | 主要用途 |
|---|---|
| `lookup_cve` | 查詢單一 CVE 的描述、CVSS、CWE、CPE 與 references |
| `lookup_cwe` | 查詢單一 CWE 的弱點資訊、相關 CWE、CAPEC、mitigations 與 consequences |
| `trace_cve_to_attack` | 追蹤 CVE -> CWE -> CAPEC -> ATT&CK 的知識圖譜 evidence path |
| `lookup_cpe_vulnerabilities` | 以 CPE URI substring 查詢產品或供應商相關 CVE |
| `triage_alert` | 從自由文字 alert 中抽取 CVE/CWE/product hint，整合上述查詢 |
| `schema_introspection` | 檢查 Neo4j labels、relationship types 與核心節點/邊數 |

## 5. `lookup_cve`

### 用途

查詢單一 CVE 的基礎漏洞資訊，包括描述、發布與修改日期、弱點分類、CVSS 分數、受影響 CPE 與外部參考。

### 輸入

```json
{
  "cve_id": "CVE-2021-34709"
}
```

`cve_id` 會被轉成大寫並去除前後空白。

### 查詢方式

此工具使用 `cyber_graph_triage/cypher/lookup_cve_graphker.cypher`。核心查詢邏輯是：

```text
MATCH (cve:CVE {Name: $cve_id})
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cve)-[:CVSS3_Impact]->(cvss3:CVSS_3)
OPTIONAL MATCH (cve)-[:CVSS2_Impact]->(cvss2:CVSS_2)
OPTIONAL MATCH (cve)-[:applicableIn]->(cpe:CPE)
OPTIONAL MATCH (cve)-[:referencedBy]->(ref:Reference_Data)
```

查詢使用參數化 `$cve_id`，不是由使用者提供任意 Cypher。CPE 與 references 在 Cypher 層各自限制為最多 20 筆。

### 輸出

成功時：

```json
{
  "found": true,
  "cve": "CVE-2021-34709",
  "description": "...",
  "published_date": "...",
  "last_modified_date": "...",
  "cwes": ["CWE-..."],
  "cvss3": [
    {
      "score": 7.8,
      "severity": "HIGH",
      "vector": "CVSS:3.1/..."
    }
  ],
  "cvss2": [],
  "cpes": ["cpe:2.3:..."],
  "references": [
    {
      "url": "https://...",
      "source": "...",
      "name": "..."
    }
  ]
}
```

找不到資料時：

```json
{
  "found": false,
  "cve": "CVE-2021-34709"
}
```

連線或執行失敗時：

```json
{
  "found": false,
  "cve": "CVE-2021-34709",
  "error": "Cannot connect to Neo4j ..."
}
```

## 6. `lookup_cwe`

### 用途

查詢單一 CWE 的弱點描述、抽象層級、結構、狀態、相關 CWE、CAPEC mapping、mitigations 與 consequences。

### 輸入

```json
{
  "cwe_id": "CWE-692"
}
```

`cwe_id` 會被轉成大寫並去除前後空白。

### 查詢方式

此工具使用 `cyber_graph_triage/cypher/lookup_cwe_graphker.cypher`。核心查詢邏輯是：

```text
MATCH (cwe:CWE {Name: $cwe_id})
OPTIONAL MATCH (cwe)-[rw:Related_Weakness]->(other:CWE)
OPTIONAL MATCH (cwe)-[:RelatedAttackPattern]->(capec:CAPEC)
OPTIONAL MATCH (cwe)-[:hasMitigation]->(mit:Mitigation)
OPTIONAL MATCH (cwe)-[:hasConsequence]->(con:Consequence)
```

`Related_Weakness` 的 `Nature` 不會被過濾。這表示 `ChildOf`、`ParentOf`、`CanPrecede`、`StartsWith` 等關係都會原樣回傳。對 Chain CWE 進行分析時，應特別檢查 `StartsWith`，但不能假設只有 `StartsWith` 重要。

### 輸出

成功時：

```json
{
  "found": true,
  "cwe": "CWE-692",
  "name": "...",
  "description": "...",
  "abstraction": "Compound",
  "structure": "Chain",
  "status": "Draft",
  "related_cwes": [
    {
      "nature": "StartsWith",
      "target": "CWE-184",
      "target_name": "..."
    }
  ],
  "capecs": [
    {
      "capec": "CAPEC-80",
      "name": "..."
    }
  ],
  "mitigations": ["..."],
  "consequences": ["Confidentiality", "Integrity"]
}
```

找不到或失敗時，格式與 `lookup_cve` 類似，使用 `found: false`，並可能包含 `error`。

## 7. `trace_cve_to_attack`

### 用途

建立 CVE 到 ATT&CK 的 evidence path。此工具是圖譜關聯推導，不是攻擊觀測結果。

### 輸入

```json
{
  "cve_id": "CVE-2023-5457"
}
```

### 查詢方式

此工具分成兩段：

第一段使用 `cyber_graph_triage/cypher/trace_cve_to_attack_graphker.cypher` 查詢：

```text
MATCH (cve:CVE {Name: $cve_id})
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cwe)-[:RelatedAttackPattern]->(capec:CAPEC)
```

第二段由 `_try_attack_lookup()` 根據查到的 CAPEC 名稱，嘗試查詢 CAPEC 到 ATT&CK 的 mapping。它會在固定 label 與 relationship 候選集合中嘗試：

```text
labels: ATTACK, Technique, ATTACK_Technique, Attack_Technique
relationships: Mapped_Attack, MAPS_TO_ATTACK, USES_ATTACK_TECHNIQUE, mapsToTechnique, RelatedTechnique
```

雖然第二段會組裝 Cypher 字串，但 label 與 relationship 來自程式內固定常數，不是使用者輸入。使用者可控的 CAPEC 名稱仍以 `$capec_names` 參數傳入。

### 輸出

成功且有 path 時：

```json
{
  "found": true,
  "cve": "CVE-2023-5457",
  "paths": [
    {
      "source": "CVE-2023-5457",
      "steps": [
        {"label": "CVE", "id": "CVE-2023-5457"},
        {"relationship": "Problem_Type"},
        {"label": "CWE", "id": "CWE-1269", "name": "..."},
        {"relationship": "RelatedAttackPattern"},
        {"label": "CAPEC", "id": "CAPEC-439", "name": "..."},
        {"relationship": "Mapped_Attack"},
        {"label": "ATTACK", "id": "1195", "name": "T1195 - Supply Chain Compromise"}
      ],
      "confidence": "knowledge_graph_mapping",
      "limitations": [
        "This path represents a knowledge-graph mapping, not observed attacker behavior.",
        "CAPEC/ATT&CK associations are derived from NVD/MITRE data and may not reflect the specific exploitation technique used in this alert."
      ],
      "cwe": "CWE-1269",
      "cwe_name": "...",
      "capec": "CAPEC-439",
      "capec_name": "...",
      "attack": {
        "id": "1195",
        "name": "T1195 - Supply Chain Compromise",
        "relation": "Mapped_Attack"
      }
    }
  ],
  "warnings": []
}
```

如果有 CWE/CAPEC 但沒有 ATT&CK mapping，`attack` 會是 `null`，並可能在 `warnings` 中出現：

```text
No ATT&CK mapping found from CAPEC nodes. Check technique labels and relationship names.
```

分析時必須保留 `confidence` 與 `limitations`。不能把此結果描述成「攻擊者已使用該 ATT&CK technique」。

## 8. `lookup_cpe_vulnerabilities`

### 用途

用產品或供應商關鍵字查詢 CPE URI 中包含該字串的 CVE。此工具適合做產品面 vulnerability inventory 初查，但不是精準資產比對。

### 輸入

```json
{
  "keyword": "apache:struts",
  "limit": 100
}
```

`keyword` 最少 3 個字元。過短關鍵字會直接回傳錯誤，不執行 Neo4j 查詢。

### 查詢方式

此工具的 Cypher 直接寫在 `cyber_graph_triage/tools/lookup_cpe_vulnerabilities.py` 中。核心查詢邏輯是：

```text
MATCH (cve:CVE)-[a:applicableIn]->(cpe:CPE)
WHERE toLower(cpe.uri) CONTAINS toLower($keyword)
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cve)-[:CVSS3_Impact]->(cvss3:CVSS_3)
RETURN cve, cpe, vulnerable, score, severity, cwes
ORDER BY score DESC
LIMIT $limit
```

實作上會以 `limit + 1` 查詢，藉此判斷結果是否被截斷。若查回筆數大於 `limit`，回傳 `truncated: true`。

### 輸出

```json
{
  "keyword": "apache:struts",
  "count": 87,
  "truncated": false,
  "warning": "Results are based on substring match of CPE URI strings, not a precise CPE inventory match. Validate affected assets separately.",
  "results": [
    {
      "cve": "CVE-2017-5638",
      "cpe": "cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*",
      "vulnerable": true,
      "score": 10.0,
      "severity": "CRITICAL",
      "cwes": ["CWE-20"]
    }
  ]
}
```

使用此結果時應保持懷疑。`keyword` 是 substring match，不是 CMDB 或 EDR inventory confirmation。必須另外驗證資產實際版本、edition、configuration 與 exposure。

## 9. `triage_alert`

### 用途

從自由文字 alert 中抽取 CVE、CWE 與可選的產品提示，然後自動整合多個工具，產出 SOC triage 結果。

### 輸入

```json
{
  "alert_text": "Possible exploitation of CVE-2021-34709 observed on Cisco device",
  "product_hint": "cisco:ios_xr",
  "asset_hint": "router-01",
  "include_report": true
}
```

欄位說明：

| 欄位 | 說明 |
|---|---|
| `alert_text` | 原始 alert 或 incident 描述 |
| `product_hint` | 可選。若提供，會作為 CPE keyword 查詢 |
| `asset_hint` | 可選。僅放入輸入脈絡，不會查詢圖譜資產 |
| `include_report` | 若為 `true`，額外產生 Markdown report |

### 抽取與查詢流程

`triage_alert` 的流程位於 `cyber_graph_triage/triage_service.py`：

1. 使用 regex 從 `alert_text` 抽取 CVE ID，格式為 `CVE-\d{4}-\d{4,7}`。
2. 使用 regex 抽取 CWE ID，格式為 `CWE-\d{1,5}`。
3. 若有 `product_hint`，直接用它作為 CPE keyword。
4. 若沒有 `product_hint`，從文字中嘗試抽取 `vendor:product` 形式的 keyword。
5. 對每個 CVE 呼叫 `lookup_cve` 與 `trace_cve_to_attack`。
6. 對每個 CWE 呼叫 `lookup_cwe`。
7. 對每個 CPE keyword 呼叫 `lookup_cpe_vulnerabilities`。
8. 彙整 `evidence_paths` 與三層 assessment。
9. 若 `include_report=true`，呼叫 `format_triage_report()` 產生 Markdown 報告。

### 輸出

```json
{
  "mode": "SOC_TRIAGE",
  "input": {
    "alert_text": "...",
    "product_hint": "cisco:ios_xr",
    "asset_hint": "router-01"
  },
  "extracted": {
    "cves": ["CVE-2021-34709"],
    "cwes": [],
    "product_hint": "cisco:ios_xr",
    "asset_hint": "router-01"
  },
  "results": {
    "cves": {
      "CVE-2021-34709": {}
    },
    "cve_traces": {
      "CVE-2021-34709": {}
    },
    "cwes": {},
    "product_vulnerabilities": []
  },
  "assessment": {
    "observed_signals": [],
    "graph_context_signals": [],
    "prioritization_signals": [],
    "warnings": [],
    "limitations": []
  },
  "evidence_paths": [],
  "report": "# SOC Triage Report\n..."
}
```

### Assessment 三層含義

| 層級 | 來源 | 用途 |
|---|---|---|
| `observed_signals` | alert text 中直接抽取到的內容 | 說明 analyst 實際提供了什麼訊號 |
| `graph_context_signals` | 圖譜 traversal 結果 | 提供 CAPEC/ATT&CK 背景脈絡，但不是 observed TTP |
| `prioritization_signals` | CVSS、severity、patch/advisory references | 協助排序處理優先級 |

如果 alert text 沒有 CVE 或 CWE，這個工具目前不會做語意搜尋。它會在 `limitations` 中提示需要 Mode B 或其他 semantic search 能力。

## 10. `schema_introspection`

### 用途

檢查目前 Neo4j graph 的 schema 是否符合工具預期。當查詢結果異常為空、缺少 ATT&CK path，或懷疑 import 不完整時，應先呼叫此工具。

### 輸入

無輸入。

```json
{}
```

### 查詢方式

此工具會呼叫：

```text
CALL db.labels()
CALL db.relationshipTypes()
```

並額外計算核心節點與邊數，例如：

```text
MATCH (n:CVE) RETURN count(n) AS c
MATCH (:CVE)-[:Problem_Type]->(:CWE) RETURN count(*) AS c
MATCH (:CAPEC)-[:Mapped_Attack]->(:ATTACK) RETURN count(*) AS c
```

### 輸出

```json
{
  "labels": ["ATTACK", "CAPEC", "CPE", "CVE", "CWE"],
  "relationship_types": ["Problem_Type", "RelatedAttackPattern", "Mapped_Attack"],
  "node_counts": {
    "CVE": 319626,
    "CWE": 1384,
    "CAPEC": 693,
    "ATTACK": 222,
    "CPE": 1502334
  },
  "edge_counts": {
    "CVE_to_CWE": 334891,
    "CWE_to_CAPEC": 1212,
    "CAPEC_to_ATTACK": 308,
    "CVE_to_CPE": 2795461
  },
  "health_warnings": []
}
```

若 `CAPEC_to_ATTACK` 為 0，工具會提示 ATT&CK trace 將無法取得 mapping。這是 schema 或資料匯入層面的問題，不應被解讀為所有 CVE 都沒有攻擊技術關聯。

## 11. 資料清理與去重行為

各工具在 Cypher 查詢後還會做一層 Python 清理：

| 工具 | 清理行為 |
|---|---|
| `lookup_cve` | 移除空值、CVSS 依 vector 或 score 去重、references 依 URL 去重、description list 轉成單一字串 |
| `lookup_cwe` | related CWE 依 `(nature, target)` 去重、CAPEC 依 CAPEC ID 去重、consequence 攤平並排序去重 |
| `trace_cve_to_attack` | 組裝階段式 `steps`，補上固定 `confidence` 與 `limitations` |
| `lookup_cpe_vulnerabilities` | score 轉 float、移除空 CWE、以 `limit + 1` 判斷 truncated |
| `triage_alert` | 彙整各工具輸出，生成 observed、graph context、prioritization 三層 assessment |

## 12. 安全與解讀限制

使用此 MCP server 時，應遵守下列限制：

1. 不要把 CAPEC 或 ATT&CK mapping 說成已觀測到的攻擊行為。
2. 不要因為沒有 ATT&CK mapping 就推論沒有風險。CAPEC -> ATT&CK 覆蓋本來就有限。
3. 不要把 CPE substring match 當成精準資產命中。它只是產品名稱或供應商字串比對。
4. 不要期待此服務做 free-form Cypher、semantic search、asset confirmation、KEV lookup 或即時 threat intelligence。
5. 對於 `triage_alert`，如果輸入文字沒有 CVE/CWE，Mode A 的能力會非常有限。
6. Evidence path 是 knowledge graph inference，需要與 alert telemetry、asset inventory、版本資訊、patch 狀態及實際 exploitation evidence 分開判讀。

## 13. 建議使用順序

若已有特定 CVE：

```text
lookup_cve
trace_cve_to_attack
必要時再 lookup_cwe
```

若已有特定 CWE：

```text
lookup_cwe
```

若只有產品或供應商名稱：

```text
lookup_cpe_vulnerabilities
```

若有完整 alert 文字：

```text
triage_alert(include_report=true)
```

若結果看起來不合理：

```text
schema_introspection
```

## 14. 核心結論

此 MCP server 的核心價值是提供固定、可重現的 cybersecurity knowledge graph 查詢。它能快速把 CVE、CWE、CPE、CAPEC 與 ATT&CK 背景關聯整理成結構化結果，但它不會確認資產是否真的受影響，也不會確認攻擊是否成功。對 SOC triage 而言，它適合提供上下文與優先級訊號，不適合單獨作為 incident conclusion。
