# MessageGuard — System Architecture (SIH26106)

---

### 1. High-Level Architectural Topology

```mermaid
graph TB
    subgraph ClientLayer["1. Client & Ingestion Layer (Android 14+ / SDK 26-36)"]
        NL["GmailNotificationListenerService<br/>(Notification Interception)"]
        MP["MediaProjectionService<br/>(Circle-to-Scan & Overlay)"]
        OCR["Google ML Kit OCR & Barcode<br/>(Visual Extraction)"]
        VOICE["ThreatVisionVoiceManager<br/>(SpeechRecognizer)"]
        ACT["DetailActivity & MainActivity<br/>(Forensic UI & Reports)"]
    end

    subgraph EdgeML["2. On-Device Intelligence Engine (Local JVM / C++)"]
        PRE["PretrainedThreatEngine"]
        TF1["text_nlp_model.tflite<br/>(Urgency / Phishing Text)"]
        TF2["url_cnn_model.tflite<br/>(Character-Level URL CNN)"]
        ONNX["full_bodmas.onnx<br/>(BODMAS Feature Matrix)"]
        VOCAB["tfidf_vocab.json<br/>(TF-IDF Vocabulary Mapping)"]
    end

    subgraph BackendAPI["3. Forensic Backend Service (FastAPI / Python 3.11)"]
        EP1["POST /api/analyze-trigger"]
        EP2["POST /analyze-email"]
        EP3["POST /api/ingest/raw & /eml"]
        EP4["GET /generate-report/{case_id}"]
        EP5["GET /api/cases & Correlation"]
    end

    subgraph ForensicPipeline["4. Threat Analysis & Forensic Engine"]
        AUTH["verify_authentication_headers<br/>(SPF / DKIM / DMARC)"]
        CONTENT["ContentAnalyzer<br/>(NLP, Link Shorteners, BEC)"]
        RELAY["ThreatIntelService<br/>(Received Chain & Trust Labels)"]
        GEO["GeoIP Resolver<br/>(ip-api + ipwho.is Fallback)"]
        DOMAIN["DomainIntelService<br/>(WHOIS, DNS, MX, Age)"]
    end

    subgraph CorrelationAndStorage["5. Correlation, Campaign & Storage"]
        CASE_DB[(SQLite Database<br/>cases.db / Room History)]
        CORR["CorrelationService<br/>(Cross-Case IOC Matching)"]
        CAMP["CampaignService<br/>(Campaign Clustering)"]
        GRAPH["InvestigationGraphService<br/>(Entity Nodes & Edges)"]
        PDF["ReportLab Service<br/>(Forensic PDF Dossier)"]
    end

    NL -->|Trigger Payload| EP1
    MP --> OCR --> PRE
    PRE --> TF1
    PRE --> TF2
    PRE --> ONNX
    PRE --> VOCAB
    PRE --> ACT

    EP1 --> AUTH
    EP1 --> CONTENT
    EP1 --> RELAY
    RELAY --> GEO
    EP1 --> DOMAIN

    AUTH & CONTENT & RELAY & DOMAIN --> CASE_DB
    CASE_DB --> CORR --> CAMP --> GRAPH
    CASE_DB --> PDF --> EP4
    EP1 --> ACT
```

---

### 2. Component Breakdown

#### A. Android Client Application (`com.messageguard`)
- **Minimum SDK:** 26 (Android 8.0 Oreo)
- **Target SDK:** 34 (Android 14 UpsideDownCake)
- **Compile SDK:** 36 (Android 15+)
- **Concurrency & Architecture:** Kotlin Coroutines (`Dispatchers.IO`, `Dispatchers.Main`), ViewBinding, Room ORM, OkHttp3 with connection pooling and 45s timeouts.
- **Forensic UI:**
  - `MainActivity.kt`: Dashboard with recent threat statistics, quick settings, QR phishing scanner, and file sandbox launcher.
  - `DetailActivity.kt`: Comprehensive forensic dossier viewer displaying risk score, SPF/DKIM/DMARC badges, interactive Leaflet/MapLibre map, hop-by-hop relay sequences, entity graphs, and local PDF export.
  - `OverlayManager.kt`: Draggable floating shield icon with quick verdict pills and Circle-to-Scan trigger.

#### B. FastAPI Backend Service (`backend/`)
- **Framework:** FastAPI 0.115 + Uvicorn ASGI server
- **Endpoints:**
  - `POST /api/analyze-trigger`: Primary notification ingestion endpoint handling direct payload or fetching RFC 822 MIME from Gmail API.
  - `POST /analyze-email`: Headless text analysis endpoint for direct message text.
  - `POST /api/ingest/raw`: Universal RFC 822 pasted raw source ingestion for Outlook, Thunderbird, and IMAP.
  - `POST /api/ingest/eml`: Universal `.eml` / `.msg` file upload ingestion.
  - `GET /generate-report/{case_id}`: Stream ReportLab-generated forensic PDF with SHA-256 seal.
  - `GET /api/cases`: Searchable case repository with configurable retention and privacy redaction.

#### C. Threat Intelligence & Domain Intelligence Services
- **`ThreatIntelService.py`:**
  - Reconstructs chronological transmission paths from top-to-bottom Received headers.
  - Assigns per-hop trust labels: `TRUSTED_RELAY`, `OBSERVED`, `SUSPICIOUS_RELAY`, `POSSIBLY_FORGED`.
  - Filters private subnets (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local, multicast).
  - Resolves earliest reliable public IP with dual-provider fallback (`ip-api.com` primary, `ipwho.is` secondary) and in-memory caching.
- **`DomainIntelService.py`:**
  - Performs non-blocking DNS queries for MX, A, and NS records with 3-second timeouts.
  - Evaluates registrar information, creation timestamps, and newly registered domain (NRD) age (<30 days).

#### D. Storage & Data Persistence
- **On-Device:** SQLite via AndroidX Room (`analysis_history` table), storing verdict history, sender reputation, explainability spans, and risk scores.
- **Backend:** SQLite database (`cases.db`), persisting normalized indicators, cross-case correlations, campaigns, and retention schedules.
