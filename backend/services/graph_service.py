"""
PS106 Threat Vision — Investigation Graph Service
==================================================
Builds a forensic relationship graph (nodes & edges) for analyzed cases:
Nodes:
  - CASE (the incident)
  - SENDER (email address with privacy masking)
  - DOMAIN (sender domain / MX / WHOIS)
  - IP (originating / relay infrastructure)
  - URL (landing URLs)
  - ATTACHMENT (SHA-256 payload)
  - CAMPAIGN (if assigned)
Edges:
  - SENT_BY, USES_DOMAIN, ROUTED_THROUGH, CONTAINS_URL, HAS_ATTACHMENT, MEMBER_OF_CAMPAIGN, SHARES_INFRASTRUCTURE
Bounded to maximum 50 nodes to guarantee fast mobile/API rendering.
"""

import os
import sqlite3
import logging
from typing import Dict, Any, List

logger = logging.getLogger("ps106.graph")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports_storage", "cases.db")


class InvestigationGraphService:
    """Additive graph data model generator for case investigation."""

    @staticmethod
    def _mask_email(email: str) -> str:
        """Apply privacy masking to email for node display."""
        if not email or "@" not in email:
            return email
        parts = email.split("@")
        user = parts[0]
        domain = parts[1]
        masked_user = user[0] + "***" if len(user) > 1 else "***"
        return f"{masked_user}@{domain}"

    def build_case_graph(
        self,
        case_id: str,
        case_data: Dict[str, Any],
        correlation_result: Dict[str, Any] = None,
        campaign_info: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Construct a structured node/edge graph from real case evidence and correlation signals.
        Returns: {"nodes": [...], "edges": [...], "summary": str}
        """
        nodes = []
        edges = []
        node_ids = set()

        def add_node(nid: str, ntype: str, label: str, masked_label: str = None, metadata: dict = None):
            if nid not in node_ids and len(nodes) < 50:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "type": ntype,
                    "label": label,
                    "masked_label": masked_label or label,
                    "metadata": metadata or {},
                })

        def add_edge(source: str, target: str, rel: str, confidence: str = "HIGH", evidence: str = ""):
            if source in node_ids and target in node_ids and len(edges) < 80:
                edges.append({
                    "source": source,
                    "target": target,
                    "relationship": rel,
                    "confidence": confidence,
                    "evidence": evidence,
                })

        # 1. Root Node: CASE
        verdict = case_data.get("verdict") or "UNKNOWN"
        risk_score = case_data.get("risk_score") or 0
        case_node_id = f"case:{case_id}"
        add_node(case_node_id, "CASE", case_id, case_id, {"verdict": verdict, "risk_score": risk_score})

        # 2. SENDER Node
        sender = case_data.get("email_metadata", {}).get("sender") or case_data.get("sender") or ""
        if sender:
            sender_id = f"sender:{sender.lower()}"
            masked = self._mask_email(sender)
            add_node(sender_id, "SENDER", sender, masked)
            add_edge(case_node_id, sender_id, "SENT_BY", "HIGH", "Header envelope From")

            # 3. DOMAIN Node
            if "@" in sender:
                dom = sender.split("@")[-1].strip(">").strip().lower()
                dom_id = f"domain:{dom}"
                add_node(dom_id, "DOMAIN", dom, dom)
                add_edge(sender_id, dom_id, "USES_DOMAIN", "HIGH", "RFC 5322 domain part")

        # 4. ORIGIN / RELAY IP Node
        orig_ip = case_data.get("geoip_data", {}).get("relay_chain_data", {}).get("earliest_reliable_observed_ip") \
                  or case_data.get("earliest_reliable_observed_ip")
        if orig_ip and orig_ip != "ORIGIN_NOT_DETERMINABLE":
            ip_id = f"ip:{orig_ip}"
            add_node(ip_id, "IP", orig_ip, orig_ip, {"type": "Observed Infrastructure"})
            add_edge(case_node_id, ip_id, "ROUTED_THROUGH", "HIGH", "Earliest reliable observed relay hop")

        # 5. URL Nodes
        url_analysis = case_data.get("content_analysis", {}).get("url_analysis", [])
        for u in url_analysis[:5]:
            url_str = u.get("url") or ""
            domain = u.get("domain") or ""
            if domain:
                u_id = f"url_domain:{domain.lower()}"
                add_node(u_id, "URL", domain, domain, {"suspicious": u.get("is_suspicious", False)})
                add_edge(case_node_id, u_id, "CONTAINS_URL", "HIGH", "Extracted from message body")

        # 6. ATTACHMENT Nodes
        attachments = case_data.get("content_analysis", {}).get("attachments", [])
        for att in attachments[:3]:
            fname = att.get("filename") or "attachment"
            sha256 = att.get("sha256") or ""
            if sha256:
                att_id = f"attachment:{sha256[:16]}"
                add_node(att_id, "ATTACHMENT", fname, fname, {"sha256": sha256})
                add_edge(case_node_id, att_id, "HAS_ATTACHMENT", "HIGH", "MIME payload attachment")

        # 7. CAMPAIGN Node
        if campaign_info:
            c_id = campaign_info.get("campaign_id")
            c_name = campaign_info.get("campaign_name") or c_id
            if c_id:
                camp_node_id = f"campaign:{c_id}"
                add_node(camp_node_id, "CAMPAIGN", c_name, c_name, {"confidence": campaign_info.get("confidence")})
                add_edge(case_node_id, camp_node_id, "MEMBER_OF_CAMPAIGN", campaign_info.get("confidence", "MEDIUM"), campaign_info.get("explanation", ""))

        # 8. Add Related Case nodes and cross-edges from correlation
        if correlation_result:
            for rel in correlation_result.get("relationships", [])[:6]:
                target_cid = rel.get("target_case_id")
                if target_cid:
                    t_node_id = f"case:{target_cid}"
                    add_node(t_node_id, "CASE", target_cid, target_cid, {"verdict": rel.get("verdict")})
                    add_edge(case_node_id, t_node_id, rel.get("relationship_type", "RELATED_TO"), rel.get("confidence", "MEDIUM"), rel.get("explanation", ""))

        return {
            "case_id": case_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "summary": f"Investigation graph constructed with {len(nodes)} nodes and {len(edges)} forensic relationships."
        }
