from rdflib import Graph, Literal, RDF, Namespace, URIRef  
from .uri_utils import safe_uri  
  
CVE = Namespace("http://example.org/cve#")  
CPE = Namespace("http://example.org/cpe#")  
  
class CVEIngestor:  
    def __init__(self):  
        self.graph = Graph()  
        self.graph.bind("cve", CVE)  
        self.graph.bind("cpe", CPE)  
  
    def get_graph(self):  
        """Return the RDFLib Graph containing all CVE triples."""  
        return self.graph  
  
    def _parse_cpe(self, cpe_str):  
        parts = cpe_str.split(":")  
        if len(parts) >= 6:  
            return {  
                "part": parts[2],  
                "vendor": parts[3],  
                "product": parts[4],  
                "version": parts[5]  
            }  
        return None  
  
    def ingest_nvd_json(self, nvd_data):  
        for item in nvd_data.get("vulnerabilities", []):  
            cve_data = item.get("cve", {})  
            cve_id = cve_data.get("id")  
            if not cve_id:  
                continue  
  
            cve_uri = URIRef(safe_uri("http://example.org/cve", cve_id))  
            self.graph.add((cve_uri, RDF.type, CVE.Vulnerability))  
            self.graph.add((cve_uri, CVE.cveId, Literal(cve_id)))  
            self.graph.add((cve_uri, CVE.published, Literal(cve_data.get("published"))))  
            self.graph.add((cve_uri, CVE.lastModified, Literal(cve_data.get("lastModified"))))  
  
            # Description  
            descriptions = cve_data.get("descriptions", [])  
            for desc in descriptions:  
                if desc.get("lang") == "en":  
                    self.graph.add((cve_uri, CVE.description, Literal(desc.get("value"))))  
                    break  
  
            # CVSS metrics  
            metrics = cve_data.get("metrics", {})  
            if "cvssMetricV31" in metrics:  
                m = metrics["cvssMetricV31"][0]  
                cvss_data = m.get("cvssData", {})  
                base_score = cvss_data.get("baseScore")  
                severity = cvss_data.get("baseSeverity")  
                if base_score is not None:  
                    self.graph.add((cve_uri, CVE.cvssScore, Literal(base_score)))  
                if severity:  
                    self.graph.add((cve_uri, CVE.severity, Literal(severity)))  
            elif "cvssMetricV30" in metrics:  
                m = metrics["cvssMetricV30"][0]  
                cvss_data = m.get("cvssData", {})  
                base_score = cvss_data.get("baseScore")  
                severity = cvss_data.get("baseSeverity")  
                if base_score is not None:  
                    self.graph.add((cve_uri, CVE.cvssScore, Literal(base_score)))  
                if severity:  
                    self.graph.add((cve_uri, CVE.severity, Literal(severity)))  
  
            # Extract CPE matches  
            for config in cve_data.get("configurations", []):  
                for node in config.get("nodes", []):  
                    for cpe_match in node.get("cpeMatch", []):  
                        criteria = cpe_match.get("criteria")  
                        if criteria:  
                            cpe_uri = URIRef(safe_uri("http://example.org/cpe", criteria))  
                            self.graph.add((cpe_uri, RDF.type, CPE.Platform))  
                            self.graph.add((cve_uri, CVE.affects, cpe_uri))  
                            self.graph.add((cpe_uri, CPE.criteria, Literal(criteria)))  
  
                            parsed = self._parse_cpe(criteria)  
                            if parsed:  
                                self.graph.add((cpe_uri, CPE.vendor, Literal(parsed["vendor"])))  
                                self.graph.add((cpe_uri, CPE.product, Literal(parsed["product"])))  
                                self.graph.add((cpe_uri, CPE.version, Literal(parsed["version"])))  