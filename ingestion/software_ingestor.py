import csv  
from rdflib import Graph, Literal, RDF, Namespace, URIRef  
from .uri_utils import safe_uri  
  
SOFT = Namespace("http://example.org/software#")  
  
class SoftwareIngestor:  
    """  
    Ingests installed software list from CSV into RDF.  
    CSV format: vendor,product,version  
    """  
    def __init__(self):  
        self.graph = Graph()  
        self.graph.bind("soft", SOFT)  
  
    def ingest_csv(self, file_path):  
        with open(file_path, newline='', encoding='utf-8') as csvfile:  
            reader = csv.DictReader(csvfile, fieldnames=["vendor", "product", "version"])  
            for row in reader:  
                uri = URIRef(safe_uri("http://example.org/software", row["vendor"], row["product"], row["version"]))  
                self.graph.add((uri, RDF.type, SOFT.Software))  
                self.graph.add((uri, SOFT.vendor, Literal(row["vendor"])))  
                self.graph.add((uri, SOFT.product, Literal(row["product"])))  
                self.graph.add((uri, SOFT.version, Literal(row["version"])))  
  
    def get_graph(self):  
        return self.graph  