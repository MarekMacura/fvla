from rdflib import Graph  
  
class RDFStore:  
    """  
    Handles storage of RDF data in Turtle file and Oracle Graph.  
    """  
  
    def __init__(self, backend="turtle", file_path="data/graph.ttl", oracle_config=None):  
        self.backend = backend  
        self.file_path = file_path  
        self.oracle_config = oracle_config  
        self.graph = Graph()  
  
    def load(self):  
        if self.backend == "turtle":  
            try:  
                self.graph.parse(self.file_path, format="turtle")  
            except FileNotFoundError:  
                pass  
        elif self.backend == "oracle":  
            # Placeholder for Oracle RDF loading  
            pass  
  
    def save(self):  
        if self.backend == "turtle":  
            self.graph.serialize(self.file_path, format="turtle")  
        elif self.backend == "oracle":  
            # Placeholder for Oracle RDF saving  
            pass  
  
    def add_graph(self, g):  
        for triple in g:  
            self.graph.add(triple)  