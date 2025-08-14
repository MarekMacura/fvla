from ingestion.nvd_ingestor import NVDIngestor  
from ingestion.software_ingestor import SoftwareIngestor  
from ingestion.cve_ingestor import CVEIngestor  
from ingestion.rdf_store import RDFStore  
from ingestion.fuzzy_linker import link_fuzzy_matches  
from ui.dashboard import Dashboard  
  
def main():  
    # Step 1: Fetch NVD CVE feed  
    nvd = NVDIngestor()  
    nvd.update_feed(2025)  
    cve_json = nvd.load_feed(2025)  
  
    # Step 2: Installed software RDF  
    sw_ingestor = SoftwareIngestor()  
    sw_ingestor.ingest_csv("data/installed_software.csv")  
  
    # Step 3: CVE RDF  
    cve_ingestor = CVEIngestor()  
    cve_ingestor.ingest_nvd_json(cve_json)  
  
    # Step 4: Store RDF  
    store = RDFStore(backend="turtle", file_path="data/graph.ttl")  
    store.load()  
    store.add_graph(sw_ingestor.get_graph())  
    store.add_graph(cve_ingestor.get_graph())  

    
  
    # Step 5: Fuzzy link matches during ingestion  
    link_fuzzy_matches(store, threshold=0.85)  
  
    store.save()  
  
    # Step 6: Launch dashboard  
    dash = Dashboard(store.graph)  
    dash.run()  
  
if __name__ == "__main__":  
    main()  