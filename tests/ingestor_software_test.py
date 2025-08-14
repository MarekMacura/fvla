from ingestion.software_ingestor import SoftwareIngestor  
  
ing = SoftwareIngestor()  
ing.ingest_csv("data/installed_software.csv")  
print(list(ing.get_graph())[:5])  