from urllib.parse import quote  
  
def safe_uri(base, *parts):  
    """  
    Create a safe RDF URI by encoding each part.  
    Example: safe_uri("http://example.org/software", "Apache", "HTTP Server", "2.4.54")  
    """  
    encoded_parts = [quote(str(p).strip().replace(" ", "_")) for p in parts]  
    return f"{base}/{'_'.join(encoded_parts)}"  