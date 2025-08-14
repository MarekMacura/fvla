from rdflib import URIRef, Literal, Namespace  
import difflib  
  
CVE = Namespace("http://example.org/cve#")  
  
def fuzzy_score(a, b):  
    return difflib.SequenceMatcher(None, str(a).lower(), str(b).lower()).ratio()  
  
def link_fuzzy_matches(store, threshold=0.85):  
    """  
    Precompute fuzzy matches between installed software and CPE entries.  
    Add triples: Software -> cve:possibleVulnerability -> CPE  
    """  
    g = store.graph  
  
    # Get installed software  
    software_list = []  
    for sw_uri in g.subjects(predicate=None, object=None):  
        if (sw_uri, None, None) in g and (sw_uri, None, None) != (None, None, None):  
            vendor = g.value(sw_uri, URIRef("http://example.org/software#vendor"))  
            product = g.value(sw_uri, URIRef("http://example.org/software#product"))  
            version = g.value(sw_uri, URIRef("http://example.org/software#version"))  
            if vendor and product:  
                software_list.append({  
                    "uri": sw_uri,  
                    "vendor": str(vendor),  
                    "product": str(product),  
                    "version": str(version) if version else ""  
                })  
  
    # Get CPE entries with parsed vendor/product  
    cpe_list = []  
    for cpe_uri in g.subjects(predicate=URIRef("http://example.org/cpe#vendor")):  
        cpe_vendor = g.value(cpe_uri, URIRef("http://example.org/cpe#vendor"))  
        cpe_product = g.value(cpe_uri, URIRef("http://example.org/cpe#product"))  
        if cpe_vendor and cpe_product:  
            cpe_list.append({  
                "uri": cpe_uri,  
                "vendor": str(cpe_vendor),  
                "product": str(cpe_product)  
            })  
  
    # Match software to CPE  
    for sw in software_list:  
        for cpe in cpe_list:  
            v_score = fuzzy_score(sw["vendor"], cpe["vendor"])  
            p_score = fuzzy_score(sw["product"], cpe["product"])  
            score = (v_score + p_score) / 2  
            if score >= threshold:  
                # Link SW to CPE  
                g.add((sw["uri"], CVE.possibleVulnerability, cpe["uri"]))  
                g.add((sw["uri"], CVE.matchScore, Literal(score)))  
  
                # Also link SW to CVEs that affect this CPE  
                for cve_uri in g.subjects(predicate=CVE.affects, object=cpe["uri"]):  
                    g.add((sw["uri"], CVE.possibleVulnerability, cve_uri))  
                    g.add((cve_uri, CVE.matchScore, Literal(score)))  