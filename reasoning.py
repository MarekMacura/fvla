# reasoning.py  
from rdflib import Namespace  
from rdflib.namespace import RDF, OWL  
from owlrl import DeductiveClosure, OWLRL_Semantics  
  
soft = Namespace("http://example.org/software#")  
cve = Namespace("http://example.org/cve#")  
  
def apply_reasoning(graph):  
    """  
    Apply OWL RL reasoning and custom SWRL-like rules to the vulnerability graph.  
    """  
    print("[Reasoning] Starting OWL RL inference...")  
    DeductiveClosure(OWLRL_Semantics).expand(graph)  
    print("[Reasoning] OWL RL inference done.")  
  
    # Custom rule 1: propagate vulnerabilities via sameAs  
    print("[Reasoning] Applying sameAs vulnerability propagation...")  
    for s1, _, s2 in graph.triples((None, OWL.sameAs, None)):  
        for v in graph.subjects(cve.affects, s1):  
            graph.add((v, cve.affects, s2))  
        for v in graph.subjects(cve.affects, s2):  
            graph.add((v, cve.affects, s1))  
  
    # Custom rule 2: dependency vulnerability propagation  
    print("[Reasoning] Propagating vulnerabilities via dependencies...")  
    for s1, _, s2 in graph.triples((None, soft.dependsOn, None)):  
        for v in graph.subjects(cve.affects, s2):  
            graph.add((v, cve.affects, s1))  
  
    # Custom rule 3: version-based vulnerability inference (simple string compare)  
    print("[Reasoning] Inferring vulnerabilities based on version ranges...")  
    for s in graph.subjects(RDF.type, soft.Software):  
        ver = graph.value(s, soft.version)  
        if ver:  
            for v in graph.subjects(RDF.type, cve.Vulnerability):  
                minv = graph.value(v, cve.minVersion)  
                maxv = graph.value(v, cve.maxVersion)  
                if minv and maxv:  
                    try:  
                        # naive lexicographic compare  
                        if str(minv) <= str(ver) <= str(maxv):  
                            graph.add((v, cve.affects, s))  
                    except Exception as e:  
                        pass  
  
    print("[Reasoning] Reasoning step complete. Graph now has", len(graph), "triples.")  
    return graph  