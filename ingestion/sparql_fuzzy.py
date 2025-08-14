from rdflib import Namespace, Literal  
from rdflib.plugins.sparql.operators import custom_function  
import difflib  
  
FUZZY = Namespace("http://example.org/fuzzy#")  
  
@custom_function(FUZZY.similarity)  
def sparql_fuzzy_similarity(a, b):  
    """  
    SPARQL function fuzzy:similarity(?str1, ?str2) -> float literal  
    """  
    s1 = str(a)  
    s2 = str(b)  
    score = difflib.SequenceMatcher(None, s1.lower(), s2.lower()).ratio()  
    return Literal(score)  