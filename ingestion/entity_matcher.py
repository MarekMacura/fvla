import difflib  
  
class EntityMatcher:  
    """  
    Matches installed software with CPE criteria using fuzzy matching.  
    """  
  
    def __init__(self, threshold=0.8):  
        self.threshold = threshold  
  
    def fuzzy_match(self, a, b):  
        return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()  
  
    def match_software_to_cpe(self, software_list, cpe_list):  
        matches = []  
        for sw in software_list:  
            for cpe in cpe_list:  
                score = self.fuzzy_match(f"{sw['vendor']} {sw['product']}", cpe)  
                if score >= self.threshold:  
                    matches.append((sw, cpe, score))  
        return matches  