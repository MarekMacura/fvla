import unittest  
from ingestion.entity_matcher import EntityMatcher  
  
class TestEntityMatcher(unittest.TestCase):  
    def test_fuzzy_match(self):  
        matcher = EntityMatcher(threshold=0.8)  
        sw_list = [{"vendor": "Microsoft", "product": "Windows", "version": "10"}]  
        cpe_list = ["microsoft windows 10", "linux kernel"]  
        matches = matcher.match_software_to_cpe(sw_list, cpe_list)  
        self.assertTrue(any("windows" in cpe for _, cpe, _ in matches))  
  
if __name__ == '__main__':  
    unittest.main()  