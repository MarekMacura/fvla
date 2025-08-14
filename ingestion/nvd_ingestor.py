import gzip  
import json  
import requests  
from datetime import datetime  
from pathlib import Path  
  
class NVDIngestor:  
    """  
    Handles downloading and parsing NVD CVE feeds incrementally.  
    """  
  
    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/"  
  
    def __init__(self, data_dir="data/nvd"):  
        self.data_dir = Path(data_dir)  
        self.data_dir.mkdir(parents=True, exist_ok=True)  
  
    def get_meta_url(self, year):  
        return f"{self.BASE_URL}nvdcve-2.0-{year}.meta"  
  
    def get_feed_url(self, year):  
        return f"{self.BASE_URL}nvdcve-2.0-{year}.json.gz"  
  
    def get_local_meta_file(self, year):  
        return self.data_dir / f"nvdcve-2.0-{year}.meta"  
  
    def get_local_feed_file(self, year):  
        return self.data_dir / f"nvdcve-2.0-{year}.json.gz"  
  
    def download_meta(self, year):  
        r = requests.get(self.get_meta_url(year))  
        r.raise_for_status()  
        return r.text  
  
    def download_feed(self, year):  
        r = requests.get(self.get_feed_url(year), stream=True)  
        r.raise_for_status()  
        with open(self.get_local_feed_file(year), "wb") as f:  
            for chunk in r.iter_content(chunk_size=8192):  
                f.write(chunk)  
  
    def needs_update(self, year):  
        meta_online = self.download_meta(year)  
        local_meta_file = self.get_local_meta_file(year)  
        if not local_meta_file.exists():  
            return True  
        local_meta = local_meta_file.read_text()  
        return "lastModifiedDate" not in local_meta or self.extract_last_modified(meta_online) != self.extract_last_modified(local_meta)  
  
    def extract_last_modified(self, meta_text):  
        for line in meta_text.splitlines():  
            if line.startswith("lastModifiedDate:"):  
                return line.split(":", 1)[1].strip()  
        return None  
  
    def update_feed(self, year):  
        if self.needs_update(year):  
            print(f"[NVDIngestor] Updating feed for {year}")  
            meta_text = self.download_meta(year)  
            self.get_local_meta_file(year).write_text(meta_text)  
            self.download_feed(year)  
            return True  
        print(f"[NVDIngestor] Feed for {year} is up to date")  
        return False  
  
    def load_feed(self, year):  
        with gzip.open(self.get_local_feed_file(year), "rt", encoding="utf-8") as f:  
            return json.load(f)  