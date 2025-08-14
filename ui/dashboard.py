from flask import Flask, request, render_template  
# ... your imports  
  
app = Flask(__name__)  
  
class Dashboard:  
    def __init__(self, rdf_graph):  
        self.rdf_graph = rdf_graph  
  
    def run(self):  
        @app.route("/", methods=["GET", "POST"])  
        def index():  
            query = ""  
            results = None  
            if request.method == "POST":  
                query = request.form.get("query")  
                results = self.rdf_graph.query(query)  
            return render_template("query.html", query=query, results=results)  
  
        @app.route("/toggle_reasoning")  
        def toggle_reasoning():  
            global g  
            from reasoning import apply_reasoning  
            g = apply_reasoning(g)  
            return "Reasoning applied. Go back to <a href='/'>Dashboard</a>."  
        
        @app.route("/probable")  
        def probable():  
            sparql = """  
            PREFIX soft: <http://example.org/software#>  
            PREFIX cve: <http://example.org/cve#>  
  
            SELECT ?vendor ?product ?version ?cveId ?description ?cvss ?severity ?score  
            WHERE {  
              ?sw a soft:Software ;  
                  soft:vendor ?vendor ;  
                  soft:product ?product ;  
                  soft:version ?version ;  
                  cve:possibleVulnerability ?cve .  
              OPTIONAL { ?cve cve:cveId ?cveId }  
              OPTIONAL { ?cve cve:description ?description }  
              OPTIONAL { ?cve cve:cvssScore ?cvss }  
              OPTIONAL { ?cve cve:severity ?severity }  
              OPTIONAL { ?sw cve:matchScore ?score }  
            }  
            ORDER BY DESC(?score)  
            """  
            results = list(self.rdf_graph.query(sparql))  
            return render_template("probable.html", results=results)  
  
        @app.route("/adhoc", methods=["GET", "POST"])  
        def adhoc():  
            vendor = ""  
            product = ""  
            threshold = 0.85  
            results = None  
  
            if request.method == "POST":  
                vendor = request.form.get("vendor", "").strip()  
                product = request.form.get("product", "").strip()  
                try:  
                    threshold = float(request.form.get("threshold", "0.85"))  
                except ValueError:  
                    threshold = 0.85  
  
                sparql = f"""  
                PREFIX cpe:  <http://example.org/cpe#>  
                PREFIX cve:  <http://example.org/cve#>  
                PREFIX FUZZY: <http://example.org/fuzzy#>  
  
                SELECT ?cpeVendor ?cpeProduct ?score ?cveId ?description ?cvss ?severity  
                WHERE {{  
                  ?cpe a cpe:Platform ;  
                       cpe:vendor ?cpeVendor ;  
                       cpe:product ?cpeProduct .  
  
                  BIND((FUZZY:similarity(?cpeVendor, "{vendor}") +  
                        FUZZY:similarity(?cpeProduct, "{product}")) / 2 AS ?score)  
                  FILTER(?score > {threshold})  
  
                  ?cve cve:affects ?cpe .  
                  OPTIONAL {{ ?cve cve:cveId ?cveId }}  
                  OPTIONAL {{ ?cve cve:description ?description }}  
                  OPTIONAL {{ ?cve cve:cvssScore ?cvss }}  
                  OPTIONAL {{ ?cve cve:severity ?severity }}  
                }}  
                ORDER BY DESC(?score)  
                """  
                results = list(self.rdf_graph.query(sparql))  
  
            return render_template("adhoc.html",  
                                   vendor=vendor,  
                                   product=product,  
                                   threshold=threshold,  
                                   results=results)  
  
        app.run(debug=True)  