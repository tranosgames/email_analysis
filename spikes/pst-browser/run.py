import functools, http.server, threading, sys, json
from playwright.sync_api import sync_playwright
class Q(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*a): pass
s=http.server.ThreadingHTTPServer(("127.0.0.1",0),functools.partial(Q,directory=sys.argv[1])); threading.Thread(target=s.serve_forever,daemon=True).start()
with sync_playwright() as p:
    b=p.chromium.launch()
    for f in sys.argv[2:]:
        pg=b.new_page(); pg.goto(f"http://127.0.0.1:{s.server_address[1]}/index.html")
        pg.set_input_files("#f", f); pg.wait_for_function("document.getElementById('out').textContent.length > 0", timeout=120000)
        print(f.split("/")[-1], pg.inner_text("#out")); pg.close()
    b.close()
