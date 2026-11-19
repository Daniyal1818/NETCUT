import re

def test_frontend_ids_aligned():
    with open("static/app.js", encoding="utf-8") as f:
        app_js = f.read()
    with open("static/index.html", encoding="utf-8") as f:
        html = f.read()

    p1 = re.compile(r'\$\(["\']([^"\']+)["\']\)')
    p2 = re.compile(r'id=["\']([^"\']+)["\']')

    ids_app = set(p1.findall(app_js))
    ids_html = set(p2.findall(html))

    # Exclude Cytoscape pseudo-selectors like :selected
    missing = [i for i in ids_app - ids_html if not i.startswith(":")]
    assert not missing, f"Missing IDs in index.html: {missing}"
    print("Frontend ID alignment test passed!")

if __name__ == "__main__":
    test_frontend_ids_aligned()
