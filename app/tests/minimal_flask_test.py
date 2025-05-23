from flask import Flask, render_template_string, url_for

app = Flask(__name__)

NAV = '''
<nav>
    <a href="/">Home</a> |
    <a href="/ip">IP Analysis</a> |
    <a href="/domain">Domain Analysis</a> |
    <a href="/url">URL Analysis</a>
</nav>
'''

@app.route('/')
def home():
    return render_template_string(f"""
        <html><body>{NAV}<h1>Home Page</h1></body></html>""")

@app.route('/ip')
def ip():
    return render_template_string(f"""
        <html><body>{NAV}<h1>IP Analysis Page</h1></body></html>""")

@app.route('/domain')
def domain():
    return render_template_string(f"""
        <html><body>{NAV}<h1>Domain Analysis Page</h1></body></html>""")

@app.route('/url')
def url():
    return render_template_string(f"""
        <html><body>{NAV}<h1>URL Analysis Page</h1></body></html>""")

if __name__ == '__main__':
    app.run(debug=True, port=5000) 