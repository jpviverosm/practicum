import sys
from flask import Flask, send_file, render_template
		
app = Flask(__name__)
		
@app.route('/challenge')
def download_file():
    file_path = './challenge/challenge.txt'
    return send_file(file_path, as_attachment=True)

@app.route("/")
def hello_world():
    #html = "<p>Hello, World!</p>"
    return render_template('landing.html')
		
if __name__ == '__main__':
	app.run(debug=True, host = sys.argv[1], port=8080)
