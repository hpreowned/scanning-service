# Deliberately unsafe: this fixture exists so the scanner has something to find.
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    os.system("echo " + request.args.get("name", ""))
    return "done"
