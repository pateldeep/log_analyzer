from flask import (
    Flask,
    request,
    redirect,
    url_for,
    send_from_directory,
    render_template,
    send_file,
)
# from flask_mail import Mail, Message
import unicodedata
app = Flask(__name__)
import sys
from paths import path
import os

import hostchecker as h
from werkzeug.utils import secure_filename
# from flask_login import (
#     LoginManager,
#     UserMixin,
#     login_required,
#     login_user,
#     logout_user,
#     current_user,
#     login_manager,
# )

import string
import random

fileNameToUse = "".join(
    random.choice(string.ascii_letters + string.digits) for i in range(12)
)

import argparse
import re
import smtplib
from email.mime.text import MIMEText
import getpass
import random

import os
from paths import path
import string

UPLOAD_FOLDER = path + "/downloads"
DOWNLOAD_FOLDER = path + "/downloads"
totalVisitors = 0

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["DOWNLOAD_FOLDER"] = DOWNLOAD_FOLDER

app.config.update(
    dict(
        DEBUG=True,
        # email server
        MAIL_SERVER="smtp-mail.outlook.com.",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME="tmenon@pulsesecure.net",
        MAIL_PASSWORD="GibsonLesPaul1275$",
    )
)

# mail = Mail(app)
#fileNameToUse = "".join(
#    random.choice(string.ascii_letters + string.digits) for i in range(12))
fileNameToUse = "outputlogs"



@app.route("/addRegion/file_downloads/")
def file_downloads():
    with open(DOWNLOAD_FOLDER + "/" + fileNameToUse + ".txt", "r") as nF:
        for cnt, line in enumerate(nF):
            if "This log was captured in level" in line:
                logLevel = line.strip()
                break
    logLevel = int(logLevel[logLevel.find("level")+len("level "):])
    try:
        return render_template("downloads.html", level = logLevel)
    except Exception as e:
        return str(e)


@app.route("/addRegion/return_files/", methods=["POST"])
def return_files():
    f = open(DOWNLOAD_FOLDER + "/" + fileNameToUse + ".txt", "r")
    global totalVisitors
    totalVisitors += 1
    with open(path + "/downloads/counter.txt", 'w') as currCounter:
        currCounter.write(str(totalVisitors))
    return send_from_directory(
        DOWNLOAD_FOLDER, fileNameToUse + ".txt", as_attachment=True
    )


# login_manager= LoginManager()
# login_manager.setup_app(current_app)

# Set the secret key to some random bytes. Keep this really secret!
# app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


@app.route("/")
def index():
    with open(path+"/downloads/counter.txt", 'r') as currCounter:
        number = currCounter.readline()
    number = int(number)
    global totalVisitors
    totalVisitors = number
    return render_template("template.html", visitors = totalVisitors)


@app.route("/back/")
def back():
    return redirect(url_for("index"))


@app.route("/makeText", methods=["POST", "GET"])
def makeText():
    # <textarea name = "logFile" placeholder="Copy/Paste everything from the log in here..."></textarea>
    text = request.form.get("logFile")
    #text = "".join(ch for ch in text if unicodedata.category(ch)[0]!="C")
    printable = set(string.printable)
    text = ''.join(filter(lambda x: x in printable, text))
    with open(path + "/downloads/" + fileNameToUse + ".txt", "w+") as textFile:
        textFile.write(text)
    ret_val = h.click_func(
        path + "/downloads/" + fileNameToUse + ".txt",
        "",
        "",
        "",
        "",
        "all",
        fileNameToUse,
    )
    if ret_val == 2:
        return render_template("mail_sent.html")
    elif ret_val == 1:
        return redirect(url_for("loading"))
        # return redirect(url_for("file_downloads"))
    elif ret_val == "fail":
        return render_template("checkFile.html")
    else:
        return redirect(url_for("index"))

@app.route("/loading", methods=["POST", "GET"])
def loading():
    for subdir, dirs, files in os.walk(path + "/downloads"):
            for file in files:
                if file == fileNameToUse+".txt":
                    return redirect(url_for("file_downloads"))    
    return render_template("loadingPage.html", fileNameToUse = fileNameToUse)


@app.route("/addRegion", methods=["GET", "POST"])
def addRegion():
    strt_d = None
    strt_t = None
    end_d = None
    end_t = None
    global fileNameToUse
    fileNameToUse = "".join(
        random.choice(string.ascii_letters + string.digits) for i in range(12)
    )
    file = request.files.get("fileToUpload")
    send_email = request.form.get("sendmail")
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    file_object = open(app.config["UPLOAD_FOLDER"] + "/" + filename, "r")
    strt_d = request.form.get("strDate")
    strt_t = request.form.get("strTime")
    end_d = request.form.get("endDate")
    end_t = request.form.get("endTime")
    userids = request.form.get("userid")
    parseBasedOn = request.form.get("chooseToParse")
    if userids:
        userids = userids.replace(" ", "")
        userids = userids.split(",")
    else:
        userids = None
    strt_ts = strt_d + " " + strt_t
    end_ts = end_d + " " + end_t

    if "yes" in send_email:
        send_email = 1
    else:
        send_email = 0
    ret_val = h.click_func(
        file_object.name, strt_ts, end_ts, userids, send_email, parseBasedOn, fileNameToUse
    )
    if ret_val == 2:
        return render_template("mail_sent.html")
    elif ret_val == 1:
        return redirect(url_for("loading"))
        # return redirect(url_for("file_downloads"))
    elif ret_val == "fail":
        return render_template("checkFile.html")
    else:
        return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
