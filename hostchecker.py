import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import getpass
from tabulate import tabulate
import os
import json
import time
from paths import path
from datetime import datetime, timedelta
import threading

# Code to read through logs and display host checker logs

logifile = " "
json_file = path + "/hc_json.json"

mail_list = []
sender = "ahotti@pulsesecure.net"
receivers = []


hostchecker_type = [
    "AntiVirus",
    "Firewall",
    "AntiSpyware",
    "HardDisk",
    "Patch Management",
]

def addBuffer(hc_dic, count):
    for i in range(0, count):
        hc_dic["Rule Checked"].append("-")
        hc_dic["Connection"].append("-")
        hc_dic["Index"].append("-")
        hc_dic["Start Date"].append("-")
        hc_dic["Start Time"].append("-")
        hc_dic["Result"].append("-")
        hc_dic["Params"].append("-")

def hc_Log_read(fo, send, parseBased, fileNameToUse):
    hc_opswat_phrase = ["dsAccessService", "OpswatIMC", "'getIMVMessage' IMV Message"]
    # hc_opswat_phrase=["dsAccessService","OpswatIMC","OpswatImcColData'"]
    hc_opswat_sent_phrase = [
        "dsAccessService",
        "OpswatIMC",
        "'toIMVMessage' IMV Message",
    ]

    ops_check_list = []
    ops_result_list = []
    opswat_server_search_string = "<parameter name=(.+?) value=(.+);"
    opswat_client_search_string = "<parameter name=(.+?) value=(.+);"

    hc_fail_count = 0
    hc_pass_count = 0
    index = 0
    hc_dic = {
        "Index": [],
        "Start Date": [],
        "Start Time": [],
        "Connection": [],
        "Rule Checked": [],
        "Params": [],
        "Result": [],
    }

    conn_search_string = "connection (.+?) on NAR (.+?),"
    hc_start_phrase = [
        "'TncHandshake' Host check started, beginning handshake"
    ]  # Check where dsAccessService called HostCheckerService to SetLanguage Id - This is the start of hostchecker
    # hc_end_phrase= [hc_fail hc_pass]
    hc_not_started = 0
    hc_start_time = 0
    hc_start_date = 0
    hc_end_time = 0
    hc_end_date = 0

    opswat_logs_yes = 0
    opswat_client_logs_sent = 0
    opswat_line = ""

    with open(path + "/hc_json.json", "r") as json_file:
        json_string = json_file.read()
        search_string = json.loads(json_string)
    
    # f = ""
    # with open(fo, 'rb') as readFromParsedFile:
    #     firstTime = fp.readline()
    #     inputFile = readFromParsedFile.read()            
    #     inputFile = inputFile.decode('utf-8', errors="ignore")
    #     inputFile = inputFile.split('\n')
    #     f = inputFile
    level = 0
    # for line in f:
    with open(fo, "rb") as fp:
        for cnt, line in enumerate(fp):
            line = line.decode('utf-8', errors="ignore")
            try:
                if(re.match(r'[0-9]*\,[0-9]* [0-90]*\/[0-90]*\/[0-90]* [0-90]*\:[0-90]*\:[0-90]*\.[0-90]* ', line)):
                    currLevel = line[33]
                    if int(currLevel) > level:
                        level = int(currLevel)
            except:
                currLevel = 0
            if (parseBased == "host-checker" or parseBased == "all") and search_string["IMV_MESSAGE"] in line:
                parsedLine = line[line.find(search_string["IMV_MESSAGE"]) + 25 : -2]
            elif (parseBased == "host-checker" or parseBased == "all") and "Host check finished" in line:
                getTimeStamps = line.split(' ')[1:3]
                line = line[line.find("new state `") + len("new state `") :]
                line = line[: line.find("'")]
                if(line == "Open"):
                    line = "Success"
                hc_dic["Params"].append("The RESULT OF THE SCAN WAS ---------->")
                hc_dic["Index"].append(index)
                hc_dic["Result"].append(line)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Rule Checked"].append("SCANNING")
                hc_pass_count += 1
                index += 1
                continue
            # 00154,09 2020/02/19 13:36:35.178 2 SYSTEM PulseSecureService.exe samAM p4664 t3F28 pcp.cpp:94 - 'pcp' max no of connections limit (64) reached for a user session
            elif (parseBased == "pdc-conn" or parseBased == "all") and "'pcp' max no of connections limit" in line: 
                getTimeStamps = line.split(' ')[1:3]
                connStat = line[line.find("connections limit "):]
                hc_dic["Rule Checked"].append("Connec Limit")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append("Conn. Limit Reached: "+connStat[connStat.find("("):connStat.find(")")+1])
                hc_dic["Params"].append(connStat)
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "Connection Status" in line:
                getTimeStamps = line.split(' ')[1:3]
                connStat = line[line.find("Connection Status")+len("Connection Status"):]
                hc_dic["Rule Checked"].append("Connection Status")
                hc_dic["Connection"].append(connStat.strip()[1:])
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(" ")
                hc_dic["Params"].append(" ")
                if 'Disconnected' in line or 'Failed' in line or 'Cancelled' in line:
                    addBuffer(hc_dic, 1)
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "Restore Wireless Adapter" in line:
                # 00266,09 2019/07/30 08:06:34.182 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4324 t14A4 8021xAccessMethod_win.cpp:2109 - '8021xSuppression' TestWirelessSuppression: Wired Disonnected. Restore Wireless Adapter. Call setWirelessSuppression(NOT_SUPPRESSING) and return.
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Wired Disonnected")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Wired Disconnected")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append("Restoring Wireless Adapter")
                hc_dic["Params"].append(line[pointer:line.find('.',pointer)])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "getAttributes- SuppressedWirelessAdapters:" in line:
                # 00243,09 2019/08/02 07:42:09.328 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p2924 t1880 8021xAccessMethod_win.cpp:1962 - '8021xSuppression' setWirelessSuppression: getAttributes- SuppressedWirelessAdapters: 76af8e0a-8579-4001-915b-a48e55dd21cc
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("SuppressedWirelessAdapters") + len("SuppressedWirelessAdapters: ")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(line[pointer:])
                hc_dic["Params"].append("GUID INFO FROM CONN-STORE")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "Requested NO_Suppress" in line:
                # 00228,09 2019/08/01 08:01:33.690 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4612 t16A8 8021xAccessMethod_win.cpp:1683 - '8021xSuppression' setAdapterState : Requested NO_Suppress (Enable) on 76af8e0a-8579-4001-915b-a48e55dd21cc
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Requested NO_Suppress")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                noSuppressLine = line[pointer:].split(" ")
                hc_dic["Params"].append(" ".join(noSuppressLine[0:2]))
                hc_dic["Result"].append(noSuppressLine[4])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "TestWirelessSuppression: Wired Adapter Connected" in line:
                # 00188,09 2019/07/31 07:57:06.557 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4608 t1ABC 8021xAccessMethod_win.cpp:2100 - '8021xSuppression' TestWirelessSuppression: Wired Adapter Connected
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(" ")
                hc_dic["Result"].append("Wired Adapter Connected")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "setWirelessSuppression[NOT_SUPPRESSING]: SuppressedWirelessAdapters" in line:
                # 00229,09 2019/08/05 07:57:50.109 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4404 t1574 8021xAccessMethod_win.cpp:1957 - '8021xSuppression' setWirelessSuppression[NOT_SUPPRESSING]: SuppressedWirelessAdapters from ConnStore: EMPTY
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("ConnStore")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append("NOT_SUPPRESSING And RESTORING FROM")
                hc_dic["Result"].append(line[pointer:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "Requested Adapter found in" in line:
                # 00202,09 2019/08/01 08:01:34.053 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4612 t16A8 8021xAccessMethod_win.cpp:1828 - '8021xSuppression' Requested Adapter found in Any State. Attempting Status Toggle   
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Requested Adapter")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find(".",pointer)])
                hc_dic["Result"].append(line[line.find(".", pointer)+2:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "'ConnectionStoreService' Failed CreateFile:" in line:
                # 1 SYSTEM PulseSecureService.exe ConnectionStore p4352 t18E0 ConnectionStoreDocSet.cpp:575 - 'ConnectionStoreService' Failed CreateFile: 32 C:\ProgramData\Pulse Secure\ConnectionStore\S-1-5-18.tmp
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Failed CreateFile:")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("ConnectionStoreService")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find(":", pointer)])
                hc_dic["Result"].append(line[line.find(":", pointer)+2:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "Adapter Enumeration Failed." in line:
                # 4 SYSTEM PulseSecureService.exe 8021xAccessMethod p3572 t14F0 8021xAccessMethod_win.cpp:1786 - '8021xSuppression' SetAdapterState: Adapter Enumeration Failed. Breaking
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Adapter Enumeration")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Re-Enable Wireless")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find(".", pointer)])
                hc_dic["Result"].append(line[line.find(".", pointer)+2:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "'8021xSuppression' setAdapterState Exiting" in line:
                # 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p3572 t14F0 8021xAccessMethod_win.cpp:1888 - '8021xSuppression' setAdapterState Exiting. RetVal : FALSE            
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("setAdapterState Exiting")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Re-Enable Wireless")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find(".", pointer)])
                hc_dic["Result"].append(line[line.find(".", pointer)+2:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "setAdapterState : Successfully" in line:
                # 00193,09 2019/08/02 07:42:11.383 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p2924 t1880 8021xAccessMethod_win.cpp:1861 - '8021xSuppression' setAdapterState : Successfully Executed Method Enable   
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("setAdapterState :") + len("setAdapterState :")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Method Exec")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find("Method", pointer)])
                hc_dic["Result"].append(line[line.find("Method",pointer)+len("method")+1:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "setWirelessSuppression[NOT_SUPPRESSING]: setAdapterState" in line:
                # 00280,09 2019/08/01 08:01:35.920 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4612 t16A8 8021xAccessMethod_win.cpp:1975 - '8021xSuppression' setWirelessSuppression[NOT_SUPPRESSING]: setAdapterState succeeded to Enable Adapter 76af8e0a-8579-4001-915b-a48e55dd21cc. Calling Listeners     
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("setAdapterState") + len("setAdapterState")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Method Exec")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find("Adapter",pointer)+len("Adapter")])
                hc_dic["Result"].append(line[line.find("Adapter",pointer)+len("Adapter"):line.find(".",pointer)])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "setWirelessSuppression: Updating ConnStore" in line:
                # 00228,09 2019/08/01 08:01:38.506 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4612 t16A8 8021xAccessMethod_win.cpp:2049 - '8021xSuppression' setWirelessSuppression: Updating ConnStore SuppressedWirelessAdapters Entry:      
                
                #00264,09 2019/08/07 08:03:42.720 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4352 t18E0 8021xAccessMethod_win.cpp:2049 - '8021xSuppression' setWirelessSuppression: Updating ConnStore SuppressedWirelessAdapters Entry Successful: 76af8e0a-8579-4001-915b-a48e55dd21cc   

                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("SuppressedWirelessAdapters") + len("SuppressedWirelessAdapters")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Updating ConnStore")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find(":", pointer)])
                hc_dic["Result"].append(line[line.find(":", pointer)+2:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "suppression" or parseBased == "all") and "Wired Adapter Disconnected" in line:
                # 00221,09 2019/08/01 08:01:39.539 3 SYSTEM PulseSecureService.exe 8021xAccessMethod p4612 t16A8 8021xAccessMethod_win.cpp:1586 - '8021xAccessMethod' isValidNetwork : cedeff91-e76e-468d-a4ba-c15cb16ca0c4 Wired Adapter Disconnected
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("isValidNetwork : ") + len("isValidNetwork : ")
                hc_dic["Rule Checked"].append("8021xSuppression")
                hc_dic["Connection"].append("Wired Adapter")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(line[pointer:line.find(" ", pointer)])
                hc_dic["Result"].append("Disconnected")
                addBuffer(hc_dic, 4)
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "IUiModelService::StartConnection" in line:
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("StartConnection")
                hc_dic["Params"].append(line[line.find("("):line.find(")")+1])
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append("STARTING-CONN")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(" ")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "kPromptTypeUsernamePassword" in line:
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("Username/Pass")
                hc_dic["Params"].append(line[line.find("Connection"):])
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(" ")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "AUTH_SUCCESS" in line:
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("Username/Pass")
                hc_dic["Params"].append("The entered information led to -------->")
                hc_dic["Result"].append("Success")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "Starting EAP" in line:
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("Starting EAP")
                hc_dic["Result"].append(" ")
                hc_dic["Params"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "iveMaxConcurrentUsersSignedIn" in line:
                conUsers = line[line.find("iveConcurrentUsers="):line.find("]", line.find("iveConcurrentUsers="))]
                hc_dic["Rule Checked"].append("iveMaxConcurrentUsersSignedIn")
                hc_dic["Result"].append(conUsers)
                hc_dic["Params"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(" ")
                hc_dic["Start Time"].append(" ")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "SSL connect" in line:
                getTimeStamps = line.split(' ')[1:3]
                line = line[line.find("SSL connect") + len("SSL connect ") :]
                ssl_connect = line.split(" ")
                hc_dic["Params"].append(ssl_connect[0])
                hc_dic["Params"].append("connection using "+line[line.find("cipher"):])
                hc_dic["Rule Checked"].append("SSL connect")
                hc_dic["Rule Checked"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Index"].append(" ")
                hc_dic["Result"].append(" ")
                hc_dic["Result"].append(" ")
                hc_dic["Connection"].append(" ")
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Start Date"].append(" ")
                hc_dic["Start Time"].append(" ")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "received fatal error" in line:
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Params"].append(line[line.find("received fatal error"):])
                hc_dic["Rule Checked"].append("FATAL ERROR")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                errorNo = int(line[line.find("fatal error from IVE: ")+len("fatal error from IVE: "):])
                if errorNo == 1:
                    hc_dic["Result"].append("NC unable to allocate IP for virtual adapter")
                elif errorNo == 2:
                    hc_dic["Result"].append("Wrong client used to access NC feature")
                elif errorNo == 3:
                    hc_dic["Result"].append("IC got connections frmo both Pulse and OAC on same endpoint")
                elif errorNo == 4:
                    hc_dic["Result"].append("Client IP addres changed; roaming not allowed")
                elif errorNo == 5:
                    hc_dic["Result"].append("Session is no longer valid")
                elif errorNo == 6:
                    hc_dic["Result"].append("Error detected on server")
                elif errorNo == 7:
                    hc_dic["Result"].append("Session is terminated")
                elif errorNo == 8:
                    hc_dic["Result"].append("Session is timed out")
                elif errorNo == 9:
                    hc_dic["Result"].append("Wrong Client, role changed loss NC role")
                elif errorNo == 10:
                    hc_dic["Result"].append("Client requested disconnect")
                elif errorNo == 11:
                    hc_dic["Result"].append("Client Deleted session thru browser")
                else:
                    hc_dic["Result"].append(str(errorNo) + "has not been integrated here yet, look on log")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "IVE sent: IP4 Client Address" in line:
                getTimeStamps = line.split(' ')[1:3]
                IP4_info = line[line.find("IVE sent: ")+len("IVE sent: "):].split(",")
                hc_dic["Rule Checked"].append("IP4 Client Addr")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Connection"].append(" ")
                hc_dic["Result"].append(" ")
                addLines = 0
                for item in IP4_info:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "IVE sent: IP6 Client Address" in line:
                getTimeStamps = line.split(' ')[1:3]
                IP6_info = line[line.find("IVE sent: ")+len("IVE sent: "):].split(",")
                hc_dic["Rule Checked"].append("IP6 Client Addr")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Connection"].append(" ")
                hc_dic["Result"].append(" ")
                addLines = 0
                for item in IP6_info:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "IVE sent: IP4 DNS1" in line:
                getTimeStamps = line.split(' ')[1:3]
                IP4_info = line[line.find("IVE sent: ")+len("IVE sent: "):].split(",")
                hc_dic["Rule Checked"].append("IP4 DNS1")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Connection"].append(" ")
                hc_dic["Result"].append(" ")
                addLines = 0
                for item in IP4_info:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "IVE mtu" in line:
                getTimeStamps = line.split(' ')[1:3]
                mtu_msg = line[line.find("IVE mtu: ")+len("IVE mtu: "):]
                hc_dic["Rule Checked"].append("IVE mtu")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(mtu_msg)
                hc_dic["Result"].append(" ")
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "MTU: from mss" in line:
                getTimeStamps = line.split(' ')[1:3]
                MTU_INFO = line[line.find("MTU: from mss")+len("MTU: "):].split(",")
                hc_dic["Rule Checked"].append("MTU")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(" ")
                addLines = 0
                for item in MTU_INFO:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "new ESP tunnel" in line:
                getTimeStamps = line.split(' ')[1:3]
                ESP_INFO = line[line.find("new ESP tunnel ")+len("new ESP tunnel "):].split(",")
                hc_dic["Rule Checked"].append("ESP tunnel")
                outStr = ESP_INFO[1]
                ipAddrInd = outStr.find(" ", 4)
                inHex = ESP_INFO[0]
                outHex = outStr[:ipAddrInd]
                ipAddr = outStr[ipAddrInd:]
                ESP_INFO.clear()
                ESP_INFO.append(inHex)
                ESP_INFO.append(outHex)
                ESP_INFO.append(ipAddr)
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Result"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                addLines = 0
                for item in ESP_INFO:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "SA dns suffix" in line:
                getTimeStamps = line.split(' ')[1:3]
                SA_DNS = line[line.find("SA dns suffix: ")+len("SA dns suffix: "):].split(",")
                hc_dic["Rule Checked"].append("SA dns suffix: ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Connection"].append(" ")
                hc_dic["Result"].append(" ")
                addLines = 0
                for item in SA_DNS:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "Enable TM Inteface" in line:
                getTimeStamps = line.split(' ')[1:3]
                TM_face = line[line.find("Enable TM Inteface: "):]
                hc_dic["Rule Checked"].append("TM Interface")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Result"].append("Virtual adapter up")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append(TM_face)
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "Switching to NCP mode" in line:
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("ESP - SSL failover")
                hc_dic["Index"].append(index)
                hc_dic["Result"].append("SSL Fallback")
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Params"].append("Switching to NCP mode")
                hc_pass_count += 1
                index += 1
                continue
            # elif (parseBased == "wts-conn" or parseBased == "all") and "WTS_SESSION" in line:
            #     line += " "
            #     sessionInfo = line[line.find("WTS_SESSION"):line.find(" ", line.find("WTS_SESSION"))]
            #     getTimeStamps = line.split(' ')[1:3]
            #     hc_dic["Rule Checked"].append(sessionInfo)
            #     hc_dic["Index"].append(index)
            #     hc_dic["Result"].append(sessionInfo[len("WTS_SESSION_"):])
            #     hc_dic["Start Date"].append(getTimeStamps[0])
            #     hc_dic["Start Time"].append(getTimeStamps[1])
            #     hc_dic["Connection"].append(" ")
            #     hc_dic["Params"].append("======================================================")
            #     hc_pass_count += 1
            #     index += 1
            #     continue
            elif (parseBased == "wts-conn" or parseBased == "all") and "WTS_" in line: 
                line += " "
                sessionInfo = line[line.find("WTS_"):line.find(" ", line.find("WTS_"))]
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append(sessionInfo)
                hc_dic["Index"].append(index)
                hc_dic["Result"].append("")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Connection"].append(" ")
                hc_dic["Params"].append(line[line.find("SessionId"):])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "wts-conn" or parseBased == "all") and "NetworkInterfaceChangeMonitor.cpp" in line:
                line += " "
                getTimeStamps = line.split(' ')[1:3]
                hc_dic["Rule Checked"].append("Network Change")
                hc_dic["Index"].append(index)
                hc_dic["Result"].append("")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Connection"].append(" ")
                hc_dic["Params"].append(line[line.find('InterfaceMonitor')-1:])
                hc_pass_count += 1
                index += 1
                continue
            elif (parseBased == "pdc-conn" or parseBased == "all") and "kmp message" in line:
                if "received" in line:
                    continue
                getTimeStamps = line.split(' ')[1:3]
                line = line[line.find("'ipsec'") + len("'ipsec '") :]
                hc_dic["Params"].append(line)
                hc_dic["Rule Checked"].append("KMP Message")
                hc_dic["Index"].append(index)
                hc_dic["Connection"].append(" ")
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                if "300" in line:
                    hc_dic["Result"].append("Data Message")
                elif "301" in line:
                    hc_dic["Result"].append("Connection Message")
                elif "302" in line:
                    hc_dic["Result"].append("ReKey Success")
                elif "303" in line:
                    hc_dic["Result"].append("General Information")
                else:
                    hc_dic["Result"].append("Please add the new KMP Return code to the list")
                hc_pass_count += 1
                index += 1
                continue
                    # 00306,09 2019/09/17 16:42:17.709 3 SYSTEM PulseSecureService.exe eapService p4236 t15F8 jamCert.cpp:339 - 'JamCertLib' 0) Processing Certificate (Subject: DTC9E8D3F3E849C.ent.wfb.bank.corp, Issuer: Wells Fargo Infrastructure Certification Authority 06 G2, Thumbprint: B4840A097D0EB0BF9A036FEA3335D7840AA3FFB7) ...
            elif (parseBased == "cert" or parseBased == "all") and "jamCert.cpp:339" in line:
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Certificate")+len("Certificate (")
                certInfo = line[pointer:line.find(')', pointer)].split(",")
                hc_dic["Rule Checked"].append("Processing Cert")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(" ")
                # Subject: DTC9E8D3F3E849C.ent.wfb.bank.corp, Issuer: Wells Fargo Infrastructure Certification Authority 06 G2, Thumbprint: B4840A097D0EB0BF9A036FEA3335D7840AA3FFB7
                addLines = 0
                for item in certInfo:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            #00247,09 2019/09/18 10:07:00.531 1 SYSTEM PulseSecureService.exe eapService p3868 t11D8 jcSelectionRule.cpp:350 - 'JamCertLib' Certificate B4840A097D0EB0BF9A036FEA3335D7840AA3FFB7 does not meet the required 'is time-valid' condition, skipping it (rank 0)
            elif (parseBased == "cert" or parseBased == "all") and "jcSelectionRule.cpp:350" in line:
                getTimeStamps = line.split(' ')[1:3]
                conditionNotMet = line[line.find('required')+len("required "):line.find("condition")]
                result = line[line.find('condition,')+len('condition,'):]
                pointer = line.find("Certificate")
                certThumb = line[pointer:line.find(" ", pointer+len("Certificate "))]
                hc_dic["Rule Checked"].append("Invalid Cert")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(result)
                hc_dic["Params"].append(certThumb+" didn't pass "+conditionNotMet+"condition")
                hc_pass_count += 1
                index += 1
                continue
            # 00162,09 2019/09/17 16:42:17.710 3 SYSTEM PulseSecureService.exe eapService p4236 t15F8 jamCert.cpp:518 - 'JamCertLib' Picked 1 client certificates with rank 0x73FF4000:
            elif (parseBased == "cert" or parseBased == "all") and "jamCert.cpp:518" in line:
                getTimeStamps = line.split(' ')[1:3]
                selected = line[line.find('Picked'):]
                hc_dic["Rule Checked"].append("Picked")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(" ")
                hc_dic["Params"].append(selected)
                hc_pass_count += 1
                index += 1
                continue
            # 00327,09 2019/09/18 10:07:00.532 3 SYSTEM PulseSecureService.exe eapService p3868 t11D8 JNPRClient.cpp:4014 - 'eapService' Picked Certificate (Subject: DTC9E8D3F3E849C.ent.wfb.bank.corp, Issuer: Wells Fargo Infrastructure Certification Authority 08 G2, Thumbprint: A7D2A4C71DD6940E2CAE3456238275FC24C9F775) for machine authentication.
            elif (parseBased == "cert" or parseBased == "all") and "JNPRClient.cpp:4014" in line:
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("Certificate")+len("Certificate (")
                certInfo = line[pointer:line.find(')', pointer)].split(",")
                hc_dic["Rule Checked"].append("Picked Cert")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append("Cert "+line[line.find(")", pointer)+len(") "):])
                addLines = 0
                for item in certInfo:
                    if addLines != 0:
                        hc_dic["Index"].append(" ")
                        hc_dic["Rule Checked"].append(" ")
                        hc_dic["Start Date"].append(" ")
                        hc_dic["Start Time"].append(" ")
                        hc_dic["Connection"].append(" ")
                        hc_dic["Result"].append(" ")
                    hc_dic["Params"].append(item)
                    addLines = 1
                hc_pass_count += 1
                index += 1
                continue
            # 00133,09 2019/09/18 10:07:01.060 2 SYSTEM PulseSecureService.exe iftProvider p3868 t2614 iftProvider.cpp:1109 - 'iftProvider' AUTH_SUCCESS!
            elif (parseBased == "cert" or parseBased == "all") and "iftProvider.cpp:1109" in line:
                getTimeStamps = line.split(' ')[1:3]
                pointer = line.find("'iftProvider'")+len("'iftProvider'")
                success_fail = line[pointer:]
                hc_dic["Rule Checked"].append("Picked Cert")
                hc_dic["Connection"].append(" ")
                hc_dic["Index"].append(index)
                hc_dic["Start Date"].append(getTimeStamps[0])
                hc_dic["Start Time"].append(getTimeStamps[1])
                hc_dic["Result"].append(success_fail)
                hc_dic["Params"].append(" ")
                hc_pass_count += 1
                index += 1
                continue
            else:
                continue
            hc_not_started = 0
            if not hc_not_started:
                hc_start_date = line[9:32].split(" ")[0]
                hc_start_time = line[9:32].split(" ")[1]
            else:
                hc_not_started = 0

            # What is being checked ?
            for phrase in hc_opswat_phrase:
                opswat_logs_yes = 1
                if phrase not in line:
                    opswat_logs_yes = 0
                    break

            for phrase in hc_opswat_sent_phrase:
                opswat_client_logs_sent = 1
                if phrase not in line:
                    opswat_client_logs_sent = 0
                    break

            opswat_logs_yes = 1
            if opswat_logs_yes:
                opswat_line = line
                m = re.search(opswat_server_search_string, opswat_line)
                if m:
                    ops_check_list = m.group(2).split(";")

            opswat_client_logs_sent = 1
            if opswat_client_logs_sent:
                opswat_line = parsedLine
                # m = re.search(opswat_server_search_string, opswat_line)
                m = re.findall(re.escape("<") + "(.*?)" + re.escape(">"), opswat_line)
                if m:
                    for item in m:
                        splitVals = item.split("value")
                        ops_result_list = []
                        for addVal in splitVals:
                            if addVal.startswith("="):
                                ops_result_list.append("value" + addVal)
                            else:
                                ops_result_list.append(addVal)

                        trimErrors = []
                        try:
                            paramName, value = ops_result_list
                            value = value.split(";")
                            value[0] = value[0][7:]
                            value.pop()
                            for chkError in value:
                                if "error=" in chkError:
                                    chkError = chkError[6:68]
                                    trimErrors.append(chkError)
                                else:
                                    trimErrors.append(chkError)
                            ruleChk = paramName[paramName.find('name="') + 6 : -2]
                            hc_dic["Rule Checked"].append(ruleChk)
                            hc_dic["Index"].append(index)
                            hc_dic["Connection"].append(" ")
                            hc_dic["Start Date"].append(hc_start_date)
                            hc_dic["Start Time"].append(hc_start_time)
                            hc_dic["Result"].append(" ")
                            addLines = 0
                            for param in trimErrors:
                                if "fileinfo=name" in param:
                                    param = param[9:]
                                    param = param.split("|")
                                    param.pop()
                                    hc_dic["Params"].append("fileinfo=")
                                    hc_dic["Rule Checked"].append(" ")
                                    hc_dic["Connection"].append(" ")
                                    hc_dic["Index"].append(" ")
                                    hc_dic["Start Date"].append(" ")
                                    hc_dic["Start Time"].append(" ")
                                    hc_dic["Result"].append(" ")
                                    for name in param:
                                        hc_dic["Params"].append("__" + name)
                                        if addLines != 0:
                                            hc_dic["Rule Checked"].append(" ")
                                            hc_dic["Index"].append(" ")
                                            hc_dic["Connection"].append(" ")
                                            hc_dic["Start Date"].append(" ")
                                            hc_dic["Start Time"].append(" ")
                                            hc_dic["Result"].append(" ")
                                        addLines = 1
                                    addLines = 0
                                else:
                                    hc_dic["Params"].append(param)
                                    if addLines != 0:
                                        hc_dic["Rule Checked"].append(" ")
                                        hc_dic["Connection"].append(" ")
                                        hc_dic["Index"].append(" ")
                                        hc_dic["Start Date"].append(" ")
                                        hc_dic["Start Time"].append(" ")
                                        hc_dic["Result"].append(" ")
                                addLines = 1

                            hc_pass_count += 1
                            index += 1
                            hc_dic["Params"].append(" ")
                            hc_dic["Connection"].append(" ")
                            hc_dic["Rule Checked"].append(" ")
                            hc_dic["Index"].append(" ")
                            hc_dic["Start Date"].append(" ")
                            hc_dic["Start Time"].append(" ")
                            hc_dic["Result"].append(" ")
                        except:
                            notUsedVariable = 1
    with open(path + "/downloads/"+fileNameToUse+".txt", "w") as file_o:
        file_o.write("\n\nThis log was captured in level "+str(level)+"\n\n")
        file_o.write(tabulate(hc_dic, headers="keys"))

    file_o.close()

    file_name = fileNameToUse+".txt"
    if send:
        # send_email(report)
        send_mime_email(file_name)
        return 2
    else:
        return 1


def send_mime_email(filename):
    with open(path + "/myfile.txt", "r") as f:
        password = f.readline()
        f.close()
    password = password.strip()
    fromaddr = "ahotti@pulsesecure.net"
    toaddr = ",".join(receivers)

    # instance of MIMEMultipart
    msg = MIMEMultipart()

    # storing the senders email address
    msg["From"] = fromaddr

    # storing the receivers email address
    msg["To"] = toaddr

    # storing the subject
    msg["Subject"] = "Host Checker Report"

    # string to store the body of the mail
    body = "PFA your report"

    # attach the body with the msg instance
    msg.attach(MIMEText(body, "plain"))

    # open the file to be sent
    attachment = open(path + "/downloads/" + filename, "rb")

    # instance of MIMEBase and named as p
    p = MIMEBase("application", "octet-stream")

    # To change the payload into encoded form
    p.set_payload((attachment).read())

    # encode into base64
    encoders.encode_base64(p)

    p.add_header("Content-Disposition", "attachment; filename= %s" % filename)

    # attach the instance 'p' to instance 'msg'
    msg.attach(p)

    # creates SMTP session
    s = smtplib.SMTP("smtp-relay.psecure.net")

    # start TLS for security
    s.starttls()

    # Authentication
    #    s.login(fromaddr, password)

    # Converts the Multipart msg into a string
    text = msg.as_string()

    # sending the mail
    s.sendmail(fromaddr, toaddr, text)
    # terminating the session
    s.quit()
    return 1


def send_email(report):
    mess = construct_message(report)
    with open(path + "/myfile.txt", "r") as f:
        password = f.readline()
        f.close()
    password = password.strip()

    smtp = smtplib.SMTP("smtp-relay.psecure.net")
    smtp.set_debuglevel(4)
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.sendmail(sender, receivers, mess)
    smtp.quit()
    return 1


def parseTime(t):
    failTest = False
    try:
        return datetime.strptime(t, "%Y-%m-%d %H:%M:%S")
    except:
        failTest = True
    try:
        return datetime.strptime(t, "%Y-%m-%d %H:%M")
    except:
        failTest = True
    try:
        return datetime.strptime(t, "%Y-%m-%d %H")
    except:
        failTest = True
    try:
        return datetime.strptime(t.strip(), "%Y-%m-%d")
    except:
        failTest = True
    


def find_ts(user_ts_start, fo, send, parseBased, fileNameToUse):
    f = fo.readlines()
    user_ts_start= parseTime(user_ts_start) #datetime.strptime(user_ts_start, '%Y-%m-%d %H:%M:%S')
    user_ts_start = user_ts_start - timedelta(seconds = 2)
    parseMeTotal=""
    for line in f:
        getTimeStamps = line.split(' ')[1:3]
        try:
            time = getTimeStamps[0] + " " + getTimeStamps[1]
            currTime = datetime.strptime(time, '%Y/%m/%d %H:%M:%S.%f')
            if(currTime >= user_ts_start):
                parseMeTotal += line
        except:
            tempNONUSEDVARIABLE = ""
    temp_file = path+"/downloads/"+fileNameToUse+".log"
    with open(temp_file,"w") as F_Out:
        F_Out.write(parseMeTotal)

    if parseMeTotal != "":
        ret_val = hc_Log_read(temp_file, send, parseBased, fileNameToUse)
    else:
        ret_val = -1
    return ret_val


def find_ts_interval(user_ts_start, user_ts_end, fo, send, parseBased, fileNameToUse):
    counter = 0
    start_index = 0
    end_index = 0
    end_ts_found = 0
    temp_filename = path + "/downloads/temp_file.log"
    temp_file_obj = open(temp_filename, "w", 1)
    
    user_ts_start= parseTime(user_ts_start) # datetime.strptime(user_ts_start, "%Y-%m-%d %H:%M:%S")
    user_ts_end = parseTime(user_ts_end) # datetime.strptime(user_ts_end, "%Y-%m-%d %H:%M:%S")
    try:
        user_ts_start = user_ts_start - timedelta(seconds = 2)
    except:
        user_ts_start= parseTime(user_ts_start + " 00:00:02")
    try:
        user_ts_end = user_ts_end + timedelta(seconds = 2)
    except:
        user_ts_end= parseTime(user_ts_end + " 00:00:02")
    parseMeTotal=""
    f = fo.readlines()
    for line in f:
        getTimeStamps = line.split(' ')[1:3]
        try:
            time = getTimeStamps[0] + " " + getTimeStamps[1]
            currTime = datetime.strptime(time, '%Y/%m/%d %H:%M:%S.%f')
            if(currTime >= user_ts_start and currTime <= user_ts_end):
                parseMeTotal += line
        except:
            tempNONUSEDVARIABLE = ""
    temp_file = path+"/downloads/"+fileNameToUse+".log"
    with open(temp_file,"w") as F_Out:
        F_Out.write(parseMeTotal)

    if parseMeTotal != "":
        ret_val = hc_Log_read(temp_file, send, parseBased, fileNameToUse)
    else:
        ret_val = -1
    return ret_val

def update_json(key_list, value_list):
    json_dic = {}
    for i in range(key_list):
        json.dic.update({key_list[i]: value_list[i]})
    with open(json_file, "a") as jfile:
        json.dump(json_dic, jfile)

    jfile.close()


# logfile = "/Users/tejasmenon/Documents/Pulse_Secure/LogsAndDiagnostics_firewall/Logs/debuglog.log"
# file_object=open(logfile,'r',1)


def click_func(file_object, user_ts_start, user_ts_end, user_list, send, parseBased, fileNameToUse):
    now = time.time()
    
    for subdir, dirs, files in os.walk(path+"/downloads"):
        for file in files:
            # print os.path.join(subdir, file)
            filepath = subdir + os.sep + file
            if file == "counter.txt":
                continue
            if filepath.endswith(".log") or filepath.endswith(".txt"):
                creationTimePlus6 = os.path.getctime(filepath)+21600
                if(now > creationTimePlus6):
                    os.remove(filepath)
    try:
        for i in range(len(user_list)):
            user_list[i] += "@pulsesecure.net"
    except TypeError:
        user_list = []
    mail_list = user_list
    global receivers
    receivers = mail_list
    ret_val = 1
    if not user_ts_start.strip(" ") and not user_ts_end.strip(" "):
        thread = threading.Thread(target=hc_Log_read, args=(file_object, send, parseBased, fileNameToUse))
        thread.start()       
        # ret_val = hc_Log_read(file_object, send, parseBased, fileNameToUse)
    elif user_ts_start.strip(" ") and user_ts_end.strip(" "):
        ret_val = find_ts_interval(user_ts_start, user_ts_end, file_object, send, parseBased, fileNameToUse)
    else:
        ret_val = find_ts(user_ts_start, file_object, send, parseBased, fileNameToUse)
    return ret_val

