import os
import csv
import sys
import json
import time
import bisect
import zipfile
import argparse
import subprocess



import shutil


# --------------------------------Main-Program-----------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Protecode-SC Application Scan ")

    parser.add_argument('--no-compress', dest='nocompress', action='store_true',  help="Use to skip binary file compression");
    parser.add_argument('--url', dest='url', action='store_true',  help="Use if binary file is located behind http/https url ");

    parser.add_argument('--debug', dest='debug', action='store_true',  help="Print debug output");


    parser.add_argument('--keep-artifacts', dest='keepArtifacts', action='store_true', help="Keep intermediate directory, vulnerability and component csv files, and json file.");


    group1 = parser.add_argument_group('required arguments')
    group1.add_argument('--app', dest='appName', required=True, help="Application (in binary format) to upload & scan ");

    group1.add_argument('--protecode-host', dest='protecodeHost', required=True, help="Protecode ES Server Address");
    group1.add_argument('--protecode-username', dest='protecodeUsername', required=True, help="Protecode ES Server User Name");
    group1.add_argument('--protecode-password', dest='protecodePassword', required=True, help="Protecode ES Server Password");
    group1.add_argument('--protecode-group', dest='protecodeGroup', required=True, help="Protecode Group ID");
    # Global Assignments
    #-------------------------
    args = parser.parse_args()
    port = '8443'
    sslText = 'true'
    ssl = sslText.lower() == 'true'

    protecodeHost = args.protecodeHost
    protecodeUsername = args.protecodeUsername
    protecodePassword = args.protecodePassword
    protecodeGroup = args.protecodeGroup;



    protecodeLoginAndPass = protecodeUsername + ":" + protecodePassword

    if (args.debug):
        print ("Running in debug mode")


    #get all groups that Protecode user belongs to
    print ("\n\nGetting all groups that Protecode SC user in part of...")
    cmd = "curl -u " + protecodeLoginAndPass + " https://" + protecodeHost + "/api/groups/"
    print (cmd)
    try:
        urlResp = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
        returncode = e.returncode
        print("Error in retrieving groups:{} \n ReturnCode:{}". format(output, returncode))
        sys.exit(-1)
    if (urlResp):
        if (args.debug):
            print(urlResp)
        json_obj = json.loads(urlResp.decode("utf-8"))
        if (args.debug):
            print (json_obj)
        if (json_obj['meta']['code'] == 200):
            if(args.debug):
                print(json_obj['groups'])
            found = False
            for group in json_obj['groups']:
                if (group['name']==args.protecodeGroup):
                   protecodeGroup=str(group['id'])
                   if (args.debug):
                       print("Found group id " + protecodeGroup)
                   found = True
            if (not found):
                print("\n\nGroup with name " + args.protecodeGroup + " not found in Protecode SC.  Please check name or create it first.")
                sys.exit(-1)
    else:
        print("Error while getting Protecode SC user's groups. No output obtained. Please check user credentials or network connectivity")


    #---------------------------------------
    #ProTecode SC Upload + Extract + Remove
    #---------------------------------------
    #Upload Application via url:
    id = 0

    application = os.path.basename(args.appName)
    print ("\nApplication:{}".format(application))
    fileName = os.path.splitext(application)[0]
    print ("FileName:{}".format(fileName))

    print ("\n\nUploading Application...")
        #Compress:
    if not (args.nocompress):
            zipFile = fileName + ".zip"
            zipHandle = zipfile.ZipFile(zipFile, 'w')
            zipHandle.write(args.appName, compress_type=zipfile.ZIP_DEFLATED)
            zipHandle.close()
    else:
            zipFile = args.appName
        #print ("No-Compress:{} zipFile:{}".format(args.nocompress, zipfile))

        # Upload by file/pathname
    cmd = "curl -u " + protecodeLoginAndPass + " -H Group:" + protecodeGroup + "  -T " + zipFile + " https://" + protecodeHost + "/api/upload/" #protecode-sc.com/api/upload/"
    print (cmd)
    try:
            uploadResp = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
            output = e.output
            returncode = e.returncode
            print(" Error while Uploading:{} \n ReturnCode:{}".format(output, returncode))
            sys.exit(-1)
    if (uploadResp):
            if (args.debug):
                print(uploadResp)
            json_obj = json.loads(uploadResp.decode("utf-8"))
            if (args.debug):
                print (json_obj)
            if (json_obj['meta']['code'] == 200):
                print("Upload Status:{}".format(json_obj['results']['status']))
                print("App ID:{}".format(json_obj['results']['id']))
                id = json_obj['results']['id']
                pollStatus = json_obj['results']['status']
                prodId = json_obj['results']['product_id']

    else:
            print("Error while Uploading. No output obtained. Please check user credentials or network connectivity")


    # Exit if upload Failure.
    if (id == 0) or (pollStatus == "F"):
        print("\nUpload failed or application ID is unavailable \nReason:{}".format(json_obj['results']['fail-reason']))
        sys.exit(-1)

    # Run a poll for checking upload status.
    print ("\n \nRunning Upload Polling Status..")
    cmd = "curl -u " + protecodeLoginAndPass + " https://" + protecodeHost + "/api/app/" +  str(id) + "/"
    while (pollStatus != 'R'):
        try:
            pollResp = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            output = e.output
            returncode = e.returncode
            print(" Error while polling upload Status:{} \n ReturnCode:{}". format(output, returncode))
            sys.exit(-1)
        pollJsonObj = json.loads(pollResp.decode("utf-8"))
        if (args.debug):
            print (pollJsonObj)
        if (pollJsonObj['meta']['code'] == 200):
            pollStatus = pollJsonObj['results']['status']
            print ("\nPolling Status:{}".format(pollStatus))
            if (pollStatus == 'F'):
                print ("\nUpload failed, check URL provided to --app argument")
                sys.exit(-1)
        elif (pollJsonObj['meta']['code'] != 200):
            print(" Polling Status failed. Please review errors. Exiting...")
            sys.exit(-1)

    # Extract Scan Results:
    # component.csv extrction
    print ("\n\nDownloading Components Report PDF file ..")
    compOutName = fileName + "_components.pdf"
    opUrl1 =  "https://" + protecodeHost + "/api/app/" + str(id) + "/pdf-report"
    cmd = "curl -u " + protecodeLoginAndPass + " " + opUrl1 + " > " + compOutName
    print (cmd)
    try:
        scanOp1 = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
            output = e.output
            returncode = e.returncode
            print(" Error while extracting component PDF file:{} \n ReturnCode:{}".format(output, returncode))
            sys.exit(-1)


    # Remove the uploaded file.
    print ("\n\nRemoving application from Protecode SC...")
    removeUrl = "https://" + protecodeHost + "/api/app/" + str(id) + "/remove"
    cmd = "curl -X DELETE -u " + protecodeLoginAndPass + " " + removeUrl
    print (cmd)
    try:
        removeResp = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
            output = e.output
            returncode = e.returncode
            print(" Error while removing application:{} \n ReturnCode:{}".format(output, returncode))
            sys.exit(-1)
    if (removeResp):
        jsonRemoveObj = json.loads(removeResp.decode("utf-8"))
        print (jsonRemoveObj)
        if (jsonRemoveObj['meta']['code'] == 200):
            print ("Application Succesfully Removed")
        else:
            print ("Application has been removed from Protecode-SC before ")
    else:
        print("Error while removing application. No output obtained. Please check user credentials or network connectivity")
