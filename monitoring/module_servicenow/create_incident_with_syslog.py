#!/usr/bin/python
# -*- coding: utf-8 -*-
###
# (C) Copyright (2012-2020) Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Author : GSE Team, HPE
###

import requests
import json

from os import path
from create_event_with_syslog import  create_event
from parser import OneviewSyslogParser as ovParser

###---------------------------------------------------------------
# Read SNOW properties
# 
###---------------------------------------------------------------
def read_properties():
    """
    Read from properties.json file
    :return: properties
    """
    print("Entered -- read_properties()")

    value = str(path.exists('properties.json'))

    if value is False:
        print("File properties.json file does not exist in current directory. Please re-check and try it again. !!!!")
        exit()

    with open('properties.json') as data_file:
        prop = json.load(data_file)

    properties = []
    snow_args = prop["servicenow"]
    incident_prop = prop["incident"]

    properties.append(snow_args["instance_url"])
    properties.append(snow_args["username"])
    properties.append(snow_args["password"])
    properties.append(incident_prop["caller"])
    properties.append(prop["syslog_file"])
    
    print("Leaving -- read_properties()")

    return properties


###---------------------------------------------------------------
# Get CMDB CI
# 
###---------------------------------------------------------------
def get_cmdb_ci(s_url, username, password, server):
    """
    Get Configuration Item(CI) of a server
    :param s_url: SNOW url
    :param username: SNOW username
    :param password: SNOW password
    :param server: server
    :return: sys_id
    """
    print("Entered -- get_cmdb_ci()")

    # Set the request parameters
    api_url = 'cmdb_ci?sysparm_query=name=' + server
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(url, auth=(username, password), headers=headers)

    print("Leaving -- get_cmdb_ci()")
    
    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        return 

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
        
    if len(data['result']) > 0:
        sys_id = data['result'][0]['sys_id']
        return sys_id
    else:
        return None


###---------------------------------------------------------------
# Get caller Sys ID
# 
###---------------------------------------------------------------
def get_caller_sys_id(properties):
    """
    Get sys_id of caller name
    :param properties:  SNOW credentials
    :return: sys_id
    """
    
    print("Entered -- get_caller_sys_id()")

    s_url = properties[0]
    username = properties[1]
    password = properties[2]
    caller = properties[3]

    # Set the request parameters
    api_url = 'sys_user?sysparm_query=user_name=' + caller
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(url, auth=(username, password), headers=headers)

    print("Leaving -- get_caller_sys_id()")
    
    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        exit()

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    if len(data['result']) > 0:
        sys_id = data['result'][0]['sys_id']
        return sys_id
    else:
        print("SNOW User '%s' is not found in SNOW. Try with another user name !!!." % caller)
        exit()

###---------------------------------------------------------------
# Check if incident already exists in SNOW
# 
###---------------------------------------------------------------
def check_incident(s_url, username, password, alert_id, tokenized_events):
    """
    Verify that alert_id is already associated with any incident in SNOW
    :param s_url: SNOW Url
    :param username: SNOW user-name
    :param password: SNOW password
    :param alert_id: Alert Id
    :param caller_id:  caller id
    :return: NOne
    """
    
    print("Entered -- check_incident()")
    
    # Set the request parameters
    qShortDescription = tokenized_events["oneviewIp"] + " :-- " + tokenized_events["alertResource"] +  " :-- " +  tokenized_events["alertMessage"]
    api_url = 'incident?sysparm_query=short_description=' + qShortDescription[:160]
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(url, auth=(username, password), headers=headers)

    print("Leaving -- check_incident()")
    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        return

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    if len(data['result']) > 0:
        #print("Alert ID '%s' is already present in '%s' incident." % (alert_id, data['result'][0]['number']))
        print("Alert is already present in {} incident.".format(data['result'][0]['number']))
        print("Start updating {} incident  with remote support service details.".format(data['result'][0]['number']))
        sys_id = data['result'][0]['sys_id']
        return sys_id
    else:
        print("Alert {} is not found in any incident intances.".format(alert_id))
        print("Start creating a new incident.")
        return

###---------------------------------------------------------------
# Create SNOW incident (Alert is not present in SNOW)
# 
###---------------------------------------------------------------
def create_incident(p, tokenized_events, caller_id, alert_id):

    """
    Create an new incident instance in SNOW.
    :param p:  SNOW URL
    :param tokenized_events:  events from syslog module
    :param caller_id: caller sys_id
    :return: sys_id
    """
    # print(tokenized_events)
    print("Entered -- create_incident()")

    s_url = p[0]
    username = p[1]
    password = p[2]

    if len(alert_id) == 0:
        print("No alert id found in event body.")
        return

    # check if alert_id is present in SNOW incident.
    incident_sys_id = check_incident(s_url, username, password, alert_id, tokenized_events)
    if incident_sys_id:
        # update incident if alert_id is already present, else create a new incident
        update_incident(s_url, username, password, incident_sys_id, tokenized_events)
        return incident_sys_id

    cmdb_ci = get_cmdb_ci(s_url, username, password, tokenized_events['alertResource'])

    # Set the request parameters
    api_url = 'incident'
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # SNOW parameters
    # caller = '\"' + caller_id + '\"'
    short_descp_message = "Issue with resource - {}".format(tokenized_events['alertResource'])
    
    qShortDescription = tokenized_events["oneviewIp"] + " :-- " + tokenized_events["alertResource"] +  " :-- " +  tokenized_events["alertMessage"]
    api_url = 'incident?sysparm_query=short_description=' + qShortDescription[:160]

    # Syslog module parameters
    data = {}
    data['caller_id'] = caller_id
    #data['short_description'] = short_descp_message
    data['short_description'] = qShortDescription[:160]
    #data['description'] =  tokenized_events['alertMessage']
    data['description'] =  json.dumps(tokenized_events, indent=4)
    data['u_time_stamp'] = tokenized_events['eventTimeStamp']
    data['u_severity'] = tokenized_events['severity']
    data['u_status'] = tokenized_events['alertType']
    data['u_node'] = tokenized_events['alertResource']
    data['u_message'] = tokenized_events['alertMessage']
    data['u_alertcategory'] = tokenized_events['alertCategory']
    data['u_oneview_ip'] = tokenized_events['oneviewIp']
    data['u_alert_id'] = alert_id
    data['u_alertstatus'] = tokenized_events['alertStatus']
    data['cmdb_ci'] = cmdb_ci
    data['u_case_id'] = tokenized_events['caseId']
    data['u_remote_support_state'] = tokenized_events['caseStatus']
    data['u_primary_contact'] = tokenized_events['caseContactDetails']

    dataJson = json.dumps(data)

    # Do the HTTP request
    response = requests.post(url, auth=(username, password), headers=headers, data=dataJson)

    # Check for HTTP codes other than 200
    if response.status_code != 201:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        return

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    sys_id = data['result']['sys_id']
    print("New Incident {} created in SNOW instance.".format(data['result']['number']))
    
    print("Leaving -- create_incident()")

    return sys_id


###---------------------------------------------------------------
# Update SNOW incident (Alert info already present in SNOW)
# 
###---------------------------------------------------------------
def update_incident(s_url, username, password, incident_sys_id, tokenized_events):
    """
    Update incident instance
    :param s_url: SNOW url
    :param username: SNOW user-name
    :param password: SNOW password
    :param incident_sys_id:  incident id
    :param tokenized_events: events
    :return: None
    """
    print("Entered -- update_incident()")

    # Set the request parameters
    api_url = 'incident/' + incident_sys_id
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Syslog module parameters
    data = {}
    data['u_time_stamp'] = tokenized_events['eventTimeStamp'] 
    data['u_severity'] = tokenized_events['severity']
    data['u_status'] = tokenized_events['alertType']
    data['u_node'] = tokenized_events['alertResource']
    data['u_message'] = tokenized_events['alertMessage']
    data['u_alertcategory'] = tokenized_events['alertCategory']
    data['u_alertstatus'] = tokenized_events['alertStatus']
    data['description'] = json.dumps(tokenized_events, indent=4)

    # Don't overwrite case details if caseID is already present in incident record
    # e.g. childEvent comes first with case details followed by parentEvent details
    if tokenized_events['caseId']:
       data['u_case_id'] = tokenized_events['caseId']
       data['u_remote_support_state'] = tokenized_events['caseStatus']
       data['u_primary_contact'] = tokenized_events['caseContactDetails']

    dataJson = json.dumps(data)

    # Do the HTTP request
    response = requests.put(url, auth=(username, password), headers=headers, data=dataJson)

    print("Leaving -- update_incident()")
    
    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        return

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    #print("Incident '%s' is updated successfully." % data['result']['number'])
    print("Incident {} is updated successfully.".format(data['result']['number']))
    
###---------------------------------------------------------------
# Validate SNOW user supplied via properties file
# 
###---------------------------------------------------------------
def validate_snow_user(properties):
    """
    validate snow username and password
    :param properties: SNOW credentials
    :return: None
    """
    
    print("Entered -- validate_snow_user()")

    url = properties[0]
    username = properties[1]
    password = properties[2]

    # Set the request parameters
    api_url = 'incident?sysparm_limit=1'
    s_url = url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    print("url - {}, username - {}, password - {}".format(s_url, username, password))
    # Do the HTTP request
    response = requests.get(s_url, auth=(username, password), headers=headers)

    # Check for HTTP codes other than 200
    if response.status_code != 200:
        # print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        data = response.json()
        print("Failed to login snow instance with error message '%s' with code %s " % (data['error']['message'],
                                                                                       response.status_code))
        exit()
        
    print("Leaving -- validate_snow_user()")


###---------------------------------------------------------------
# Validate SNOW properties
# 
###---------------------------------------------------------------
def validate_snow(p):

    """
    Validate SNOW instance with login credentials
    :param p: SNOW instance and its' login credentials
    """
    
    print("Entered -- validate_snow()")

    # validate snow log-in user and password.
    validate_snow_user(p)
    # check for syslog file in properties.json file
    if p[4] is None:
        print("No syslog file in properties.json file. Try it valid file !!!")
        exit()

    # Verify that SNOW user already exists and find its caller_id.
    # If SNOW user(caller) does not exits, it exits the program
    caller_id = get_caller_sys_id(p)
    
    print("Leaving -- validate_snow()")
    
    return caller_id


###---------------------------------------------------------------
# Get alert description
# 
###---------------------------------------------------------------
def get_description(p, alert_id):
    """
    Get alert message of alert_id
    :param p: tokenized message in dictionary format
    :param alert_id: Alert Id
    :return:
    """
    s_url = p[0]
    username = p[1]
    password = p[2]
    
    print("Entered -- get_description()")
	
    # Set the request parameters
    api_url = 'incident?sysparm_query=u_alert_id=' + alert_id
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(url, auth=(username, password), headers=headers)

    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        return

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    print("data - {}".format(json.dumps(data, indent=4)))
    
    print("Leaving -- get_description()")
    
    if len(data['result']) > 0:        
        alert_message = data['result'][0]['u_message']
        return alert_message
		

###---------------------------------------------------------------
# Perform SNOW operation - CRUD on Incident or Event
# 
###---------------------------------------------------------------
def snow_operations(tokenized_message, caller_id, p):

    """
    Creation of SNOW incident based on alert type and category
    :param tokenized_message: Event message from parser module
    :param caller_id: SNOW user
    :p: SNOW instance and its credentials wrapped in dictionary format
    """
    
    print("Entered -- snow_operations()")

    # Do nothing if alert_type is "Stats"
    if tokenized_message['alertType'] != "Stats":
        # Check for Case ID in message body
        if tokenized_message['caseId']:
            print("For each case ID, create incident.")
            # For each child, check if child ID is already present in SNOW, then update incident records.
            # Else create an new incident for each child.
            if tokenized_message['childEvents']:
                # Create incident instances with child alert ids
                for x in tokenized_message['childEvents']:
                    # If the return value 'des' is not None, append new alert messages to existing incident record.  
                    # Else create a new record in incident table with alert message of new tokenized_message.   
                    print("Get description for each child.")
                    #des = get_description(p, str(x))
                    #if des:
                       #message = str(des) + "\n\n" + "Message from Child:" + "\n" + tokenized_message['alertMessage']
                       #tokenized_message['alertMessage'] = message
                    create_incident(tokenized_message, caller_id, str(x))

            # if there is no childEvents, create new incident with case id details
            else:
                create_incident(p, tokenized_message, caller_id, tokenized_message['alertId'])

        # there is no Case ID in message body
        else:
            if (tokenized_message['alertCategory'] == "server-hardware") and (tokenized_message['severity'] == "CRITICAL"):
                print("#### Create a new Incident record.")
                #des = get_description(p, tokenized_message['alertId'])
                # append parent alert messages on existing child's alert message. don't overwrite it. 
                #if des:
                #   message = str(des) + "\n\n" + "Message from Parent event:" + "\n" + tokenized_message['alertMessage']
                #   tokenized_message['alertMessage'] = message
                create_incident(p, tokenized_message, caller_id, tokenized_message['alertId'])
            elif (tokenized_message['alertCategory'] != "server-hardware") and (tokenized_message['severity'] == "CRITICAL"):
                print("#### Create Event in SNOW")
                create_event(p=p, tokenized_events=tokenized_message, alert_id=tokenized_message['alertId'])
            else:
                print("#### Skipping non CRITICAL severity message.")
                pass
                
    print("Leaving -- snow_operations()")


###---------------------------------------------------------------
# Main module. Execution starts from here. 
# 
###---------------------------------------------------------------
if __name__ == '__main__':

    # Read snow credentials from properties.json file
    p = read_properties()
    
    print("Snow properties - {}".format(p))
    # validate SNOW user "caller"
    caller_id = validate_snow(p)
    
    # Parsing syslog file using parser module
    sys_log = p[4]
    parserClient = ovParser(sys_log)
    eventCounter = 0
    print("Starting to wait for tokenised messages..!")
    for eventMsg in parserClient.follow():
        eventCounter +=1
        #print("KVR-TEST: received message from pytail. Delete this msg later. Event Count - {}".format(eventCounter))
        alertDictionary = parserClient.tokenize_event_message(eventMsg)
        if alertDictionary:
            print("Tokenised message :")
            print(json.dumps(alertDictionary, indent=4, sort_keys=True))
            snow_operations(alertDictionary, caller_id, p)
