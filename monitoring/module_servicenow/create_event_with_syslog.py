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

###---------------------------------------------------------------
# Verify the alert ID. 
# 
###---------------------------------------------------------------
def check_event(s_url, username, password, alert_id):
    """
    Verify that alert_id is already associated with any incident in SNOW
    :param s_url: SNOW Url
    :param username: SNOW user-name
    :param password: SNOW password
    :param alert_id: Alert Id
    :return: None
    """

    # Set the request parameters
    api_url = 'em_event?sysparm_query=u_alert_id=' + alert_id
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.get(url, auth=(username, password), headers=headers)

    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status 1:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        # data = response.json()
        exit()

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    if len(data['result']) > 0:
        print("Alert ID '%s' is already present." % alert_id)
        print("Start updating Event ...." )
        sys_id = data['result'][0]['sys_id']
        return sys_id
    else:
        print("Alert ID '%s' is not found in any event instances." % alert_id)
        print("Start creating a new event....")
        return

###---------------------------------------------------------------
# Create event in SNOW portal
# 
###---------------------------------------------------------------
def create_event(p, tokenized_events, alert_id):

    """
    Create an new incident instance in SNOW.
    :param p:  SNOW URL
    :param tokenized_events:  events from syslog module
    :param alert_id : alert ID
    :return: sys_id
    """
    # print(tokenized_events)

    s_url = p[0]
    username = p[1]
    password = p[2]

    if len(alert_id) == 0:
        print("No alert id found in event body.")
        return

    # check if alert_id is present in SNOW incident.
    event_sys_id = check_event(s_url, username, password, alert_id)
    if event_sys_id is not None:
        # update incident if alert_id is already present, else create a new incident
        update_event(s_url, username, password, event_sys_id, tokenized_events)
        return event_sys_id

    from create_incident_with_syslog import get_cmdb_ci
    cmdb_ci = get_cmdb_ci(s_url, username, password, tokenized_events['alertResource'])
    # cmdb_ci = " "

    # Set the request parameters
    api_url = 'em_event'
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # SNOW parameters
    # caller = '\"' + caller_id + '\"'
    short_descp_message = "Issue with resource '%s'" % tokenized_events['alertResource']

    data = {}
    data['u_short_description'] = short_descp_message
    data['description'] = tokenized_events['alertMessage']
    data['u_time_stamp'] = tokenized_events['eventTimeStamp']
    data['u_severity'] = tokenized_events['severity']
    data['u_status'] = tokenized_events['alertType']
    data['u_node'] = tokenized_events['alertResource']
    # data['u_message'] = tokenized_events['alertMessage']
    # data['u_alertcategory'] = tokenized_events['alertCategory']
    data['u_oneview_ip'] = tokenized_events['oneviewIp']
    data['u_alert_id'] = alert_id
    data['u_alertstatus'] = tokenized_events['alertStatus']
    data['cmdb_ci'] = cmdb_ci
    data1 = json.dumps(data)

    # Do the HTTP request
    response = requests.post(url, auth=(username, password), headers=headers, data=data1)

    # Check for HTTP codes other than 200
    if response.status_code != 201:
        print('Status 2:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        exit()

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    sys_id = data['result']['sys_id']
    print("New event '%s' created in SNOW instance." % data['result']['sys_id'])

    return sys_id


###---------------------------------------------------------------
# Update existing Event in SNOW portal
# 
###---------------------------------------------------------------
def update_event(s_url, username, password, event_sys_id, tokenized_events):
    """
    Update incident instance
    :param s_url: SNOW url
    :param username: SNOW user-name
    :param password: SNOW password
    :param event_sys_id:  incident id
    :param tokenized_events: events
    :return: None
    """

    # Set the request parameters
    api_url = 'em_event/' + event_sys_id
    url = s_url + '/' + api_url

    # Set proper headers
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    data = {}
    data['u_time_stamp'] = tokenized_events['eventTimeStamp'] 
    data['u_severity'] = tokenized_events['severity']
    data['u_status'] = tokenized_events['alertType']
    data['u_node'] = tokenized_events['alertResource']
    data['description'] = tokenized_events['alertMessage']
    data['u_alertcategory'] = tokenized_events['alertCategory']
    data['u_alertstatus'] = tokenized_events['alertStatus']

    data1 = json.dumps(data)

    # Do the HTTP request
    response = requests.put(url, auth=(username, password), headers=headers, data=data1)

    # Check for HTTP codes other than 200
    if response.status_code != 200:
        print('Status 3:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        exit()

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    print("Event '%s' is updated successfully." % data['result']['sys_id'])
