import sys
import tailer
import json
from time import sleep

class OneviewSyslogParser(object):
    SEVERITY_MAP = {'2':'CRITICAL', '3':'ERROR', '4':'WARNING', '5':'UNKNOWN', '6':'OK', '7':'DEBUG'}

    def __init__(self, fileName):
        self.fileName = fileName

    def tokenize_event_message(self, event):
        eventTokens = {}
        #print("Event to tokenize :- {}".format(event))
        #print("Karthik calling tokenize")
        '''
        Sample event message: (for critical alert)
        event - <2> 2019-09-12T05:54:40.133Z cs-oneview1.cbcng.local ovgd server-profiles [cs-esx1] [deecb4d5-bb21-4729-b6c4-5d6773317a0e|Connection|Locked|None|None] [An error has occurred on connection 19.  Interconnect {"name":"ConvergedSystem-Encl1, interconnect 1","uri":"/rest/interconnects/5e90904c-5159-4c3a-a381-d690148ca094"} port 1 subport a is unlinked.If the server {"name":"ConvergedSystem-Encl1, bay 1","uri":"/rest/server-hardware/31353337-3135-5A43-3333-343353373950"} is power cycling or powered off, connectivity alerts may occur as the network adapter is either disconnected or negotiates connectivity with the interconnect. These alerts can be ignored and should clear automatically. If this server is booted up and running an operating system, this alert indicates a loss of connectivity between the network adapter and the interconnect. Verify the configuration of the operating system, health and link status of the downlink ports on which the connection depends. If the problem persists, please contact your authorized support representative and provide them with a support dump.]
        '''
        '''
        Sample event message: (for power stats)
        event - <6> 2019-07-31T10:45:00Z 10.188.239.35 oneview ServerStats [0000A66101, bay 6] [AmbientTemperature=29 dec C|AveragePower=136 watts|CpuAverageFreq=2801 Hz|CpuUtilization=23 %|PeakPower=142 watts|PowerCap=None]
        '''

        allTokens = event.split('[')
        '''
        print("\nTokens:")
        for token in allTokens:
            print(token)
        print('\n\n')
        '''
        if len(allTokens) < 3:
            #print("Improper message received. ")
            return None

        #print("len(allTokens) - {}".format(len(allTokens)))
        #--------------------------- First token processing..

        token1 = allTokens[0].strip()
        token1SubSplit = token1.split(' ')
        
        eventTokens['severity'] = token1SubSplit[0]
        eventTokens['eventTimeStamp'] = token1SubSplit[1]
        eventTokens['oneviewIp'] = token1SubSplit[2]
        eventTokens['alertCategory'] = token1SubSplit[4]
    
        idx = eventTokens['severity'][1]
        eventTokens['severity'] = self.SEVERITY_MAP[idx] # Mapping severity to verbose.
        #---------------------------
    
        #--------------------------- Second token processing..
        temp = allTokens[1].strip()
        eventTokens['alertResource'] = temp[0:len(temp)-1] # Remove the closing big bracket
        if eventTokens['alertCategory'] == 'server-hardware':
            eventTokens['serialNumber'] = eventTokens['alertResource'].split(';')[-1]
            eventTokens['alertResource'] = eventTokens['alertResource'].split(';')[0]
        else:
            eventTokens['serialNumber'] = "NA"
    
        # Init to blanks before actual init
        eventTokens["alertId"] = eventTokens["alertStatus"] = eventTokens["caseId"] = ""
        eventTokens["caseStatus"] = eventTokens["caseContactDetails"] = ""

        if len(allTokens) == 3:
            temp = allTokens[2].strip()
            eventTokens['alertMessage'] = temp[0:len(temp)-1]
            eventTokens['alertType'] = "Stats"
        
        elif len(allTokens) == 5:
            #----- Processing alert message. Token #4.
            temp = allTokens[4].strip()
            eventTokens['alertMessage'] = temp[0:len(temp)-1]
            
            '''
            Split the eventId and contact details. 
                allTokens[2] = 1269|Storage|Active|None|None]
                allTokens[2] = 1186|Storage|Active|None|{111231231|test@hpe.com|Open}
            '''
            temp = allTokens[2].strip(' ')
            #temp = allTokens[2].strip('{')
            #temp = allTokens[2].strip('}')
            #contactDetails = temp[0:len(temp)-1] # Remove the pipe symbol at the end
            contactSubSplit = temp.split('|')
            #print("contactSubSplit - {}".format(contactSubSplit))
                
            eventTokens["alertId"] = contactSubSplit[0]
            eventTokens["alertType"] = contactSubSplit[1]
            eventTokens["alertStatus"] = contactSubSplit[2]
        
            if contactSubSplit[4] != "None":
                eventTokens["caseId"] = contactSubSplit[4][1:]
                eventTokens["caseContactDetails"] = contactSubSplit[5]
                eventTokens["caseStatus"] = contactSubSplit[6][:-1]
            
            # Child events
            childEventArray = []
            
            temp = allTokens[3].strip()
            #print("type(temp) - {}, len(temp) - {}, temp - {}".format(type(temp), len(temp), temp))
            if len(temp) > 2: # Just a new line char or string ']]' present
                temp = temp[0:len(temp)-2]
                #print("temp - {}".format(temp))
                childEventsSubSplit = temp.split(',')

                # If child alerts are present, it will be comma separated strings.
                if len(childEventsSubSplit) > 0:
                    for element in childEventsSubSplit:
                        element = element.strip()
                        #print("type(element) - {}. element - {}".format(type(element), element))
                        childId = int(element)
                        #print(childId)
                        childEventArray.append(childId)

            eventTokens["childEvents"] = childEventArray
        
            #print("eventTokens {}".format(eventTokens))
        else:
            print("**********************************.Non compliant message received.. Please reconfirm.**********************************")
            alertMessage = "**********************************.Non compliant message received.. Please reconfirm.**********************************"
        
        
            eventTokens['alertMessage'] = "Non compliant message.\n]n" + event
            #print("\n\nalertMessage - {}\n\n".format(alertMessage))
    
        #print("eventTokens {}".format(json.dumps(eventTokens, indent=2)))
        return eventTokens


    def follow(self):
        return tailer.follow(open(self.fileName))
