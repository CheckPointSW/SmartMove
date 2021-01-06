#!/usr/bin/env python

import sys
import argparse
import json
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
from cpapi import APIClient, APIClientArgs


# printing messages to console and log file
# res_action - response from server, used if response is not OK
# message - message to inform user
# error - message with mark to inform user about issue
# ---
# returns: nothing
def printStatus(res_action, message, error=None):
    line = ""
    if res_action is not None and res_action.success is False:
        if 'errors' in res_action.data:
            for msg_err in res_action.data['errors']:
                line += "WARN:" + "\t" + msg_err['message'] + "\n"
        if 'warnings' in res_action.data:
            for msg_wrn in res_action.data['warnings']:
                line += "WARN:" + "\t" + msg_wrn['message'] + "\n"
        if line == "":
            line = "WARN:" + "\t" + res_action.data['message'] + "\n"
    elif message is not None:
        line += "\t" + message + "\n"
    elif error is not None:
        line += "WARN:" + "\t" + error + "\n"
    if line != "":
        print(line.rstrip())
        file_log.write(line)
        file_log.flush()


# printing info message "process..." with delimeters
# objectsType - string of objects type
# ---
# returns: nothing
def printMessageProcessObjects(objectsType):
    printStatus(None, "==========")
    printStatus(None, "process " + objectsType + " ...")
    printStatus(None, "")


# publishing to database new updates by condition; increasing counter by 1
# counter - is number of new updates. if it equals threshold then updates will be published
# isForced - publishing to database anyway
# ---
# returns: updated counter
def publishUpdate(counter, isForced):
    if counter < 0:
        counter = 0
    counter += 1
    if isForced or counter >= args.threshold:
        if not isForced:
            printStatus(None, "")
        printStatus(None, "----------")
        printStatus(None, "publishing to database...")
        res_publish = client.api_call("publish", {})
        if res_publish.success:
            counter = 0
        printStatus(res_publish, "publish is completed")
        printStatus(None, "----------")
        if isForced:
            printStatus(None, "")
    return counter


# check if response contains message that name of "new" object exists in database
# res_add_obj - response from server
# ---
# returns: True - if the name is duplicated, False - otherwise
def isNameDuplicated(res_add_obj):
    isNameDuplicated = False
    if 'errors' in res_add_obj.data:
        for msg in res_add_obj.data['errors']:
            if msg['message'].startswith("More than one object named") and msg['message'].endswith("exists."):
                isNameDuplicated = True
    return isNameDuplicated


# check if response contains message that IP of "new" object exists in database
# res_add_obj - response from server
# ---
# returns: True - if the IP is duplicated, False - otherwise
def isIpDuplicated(res_add_obj):
    isIpDuplicated = False
    if 'warnings' in res_add_obj.data:
        messagePrefixes = ("Multiple objects have the same IP address",)
        messagePrefixes += ("More than one network have the same IP",)
        messagePrefixes += ("More than one network has the same IP",)
        for msg in res_add_obj.data['warnings']:
            if msg['message'].startswith(messagePrefixes):
                isIpDuplicated = True
    return isIpDuplicated


# check if object from server comes from "global" domain
# serverObject - JSON presentation of object
# ---
# returns: True - if object comes from "global" domain, False - otherwise
def isServerObjectGlobal(serverObject):
    return serverObject['domain']['domain-type'] == "global domain"


# check if object from server comes from "local" domain
# serverObject - JSON presentation of object
# ---
# returns: True - if object comes from "local" domain, False - otherwise
def isServerObjectLocal(serverObject):
    return serverObject['domain']['domain-type'] == "domain"


# adding "new" object to server
# adjusting the name if object with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# apiCommand - short string which indicates what should be done
# payload - JSON representation of "new" object
# userObjectNamePostfix - postfix as number
# changeName=True - True: to try to add object and adjust the name; False: to try to add object and NOT adjust the name
# ---
# returns: added object from server in JSON format, None - otherwise
def addUserObjectToServer(client, apiCommand, payload, userObjectNamePostfix=1, changeName=True):
    isObjectAdded = False
    userObjectNameInitial = ""
    if changeName:
        userObjectNameInitial = payload['name']
    addedObject = None
    while not isObjectAdded:
        res_add_obj = client.api_call(apiCommand, payload)
        printStatus(res_add_obj, None)
        if res_add_obj.success is False:
            if not changeName:
                break
            if isNameDuplicated(res_add_obj):
                payload['name'] = userObjectNameInitial + '_' + str(userObjectNamePostfix)
                userObjectNamePostfix += 1
            else:
                break
        else:
            addedObject = res_add_obj.data
            isObjectAdded = True
    return addedObject


# adding to server the object which contains fields with IP: hosts, networks
# adjusting the name if object with the name exists at server: <initial_object_name>_<postfix>
# using the object from server side if object exsits with the same IP at server
# client - client object
# payload - JSON representation of "new" object
# userObjectType - the type of object: host or network
# userObjectIp - IP which will be used as filter in request to server
# mergedObjectsNamesMap - the map which contains name of user's object (key) and name of resulting object (value)
# ---
# returns: updated mergedObjectsNamesMap
def addCpObjectWithIpToServer(client, payload, userObjectType, userObjectIp, mergedObjectsNamesMap):
    printStatus(None, "processing " + userObjectType + ": " + payload['name'])
    userObjectNameInitial = payload['name']
    userObjectNamePostfix = 1
    isFinished = False
    isIgnoreWarnings = False
    while not isFinished:
        payload["ignore-warnings"] = isIgnoreWarnings
        res_add_obj_with_ip = client.api_call("add-" + userObjectType, payload)
        printStatus(res_add_obj_with_ip, "REPORT: " + userObjectNameInitial + " is added as " + payload['name'])
        if res_add_obj_with_ip.success is False:
            if isIpDuplicated(res_add_obj_with_ip) and not isIgnoreWarnings:
                res_get_obj_with_ip = client.api_query("show-objects", payload={"filter": userObjectIp, "ip-only": True,
                                                                                "type": userObjectType})
                printStatus(res_get_obj_with_ip, None)
                if res_get_obj_with_ip.success is True:
                    if len(res_get_obj_with_ip.data) > 0:
                        for serverObject in res_get_obj_with_ip.data:
                            if isServerObjectLocal(serverObject) and not isReplaceFromGlobalFirst:
                                mergedObjectsNamesMap[userObjectNameInitial] = serverObject['name']
                                break
                            if isServerObjectGlobal(serverObject) and isReplaceFromGlobalFirst:
                                mergedObjectsNamesMap[userObjectNameInitial] = serverObject['name']
                                break
                            mergedObjectsNamesMap[userObjectNameInitial] = serverObject['name']
                        printStatus(None, "REPORT: " + "CP object " + mergedObjectsNamesMap[
                            userObjectNameInitial] + " is used instead of " + userObjectNameInitial)
                        isFinished = True
                    else:
                        isIgnoreWarnings = True
                else:
                    isFinished = True
            elif isNameDuplicated(res_add_obj_with_ip):
                payload['name'] = userObjectNameInitial + '_' + str(userObjectNamePostfix)
                userObjectNamePostfix += 1
            else:
                isFinished = True
        else:
            mergedObjectsNamesMap[userObjectNameInitial] = payload['name']
            isFinished = True
    return mergedObjectsNamesMap


# processing and adding to server the groups which contains list of members
# adjusting the name if group with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# apiCommand - short string which indicates what should be done
# userGroup - group which will be processed and added to server
# mergedObjectsMap - map of objects which will be used for replacing
# mergedGroupsNamesMap - the map which contains name of user's object (key) and name of resulting object (value)
# ---
# returns: updated mergedGroupsNamesMap
def processGroupWithMembers(client, apiCommand, userGroup, mergedObjectsMap, mergedGroupsNamesMap):
    for i, userGroupMember in enumerate(userGroup['Members']):
        if userGroupMember in mergedObjectsMap:
            userGroup['Members'][i] = mergedObjectsMap[userGroupMember]
        elif userGroupMember in mergedGroupsNamesMap:
            userGroup['Members'][i] = mergedGroupsNamesMap[userGroupMember]
    addedGroup = addUserObjectToServer(
        client,
        apiCommand,
        {
            "name": userGroup['Name'],
            "members": userGroup['Members'],
            "comments": userGroup['Comments'],
            "tags": userGroup['Tags']
        }
    )
    return addedGroup


# processing and adding to server the CheckPoint Domains
# adjusting the name if domain with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userDomains - the list of domains which will be processed and added to server
# ---
# returns: mergedDomainsNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processDomains(client, userDomains):
    printMessageProcessObjects("domains...")
    publishCounter = 0
    mergedDomainsNamesMap = {}
    if len(userDomains) == 0:
        return mergedDomainsNamesMap
    for userDomain in userDomains:
        userDomainNameInitial = userDomain['Name']
        printStatus(None, "processing domain: " + userDomain['Name'])
        addedDomain = addUserObjectToServer(
            client,
            "add-dns-domain",
            {
                "name": userDomain['Name'],
                "is-sub-domain": userDomain['IsSubDomain'],
                "comments": userDomain['Comments'],
                "tags": userDomain['Tags']
            }
        )
        if addedDomain is not None:
            mergedDomainsNamesMap[userDomainNameInitial] = addedDomain['name']
            printStatus(None, "REPORT: " + userDomainNameInitial + " is added as " + addedDomain['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userDomainNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedDomainsNamesMap


# processing and adding to server the CheckPoint Hosts
# adjusting the name if host with the name exists at server: <initial_object_name>_<postfix>
# if host contains existing IP address then Host object from server will be used instead
# client - client object
# userHosts - the list of hosts which will be processed and added to server
# ---
# returns: mergedHostsNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processHosts(client, userHosts):
    printMessageProcessObjects("hosts")
    publishCounter = 0
    mergedHostsNamesMap = {}
    if len(userHosts) == 0:
        return mergedHostsNamesMap
    for userHost in userHosts:
        payload = {
            "name": userHost['Name'],
            "ip-address": userHost['IpAddress'],
            "comments": userHost['Comments'],
            "tags": userHost['Tags']
        }
        initialMapLength = len(mergedHostsNamesMap)
        mergedHostsNamesMap = addCpObjectWithIpToServer(client, payload, "host", userHost['IpAddress'],
                                                        mergedHostsNamesMap)
        if initialMapLength == len(mergedHostsNamesMap):
            printStatus(None, "REPORT: " + userHost['Name'] + ' is not added.')
        else:
            publishCounter = publishUpdate(publishCounter, False)
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedHostsNamesMap


# processing and adding to server the CheckPoint Networks
# adjusting the name if network with the name exists at server: <initial_object_name>_<postfix>
# if network contains existing IP subnet then Network object from server will be used instead
# client - client object
# userNetworks - the list of networks which will be processed and added to server
# ---
# returns: mergedNetworksNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processNetworks(client, userNetworks):
    printMessageProcessObjects("networks")
    publishCounter = 0
    mergedNetworksNamesMap = {}
    if len(userNetworks) == 0:
        return mergedNetworksNamesMap
    for userNetwork in userNetworks:
        payload = {
            "name": userNetwork['Name'],
            "subnet4": userNetwork['Subnet'],
            "subnet-mask": userNetwork['Netmask'],
            "comments": userNetwork['Comments'],
            "tags": userNetwork['Tags']
        }
        initialMapLength = len(mergedNetworksNamesMap)
        mergedNetworksNamesMap = addCpObjectWithIpToServer(client, payload, "network", userNetwork['Subnet'],
                                                           mergedNetworksNamesMap)
        if initialMapLength == len(mergedNetworksNamesMap):
            printStatus(None, "REPORT: " + userNetwork['Name'] + ' is not added.')
        else:
            publishCounter = publishUpdate(publishCounter, False)
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedNetworksNamesMap


# processing and adding to server the CheckPoint Ranges
# adjusting the name if range with the name exists at server: <initial_object_name>_<postfix>
# if range contains existing IP start and end then Range object from server will be used instead
# client - client object
# userRanges - the list of ranges which will be processed and added to server
# ---
# returns: mergedRangesNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processRanges(client, userRanges):
    printMessageProcessObjects("ranges")
    publishCounter = 0
    mergedRangesNamesMap = {}
    if len(userRanges) == 0:
        return mergedRangesNamesMap
    serverRangesMap = {}
    serverRangesMapGlobal = {}
    serverRangesMapLocal = {}
    printStatus(None, "reading address ranges from server")
    res_get_ranges = client.api_query("show-address-ranges")
    printStatus(res_get_ranges, None)
    for serverRange in res_get_ranges.data:
        key = serverRange['ipv4-address-first'] + '_' + serverRange['ipv4-address-last']
        if isServerObjectGlobal(serverRange) and key not in serverRangesMapGlobal:
            serverRangesMapGlobal[key] = serverRange['name']
        elif isServerObjectLocal(serverRange) and key not in serverRangesMapLocal:
            serverRangesMapLocal[key] = serverRange['name']
        elif key not in serverRangesMapGlobal and key not in serverRangesMapLocal and key not in serverRangesMap:
            serverRangesMap[key] = serverRange['name']
    printStatus(None, "")
    if sys.version_info >= (3, 0):
        serverRangesMap = serverRangesMap.copy()
        if isReplaceFromGlobalFirst:
            serverRangesMap.update(serverRangesMapLocal)
            serverRangesMap.update(serverRangesMapGlobal)
        else:
            serverRangesMap.update(serverRangesMapGlobal)
            serverRangesMap.update(serverRangesMapLocal)
    else:
        if isReplaceFromGlobalFirst:
            serverRangesMap = dict(
                serverRangesMap.items() + serverRangesMapLocal.items() + serverRangesMapGlobal.items())
        else:
            serverRangesMap = dict(
                serverRangesMap.items() + serverRangesMapGlobal.items() + serverRangesMapLocal.items())
    for userRange in userRanges:
        printStatus(None, "processing range: " + userRange['Name'])
        userRangeNameInitial = userRange['Name']
        key = userRange['RangeFrom'] + '_' + userRange['RangeTo']
        if key in serverRangesMap:
            printStatus(None, None,
                        "More than one range has the same ip: '" + userRange['RangeFrom'] + "' and '" + userRange[
                            'RangeTo'] + "'")
            mergedRangesNamesMap[userRangeNameInitial] = serverRangesMap[key]
            printStatus(None, "REPORT: " + "CP object " + mergedRangesNamesMap[
                userRangeNameInitial] + " is used instead of " + userRangeNameInitial)
        else:
            userRangeNamePostfix = 1
            if userRange['Name'] in serverRangesMap.values():
                printStatus(None, None, "More than one object named '" + userRange['Name'] + "' exists.")
                while userRange['Name'] in serverRangesMap.values():
                    userRange['Name'] = userRangeNameInitial + '_' + str(userRangeNamePostfix)
                    userRangeNamePostfix += 1
            payload = {
                "name": userRange['Name'],
                "ip-address-first": userRange['RangeFrom'],
                "ip-address-last": userRange['RangeTo'],
                "comments": userRange['Comments'],
                "tags": userRange['Tags'],
                "ignore-warnings": True
            }
            addedRange = addUserObjectToServer(client, "add-address-range", payload, userRangeNamePostfix)
            if addedRange is not None:
                mergedRangesNamesMap[userRangeNameInitial] = addedRange['name']
                key = addedRange['ipv4-address-first'] + '_' + addedRange['ipv4-address-last']
                serverRangesMap[key] = addedRange['name']
                printStatus(None, "REPORT: " + userRangeNameInitial + " is added as " + addedRange['name'])
                publishCounter = publishUpdate(publishCounter, False)
            else:
                printStatus(None, "REPORT: " + userRangeNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedRangesNamesMap


# processing and adding to server the CheckPoint Network Groups
# adjusting the name if network group with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userNetworkGroups - the list of network groups which will be processed and added to server
# mergedNetworkObjectsMap - map of network objects which will be used for replacing
# ---
# returns: mergedGroupsNamesDict dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processNetGroups(client, userNetworkGroups, mergedNetworkObjectsMap):
    printMessageProcessObjects("network groups")
    publishCounter = 0
    mergedGroupsNamesDict = {}
    if len(userNetworkGroups) == 0:
        return mergedGroupsNamesDict
    for userNetworkGroup in userNetworkGroups:
        userNetworkGroupNameInitial = userNetworkGroup['Name']
        addedNetworkGroup = None
        if userNetworkGroup['TypeName'] == 'CheckPoint_GroupWithExclusion':
            printStatus(None, "processing network group with exclusion: " + userNetworkGroup['Name'])
            if userNetworkGroup['Include'] in mergedGroupsNamesDict:
                userNetworkGroup['Include'] = mergedGroupsNamesDict[userNetworkGroup['Include']]
            if userNetworkGroup['Except'] in mergedGroupsNamesDict:
                userNetworkGroup['Except'] = mergedGroupsNamesDict[userNetworkGroup['Except']]
            addedNetworkGroup = addUserObjectToServer(
                client,
                "add-group-with-exclusion",
                {
                    "name": userNetworkGroup['Name'],
                    "include": userNetworkGroup['Include'],
                    "except": userNetworkGroup['Except'],
                    "comments": userNetworkGroup['Comments'],
                    "tags": userNetworkGroup['Tags']
                }
            )
        else:
            printStatus(None, "processing network group: " + userNetworkGroup['Name'])
            addedNetworkGroup = processGroupWithMembers(client, "add-group", userNetworkGroup, mergedNetworkObjectsMap,
                                                        mergedGroupsNamesDict)
        if addedNetworkGroup is not None:
            mergedGroupsNamesDict[userNetworkGroupNameInitial] = addedNetworkGroup['name']
            printStatus(None, "REPORT: " + userNetworkGroupNameInitial + " is added as " + addedNetworkGroup['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userNetworkGroupNameInitial + " is not added.")
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedGroupsNamesDict


# processing and adding to server the CheckPoint Simple Gateways
# adjusting the name if simple gateway with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userSimpleGateways - the list of simple gateways which will be processed and added to server
# ---
# returns: mergedSimpleGatewaysNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processSimpleGateways(client, userSimpleGateways):
    printMessageProcessObjects("simple gateways")
    publishCounter = 0
    mergedSimpleGatewaysNamesMap = {}
    if len(userSimpleGateways) == 0:
        return mergedSimpleGatewaysNamesMap
    for userSimpleGateway in userSimpleGateways:
        printStatus(None, "processing simple getway: " + userSimpleGateway['Name'])
        userSimpleGatewayNameInitial = userSimpleGateway['Name']
        addedSimpleGateway = addUserObjectToServer(
            client,
            "add-simple-gateway",
            {
                "name": userSimpleGateway['Name'],
                "ip-address": userSimpleGateway['IpAddress'],
                "comments": userSimpleGateway['Comments'],
                "tags": userSimpleGateway['Tags']
            }
        )
        if addedSimpleGateway is not None:
            mergedSimpleGatewaysNamesMap[userSimpleGatewayNameInitial] = addedSimpleGateway['name']
            printStatus(None, "REPORT: " + userSimpleGatewayNameInitial + " is added as " + addedSimpleGateway['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userSimpleGatewayNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedSimpleGatewaysNamesMap


# processing and adding to server the CheckPoint Zones
# adjusting the name if zone with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userZones - the list of zones which will be processed and added to server
# ---
# returns: mergedZonesNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processZones(client, userZones):
    printMessageProcessObjects("zones")
    publishCounter = 0
    mergedZonesNamesMap = {}
    if len(userZones) == 0:
        return mergedZonesNamesMap
    for userZone in userZones:
        printStatus(None, "processing zone: " + userZone['Name'])
        userZoneNameInitial = userZone['Name']
        addedZone = addUserObjectToServer(
            client,
            "add-security-zone",
            {
                "name": userZone['Name'],
                "comments": userZone['Comments'],
                "tags": userZone['Tags']
            }
        )
        if addedZone is not None:
            mergedZonesNamesMap[userZoneNameInitial] = addedZone['name']
            printStatus(None, "REPORT: " + userZoneNameInitial + " is added as " + addedZone['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userZoneNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedZonesNamesMap


# generate and provide key for Services dictionary
# serverService - service in JSON format
# ---
# returns: string as key
def provideServerServiceKey(serverService):
    key = ""
    if 'port' in serverService:  # key for TCP or UDP or SCTP
        key = serverService['port']
    elif 'icmp-type' in serverService:  # key for ICMP
        key = str(serverService['icmp-type'])
        if 'icmp-code' in serverService and serverService['icmp-code'] != 'null':
            key += "_" + str(serverService['icmp-code'])
    elif 'ip-protocol' in serverService:  # key for Other
        key = serverService['ip-protocol']
    return key


# processing and adding to server the CheckPoint Services (TCP, UDP, SCTP, ICMP or Other)
# adjusting the name if service with the name exists at server: <initial_object_name>_<postfix>
# if service contains existing port then Service object from server will be used instead
# client - client object
# userServices - the list of services which will be processed and added to server
# userServiceType - the type of service which should be processed
# ---
# returns: mergedServicesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processServices(client, userServices, userServiceType):
    printMessageProcessObjects(userServiceType + " services")
    publishCounter = 0
    mergedServicesMap = {}
    serverServicesMap = {}
    serverServicesMapGlobal = {}
    serverServicesMapLocal = {}
    printStatus(None, "reading " + userServiceType + " services from server")
    res_get_services = client.api_query("show-services-" + userServiceType)
    printStatus(res_get_services, None)
    for serverService in res_get_services.data:
        mergedServicesMap[serverService['name']] = serverService['uid']
        key = provideServerServiceKey(serverService)
        isServiceReplacing = False
        if 'port' in serverService and ('protocol' not in serverService or serverService['protocol'] == 'null'):
            isServiceReplacing = True
        if isServerObjectGlobal(serverService) and (key not in serverServicesMapGlobal or isServiceReplacing):
            serverServicesMapGlobal[key] = (serverService['name'], serverService['uid'])
        elif isServerObjectLocal(serverService) and (key not in serverServicesMapLocal or isServiceReplacing):
            serverServicesMapLocal[key] = (serverService['name'], serverService['uid'])
        elif not isServerObjectGlobal(serverService) and not isServerObjectLocal(serverService) and (
                key not in serverServicesMap or isServiceReplacing):
            serverServicesMap[key] = (serverService['name'], serverService['uid'])
    printStatus(None, "")
    if sys.version_info >= (3, 0):
        serverServicesMap = serverServicesMap.copy()
        if isReplaceFromGlobalFirst:
            serverServicesMap.update(serverServicesMapLocal)
            serverServicesMap.update(serverServicesMapGlobal)
        else:
            serverServicesMap.update(serverServicesMapGlobal)
            serverServicesMap.update(serverServicesMapLocal)
    else:
        if isReplaceFromGlobalFirst:
            serverServicesMap = dict(
                serverServicesMap.items() + serverServicesMapLocal.items() + serverServicesMapGlobal.items())
        else:
            serverServicesMap = dict(
                serverServicesMap.items() + serverServicesMapGlobal.items() + serverServicesMapLocal.items())
    if len(userServices) == 0:
        return mergedServicesMap
    for userService in userServices:
        printStatus(None, "processing " + userServiceType + " service: " + userService['Name'])
        userServiceNameInitial = userService['Name']
        key = ""
        duplicationValueMessagePostfix = ""
        if 'Port' in userService:
            key = userService['Port']
            duplicationValueMessagePostfix = "port: " + userService['Port']
        elif 'Type' in userService:
            key = userService['Type']
            duplicationValueMessagePostfix = "type: " + userService['Type']
            if 'Code' in userService and userService['Code'] != 'null':
                key += "_" + userService['Code']
                duplicationValueMessagePostfix = "type / code: " + userService['Type'] + " / " + userService['Code']
        elif 'IpProtocol' in userService:
            key = userService['IpProtocol']
            duplicationValueMessagePostfix = "ip-protocol: " + userService['IpProtocol']
        if key in serverServicesMap:
            printStatus(None, None,
                        "More than one " + userServiceType + " service has the same " + duplicationValueMessagePostfix)
            mergedServicesMap[userServiceNameInitial] = serverServicesMap[key][1]
            printStatus(None, "REPORT: " + "CP object " + serverServicesMap[key][
                0] + " is used instead of " + userServiceNameInitial)
        else:
            userServiceNamePostfix = 1
            serverServicesNames = [serverServiceNameUid[0] for serverServiceNameUid in serverServicesMap.values()]
            if userService['Name'] in serverServicesNames:
                printStatus(None, None, "More than one object named '" + userService['Name'] + "' exists.")
                while userService['Name'] in serverServicesNames:
                    userService['Name'] = userServiceNameInitial + '_' + str(userServiceNamePostfix)
                    userServiceNamePostfix += 1
            payload = {}
            payload["name"] = userService['Name']
            payload["comments"] = userService['Comments']
            payload["tags"] = userService['Tags']
            payload["ignore-warnings"] = True
            if 'Port' in userService:
                payload["port"] = userService['Port']
                payload["source-port"] = userService['SourcePort']
                payload["session-timeout"] = userService['SessionTimeout']
            elif 'Type' in userService:
                payload["icmp-type"] = userService['Type']
                if 'Code' in userService and userService['Code'] != 'null':
                    payload["icmp-code"] = userService['Code']
            elif 'IpProtocol' in userService:
                payload["ip-protocol"] = userService['IpProtocol']
                payload["match-for-any"] = True
            addedService = addUserObjectToServer(client, "add-service-" + userServiceType, payload,
                                                 userServiceNamePostfix)
            if addedService is not None:
                mergedServicesMap[userServiceNameInitial] = addedService['uid']
                key = provideServerServiceKey(addedService)
                serverServicesMap[key] = (addedService['name'], addedService['uid'])
                printStatus(None, "REPORT: " + userServiceNameInitial + " is added as " + addedService['name'])
                publishCounter = publishUpdate(publishCounter, False)
            else:
                printStatus(None, "REPORT: " + userServiceNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedServicesMap


# processing and adding to server the CheckPoint Service Groups
# adjusting the name if service group with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userServicesGroups - the list of service groups which will be processed and added to server
# mergedServicesMap - map of service objects which will be used for replacing
# ---
# returns: mergedServicesGroupsNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processServicesGroups(client, userServicesGroups, mergedServicesMap):
    printMessageProcessObjects("services groups")
    publishCounter = 0
    mergedServicesGroupsNamesMap = {}
    if len(userServicesGroups) == 0:
        return mergedServicesGroupsNamesMap
    for userServicesGroup in userServicesGroups:
        printStatus(None, "processing services group: " + userServicesGroup['Name'])
        userServicesGroupNameInitial = userServicesGroup['Name']
        addedServicesGroup = processGroupWithMembers(client, "add-service-group", userServicesGroup, mergedServicesMap,
                                                     mergedServicesGroupsNamesMap)
        if addedServicesGroup is not None:
            mergedServicesGroupsNamesMap[userServicesGroupNameInitial] = addedServicesGroup['name']
            printStatus(None, "REPORT: " + userServicesGroupNameInitial + " is added as " + addedServicesGroup['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userServicesGroupNameInitial + " is not added.")
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedServicesGroupsNamesMap


# processing and adding to server the CheckPoint Time Groups
# adjusting the name if time group with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userTimesGroups - the list of time groups which will be processed and added to server
# ---
# returns: mergedTimesGroupsNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processTimesGroups(client, userTimesGroups):
    printMessageProcessObjects("times groups")
    publishCounter = 0
    mergedTimesGroupsNamesMap = {}
    if len(userTimesGroups) == 0:
        return mergedTimesGroupsNamesMap
    for userTimesGroup in userTimesGroups:
        printStatus(None, "processing times group: " + userTimesGroup['Name'])
        userTimesGroupNameInitial = userTimesGroup['Name']
        addedTimesGroup = addUserObjectToServer(
            client,
            "add-time-group",
            {
                "name": userTimesGroup['Name'],
                "members": userTimesGroup['Members'],
                "comments": userTimesGroup['Comments'],
                "tags": userTimesGroup['Tags']
            }
        )
        if addedTimesGroup is not None:
            mergedTimesGroupsNamesMap[userTimesGroupNameInitial] = addedTimesGroup['name']
            printStatus(None, "REPORT: " + userTimesGroupNameInitial + " is added as " + addedTimesGroup['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userTimesGroupNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedTimesGroupsNamesMap


# processing and adding to server the CheckPoint Time objects
# adjusting the name if time object with the name exists at server: <initial_object_name>_<postfix>
# client - client object
# userTimes - the list of time objects which will be processed and added to server
# ---
# returns: mergedTimesNamesMap dictionary
# the map contains name of user's object (key) and name of resulting object (value)
def processTimes(client, userTimes):
    printMessageProcessObjects("times")
    publishCounter = 0
    mergedTimesNamesMap = {}
    payload = {}
    if len(userTimes) == 0:
        return mergedTimesNamesMap
    weekdays = {0: "Sun", 1: "Mon", 2: "Tue", 3: "Wed", 4: "Thu", 5: "Fri", 6: "Sat"}
    for userTime in userTimes:
        printStatus(None, "processing time: " + userTime['Name'])
        userTimeNameInitial = userTime['Name']

        payload["name"] = userTime['Name']
        payload["comments"] = userTime['Comments']

        payload["start-now"] = userTime['StartNow']
        payload["start"] = {
            "date": userTime['StartDate'],
            "time": userTime['StartTime']
        }

        payload["end-never"] = userTime['EndNever']
        payload["end"] = {
            "date": userTime['EndDate'],
            "time": userTime['EndTime']
        }

        payload["hours-ranges"] = [
            {
                "enabled": userTime['HoursRangesEnabled_1'],
                "from": userTime['HoursRangesFrom_1'] if userTime['HoursRangesFrom_1'] is not None else "00:00",
                "to": userTime['HoursRangesTo_1'] if userTime['HoursRangesTo_1'] is not None else "00:00",
                "index": 1
            },
            {
                "enabled": userTime['HoursRangesEnabled_2'],
                "from": userTime['HoursRangesFrom_2'] if userTime['HoursRangesFrom_2'] is not None else "00:00",
                "to": userTime['HoursRangesTo_2'] if userTime['HoursRangesTo_2'] is not None else "00:00",
                "index": 2
            },
            {
                "enabled": userTime['HoursRangesEnabled_3'],
                "from": userTime['HoursRangesFrom_3'] if userTime['HoursRangesFrom_3'] is not None else "00:00",
                "to": userTime['HoursRangesTo_3'] if userTime['HoursRangesTo_3'] is not None else "00:00",
                "index": 3
            }
        ]

        daysNames = []  # list of weekdays names e.g. "Sun", "Mon"...
        # weekdays are presented as [1,2,3.. ] in userTime['RecurrenceWeekdays']
        for day in userTime['RecurrenceWeekdays']:
            daysNames.append(weekdays[day])

        payload["recurrence"] = {
            "pattern": "Daily" if userTime['RecurrencePattern'] == 1 else (
                "Weekly" if userTime['RecurrencePattern'] == 2 else (
                    "Monthly" if userTime['RecurrencePattern'] == 3 else None)),
            "weekdays": daysNames
        }

        payload["tags"] = userTime['Tags']

        addedTime = addUserObjectToServer(
            client,
            "add-time",
            payload
        )

        if addedTime is not None:
            mergedTimesNamesMap[userTimeNameInitial] = addedTime['name']
            printStatus(None, "REPORT: " + userTimeNameInitial + " is added as " + addedTime['name'])
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: " + userTimeNameInitial + ' is not added.')
        printStatus(None, "")
    publishUpdate(publishCounter, True)
    return mergedTimesNamesMap


# processing and adding to server the CheckPoint Access Rules
# the rules is added in back order: the last item of list goes first and the first item goes last
# client - client object
# userRules - the list of access rules which will be processed and added to server
# userLayerName - the name of layer where access rules will be added
# skipCleanUpRule - the flag which indicates to exclude "Clean up" rule from layer or not; "Clean up" rule is the last rule in the layer always
# mergedNetworkObjectsMap - map of all network objects (groups is included) which will be used for replacing
# mergedServiceObjectsMap - map of all services objects (groups is included) which will be used for replacing
# mergedTimesGroupsNamesMap - map of time groups objects which will be used for replacing
# ---
# returns: nothing
def addAccessRules(client, userRules, userLayerName, skipCleanUpRule, mergedNetworkObjectsMap, mergedServiceObjectsMap,
                   mergedTimesGroupsNamesMap, mergedTimesNamesMap):
    if userRules is not None:
        publishCounter = 0
        printStatus(None, "processing access rules to " + userLayerName + " layer")
        printStatus(None, "")
        userRulesStartPosition = -2 if skipCleanUpRule else -1
        # userRules[userRulesStartPosition::-1]:
        # -1 - minus means to iterate backwards, 1 means step
        # userRulesStartPosition - start point, length of list "- userRulesStartPosition" because reverse mode is specified
        # end point is not specified - all elements
        for i, userRule in enumerate(userRules[userRulesStartPosition::-1]):
            printStatus(None, "processing access rule: #" + str(len(userRules) - i) + ", " + (
                userRule['Name'] if userRule['Name'] is not None else ""))
            # JSON access rules contain "action" as number
            # "action" number points to the next list of values from SmartMove:
            # 0 = Accept
            # 1 = Drop
            # 2 = Reject
            # 3 = SubPolicy
            actions = {0: "accept", 1: "drop", 2: "reject", 3: "apply layer"}
            sources = []
            for source in userRule['Source']:
                sourceName = source['Name']
                sourceName = mergedNetworkObjectsMap[
                    sourceName] if sourceName in mergedNetworkObjectsMap else sourceName
                sources.append(sourceName)
            destinations = []
            for destination in userRule['Destination']:
                destinationName = destination['Name']
                destinationName = mergedNetworkObjectsMap[
                    destinationName] if destinationName in mergedNetworkObjectsMap else destinationName
                destinations.append(destinationName)
            services = []
            for service in userRule['Service']:
                serviceName = service['Name']
                serviceName = mergedServiceObjectsMap[
                    serviceName] if serviceName in mergedServiceObjectsMap else serviceName
                services.append(serviceName)
            times = []
            for time in userRule['Time']:
                timeName = time['Name']

                # support of time-ranges along with time-groups is added
                if timeName in mergedTimesGroupsNamesMap:
                    timeName = mergedTimesGroupsNamesMap[timeName]
                elif timeName in mergedTimesNamesMap:
                    timeName = mergedTimesNamesMap[timeName]
                else:
                    timeName = timeName
                # timeName = mergedTimesGroupsNamesMap[timeName] if timeName in mergedTimesGroupsNamesMap else timeName

                times.append(timeName)
            payload = {
                "layer": userRule['Layer'],
                "position": "top",
                "name": userRule['Name'],
                "action": actions[userRule['Action']],
                "destination": destinations,
                "destination-negate": userRule['DestinationNegated'],
                "enabled": userRule['Enabled'],
                "service": services,
                "source": sources,
                "source-negate": userRule['SourceNegated'],
                "time": times,
                "track": {"type": "None" if userRule['Track'] == 0 else "Log"},
                "comments": userRule['Comments']
            }
            if userRule['Action'] == 3:
                payload["inline-layer"] = userRule['SubPolicyName']
            if userRule['ConversionComments'].strip() != "":
                payload["custom-fields"] = {"field-1": userRule['ConversionComments']}
            addedRule = addUserObjectToServer(client, "add-access-rule", payload, changeName=False)
            if addedRule is not None:
                printStatus(None, "REPORT: access rule is added")
                publishCounter = publishUpdate(publishCounter, False)
            else:
                printStatus(None, "REPORT: access rule is not added")
            printStatus(None, "")
        publishUpdate(publishCounter, True)


# processing and adding to server the CheckPoint Package with Layers and Access Rules
# client - client object
# userPackage - the package which contains layers and access rules
# mergedNetworkObjectsMap - map of all network objects (groups is included) which will be used for replacing
# mergedServiceObjectsMap - map of all services objects (groups is included) which will be used for replacing
# mergedTimesGroupsNamesMap - map of time groups objects which will be used for replacing
# ---
# returns: added package in JSON format
def processPackage(client, userPackage, mergedNetworkObjectsMap, mergedServiceObjectsMap, mergedTimesGroupsNamesMap,
                   mergedTimesNamesMap):
    printMessageProcessObjects("package")
    addedPackage = None
    if userPackage is not None:
        publishCounter = 0
        printStatus(None, "processing package: " + userPackage['Name'])
        addedPackage = addUserObjectToServer(
            client,
            "add-package",
            {
                "name": userPackage['Name'],
                "threat-prevention": False,
                "tags": userPackage['Tags']
            },
            changeName=False
        )
        if addedPackage is None:
            printStatus(None, "REPORT: " + userPackage['Name'] + " package is not added")
            return addedPackage
        printStatus(None, "REPORT: " + userPackage['Name'] + " package is added")
        printStatus(None, "")
        publishCounter = publishUpdate(publishCounter, True)
        if userPackage['SubPolicies'] is not None:
            for userSubLayer in userPackage['SubPolicies']:
                printStatus(None, "processing access layer: " + userSubLayer['Name'])
                addedSubLayer = addUserObjectToServer(
                    client,
                    "add-access-layer",
                    {
                        "name": userSubLayer['Name'],
                        "add-default-rule": False,
                        "applications-and-url-filtering": userSubLayer['ApplicationsAndUrlFiltering'],
                        "comments": userSubLayer['Comments'],
                        "tags": userSubLayer['Tags']
                    },
                    changeName=False
                )
                if addedSubLayer is None:
                    printStatus(None, "REPORT: " + userSubLayer['Name'] + " layer is not added")
                    continue
                printStatus(None, "REPORT: " + userSubLayer['Name'] + " layer is added")
                printStatus(None, "")
                publishCounter = publishUpdate(publishCounter, True)
                addAccessRules(client, userSubLayer['Rules'], userSubLayer['Name'], False, mergedNetworkObjectsMap,
                               mergedServiceObjectsMap, mergedTimesGroupsNamesMap, mergedTimesNamesMap)
        if userPackage['ParentLayer'] is not None:
            addAccessRules(client, userPackage['ParentLayer']['Rules'], "parent", True, mergedNetworkObjectsMap,
                           mergedServiceObjectsMap, mergedTimesGroupsNamesMap, mergedTimesNamesMap)
    return addedPackage


# processing and adding to server the CheckPoint NAT rules
# NAT rules are added if package has been added
# client - client object
# addedPackage - added package in JSON format
# userNatRules - the list of NAT rules which will be processed and added to server
# mergedNetworkObjectsMap - map of all network objects (groups is included) which will be used for replacing
# mergedServiceObjectsMap - map of all services objects (groups is included) which will be used for replacing
# ---
# returns: nothing
def processNatRules(client, addedPackage, userNatRules, mergedNetworkObjectsMap, mergedServiceObjectsMap):
    printMessageProcessObjects("nat rules")
    if addedPackage is None:
        printStatus(None, "REPORT: nat rules can not been added because package was not added")
        return
    publishCounter = 0
    for i, userNatRule in enumerate(userNatRules):
        printStatus(None, "processing nat rule: #" + str(i))
        sourceOrig = ""
        if userNatRule['Source'] is not None:
            sourceOrig = userNatRule['Source']['Name']
            sourceOrig = mergedNetworkObjectsMap[sourceOrig] if sourceOrig in mergedNetworkObjectsMap else sourceOrig
        destinationOrig = ""
        if userNatRule['Destination'] is not None:
            destinationOrig = userNatRule['Destination']['Name']
            destinationOrig = mergedNetworkObjectsMap[
                destinationOrig] if destinationOrig in mergedNetworkObjectsMap else destinationOrig
        serviceOrig = ""
        if userNatRule['Service'] is not None:
            serviceOrig = userNatRule['Service']['Name']
            serviceOrig = mergedServiceObjectsMap[
                serviceOrig] if serviceOrig in mergedServiceObjectsMap else serviceOrig
        sourceTrans = ""
        if userNatRule['TranslatedSource'] is not None:
            sourceTrans = userNatRule['TranslatedSource']['Name']
            sourceTrans = mergedNetworkObjectsMap[
                sourceTrans] if sourceTrans in mergedNetworkObjectsMap else sourceTrans
        destinationTrans = ""
        if userNatRule['TranslatedDestination'] is not None:
            destinationTrans = userNatRule['TranslatedDestination']['Name']
            destinationTrans = mergedNetworkObjectsMap[
                destinationTrans] if destinationTrans in mergedNetworkObjectsMap else destinationTrans
        serviceTrans = ""
        if userNatRule['TranslatedService'] is not None:
            serviceTrans = userNatRule['TranslatedService']['Name']
            serviceTrans = mergedServiceObjectsMap[
                serviceTrans] if serviceTrans in mergedServiceObjectsMap else serviceTrans
        payload = {
            "package": userNatRule['Package'],
            "position": "bottom",
            "comments": userNatRule['Comments'],
            "enabled": userNatRule['Enabled'],
            "method": "static" if userNatRule['Method'] == 0 else "hide",
            "original-source": sourceOrig,
            "original-destination": destinationOrig,
            "original-service": serviceOrig,
            "translated-source": sourceTrans,
            "translated-destination": destinationTrans,
            "translated-service": serviceTrans
        }
        addedNatRule = addUserObjectToServer(client, "add-nat-rule", payload, changeName=False)
        if addedNatRule is not None:
            printStatus(None, "REPORT: nat rule is added")
            publishCounter = publishUpdate(publishCounter, False)
        else:
            printStatus(None, "REPORT: nat rule is not added")
        printStatus(None, "")
    publishCounter = publishUpdate(publishCounter, True)


# START

args_parser = argparse.ArgumentParser()

args_parser._optionals.title = "arguments"

args_parser.add_argument('-r', '--root', action="store_true",
                         help="If administrator logged into the management server and wants to receive SuperUser permissions, 'login-as-root' feature might be used. " +
                              "In this case providing additional login credentials is not required.")
args_parser.add_argument('-m', '--management', default='127.0.0.1',
                         help="Management server IP address or name. Default: 127.0.0.1")
args_parser.add_argument('--port', type=int,
                         help="Server port. Default: 443")
args_parser.add_argument('-u', '--user',
                         help="User name")
args_parser.add_argument('-p', '--password',
                         help="User password")
args_parser.add_argument('-f', '--file', default='cp_objects.json',
                         help="JSON file with CheckPoint Objects. Default: cp_objects.json")
args_parser.add_argument('-t', '--threshold', type=int, default=100,
                         help="Parameter specifies maximum number of Check Point objects/rules to add before starting publish operation. Default: 100")
args_parser.add_argument('-d', '--domain', default=None,
                         help="The name/uid of the domain you want to log into in an MDS environment.")
args_parser.add_argument('--replace-from-global-first', default="false",
                         help="The argument indicates that SmartConnector should use 'Global' objects at first, by default it uses 'Local' objects. [true, false]")

args = args_parser.parse_args()

file_name_log = "smartconnector"
if args.file != "cp_objects.json":
    file_name_log += "_" + os.path.splitext(args.file)[0]
file_name_log += ".log"
if os.path.exists(file_name_log):
    os.remove(file_name_log)
file_log = open(file_name_log, "w+")

if not args.root and args.user is None:
    print("")
    printStatus(None, None, "No user or root option is specified.")
    print("")
    args_parser.print_help()
elif args.root and args.user is not None:
    print("")
    printStatus(None, None, "Command contains ambiguous parameters. User is unexpected when logging in as root.")
    print("")
    args_parser.print_help()
elif args.root and args.management != '127.0.0.1':
    print("")
    printStatus(None, None, "Command contains ambiguous parameters. Management is unexpected when logging in as root.")
    print("")
    args_parser.print_help()
elif not args.root and args.password is None:
    print("")
    printStatus(None, None, "No password option is specified.")
    print("")
    args_parser.print_help()
elif not os.path.isfile(args.file):
    print("")
    printStatus(None, None, "The file does not exists")
    print("")
    args_parser.print_help()
elif args.replace_from_global_first.lower() != "true" and args.replace_from_global_first.lower() != "false":
    print("")
    printStatus(None, None,
                "smartconnector.py: error: argument --replace-from-global-first: invalid boolean value: '" + args.replace_from_global_first + "'")
    print("")
    args_parser.print_help()
else:
    if args.replace_from_global_first.lower() == "true":
        isReplaceFromGlobalFirst = True
    elif args.replace_from_global_first.lower() == "false":
        isReplaceFromGlobalFirst = False
    printStatus(None, "Input arguments:")
    printStatus(None, "root flag is set" if args.root else "root flag is not set")
    printStatus(None, "management: " + args.management)
    printStatus(None,
                "port: " + str(args.port) if args.port is not None else "port: is not set, default value will be used")
    printStatus(None, "domain: " + args.domain if args.domain is not None else "domain: is not set")
    printStatus(None, "user: " + args.user if args.user is not None else "user: is not set")
    printStatus(None, "password: ***" if args.password is not None else "password: is not set")
    printStatus(None, "file: " + args.file)
    printStatus(None, "threshold: " + str(args.threshold))
    printStatus(None, "replace-from-global-first: " + str(isReplaceFromGlobalFirst))
    printStatus(None, "===========================================")
    printStatus(None, "reading and parsing processes are started for JSON file: " + args.file)
    with open(args.file) as json_file:
        json_data = json.load(json_file)
    # define lists of CheckPoint Objects
    userDomains = []
    userHosts = []
    userNetworks = []
    userRanges = []
    userNetGroups = []
    userSimpleGateways = []
    userZones = []
    userServicesTcp = []
    userServicesUdp = []
    userServicesSctp = []  # is not used in Cisco
    userServicesIcmp = []  # is not used in Cisco
    userServicesOther = []
    userServicesGroups = []
    userTimesGroups = []
    userTimes = []
    userPackage = None
    userNatRules = []
    for jsonObject in json_data:
        if jsonObject is None or 'TypeName' not in jsonObject:
            continue
        if jsonObject['TypeName'] == 'CheckPoint_Domain':
            userDomains.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_Host':
            userHosts.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_Network':
            userNetworks.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_Range':
            userRanges.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_NetworkGroup' or jsonObject[
            'TypeName'] == 'CheckPoint_GroupWithExclusion':
            userNetGroups.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_SimpleGateway':
            userSimpleGateways.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_Zone':
            userZones.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_TcpService':
            userServicesTcp.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_UdpService':
            userServicesUdp.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_SctpService':
            userServicesSctp.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_IcmpService':
            userServicesIcmp.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_OtherService':
            userServicesOther.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_ServiceGroup':
            userServicesGroups.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_TimeGroup':
            userTimesGroups.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_Time':
            userTimes.append(jsonObject)
        if jsonObject['TypeName'] == 'CheckPoint_Package':
            userPackage = jsonObject
        if jsonObject['TypeName'] == 'CheckPoint_NAT_Rule':
            userNatRules.append(jsonObject)

    printStatus(None, "reading and parsing processes are completed for JSON file: " + args.file)
    client_args = None
    if args.port is not None:
        client_args = APIClientArgs(server=args.management, port=args.port)
    else:
        client_args = APIClientArgs(server=args.management)
    with APIClient(client_args) as client:
        client.debug_file = "api_calls.json"
        printStatus(None, "checking fingerprint")
        if client.check_fingerprint() is False:
            printStatus(None, "Could not get the server's fingerprint - Check connectivity with the server.")
        else:
            if args.root:
                msg = "login as root to "
                if args.domain is not None:
                    msg += args.domain + " domain of local server"
                else:
                    msg += "local server"
                printStatus(None, msg)
                login_res = client.login_as_root(domain=args.domain)
            else:
                msg = "login as " + args.user + " to "
                if args.domain is not None:
                    msg += args.domain + " domain of " + args.management + " server"
                else:
                    msg += args.management + " server"
                printStatus(None, msg)
                login_res = client.login(args.user, args.password, domain=args.domain)
            if login_res.success is False:
                printStatus(None, "Login failed: {}".format(login_res.error_message))
            else:
                printStatus(None, "")
                mergedNetworkObjectsMap = {}
                mergedNetworkObjectsMap.update(processDomains(client, userDomains))
                mergedNetworkObjectsMap.update(processHosts(client, userHosts))
                mergedNetworkObjectsMap.update(processNetworks(client, userNetworks))
                mergedNetworkObjectsMap.update(processRanges(client, userRanges))
                mergedNetworkObjectsMap.update(processNetGroups(client, userNetGroups, mergedNetworkObjectsMap))
                mergedNetworkObjectsMap.update(processSimpleGateways(client, userSimpleGateways))
                mergedNetworkObjectsMap.update(processZones(client, userZones))
                mergedServicesObjectsMap = {}
                mergedServicesObjectsMap.update(processServices(client, userServicesTcp, "tcp"))
                mergedServicesObjectsMap.update(processServices(client, userServicesUdp, "udp"))
                mergedServicesObjectsMap.update(processServices(client, userServicesSctp, "sctp"))
                mergedServicesObjectsMap.update(processServices(client, userServicesIcmp, "icmp"))
                mergedServicesObjectsMap.update(processServices(client, userServicesOther, "other"))
                mergedServicesObjectsMap.update(
                    processServicesGroups(client, userServicesGroups, mergedServicesObjectsMap))
                mergedTimesGroupsMap = processTimesGroups(client, userTimesGroups)
                mergedTimesMap = processTimes(client, userTimes)
                addedPackage = processPackage(client, userPackage, mergedNetworkObjectsMap, mergedServicesObjectsMap,
                                              mergedTimesGroupsMap, mergedTimesMap)
                processNatRules(client, addedPackage, userNatRules, mergedNetworkObjectsMap, mergedServicesObjectsMap)
                printStatus(None, "==========")
file_log.close()
# END
