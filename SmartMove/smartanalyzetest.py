
import sys
import argparse
import os
from pathlib import Path
import glob
from typing import Optional
#added
total_rules = []
rules_any = []
rules_any_source = []
rules_any_destination = []
rules_any_services = []
rules_uncommented = []
rules_disabled = []
rules_times = []
rules_optimization_potential = []
rules_non_logging = []
rules_clean_up = []
total_networks = []
total_services = []
used_total_networks = []
used_total_services = []

folder_list = []

path_without_sub = True

def read_objects(path):
    passed = False
    for file in os.listdir(path):  
        if 'objects.html' in file:
            passed = True
            used_total_networks = 0
            used_total_services = 0
            #print(file)
            with open(path + '\\' + file) as f:
                for index, line in enumerate(f):
                    if 'Hosts Objects' in line:
                        used_total_networks+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'Networks Objects' in line:
                        used_total_networks+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'Ranges Objects' in line:
                        used_total_networks+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'Network Groups Objects' in line:
                        used_total_networks+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'TCP Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'UDP Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'SCTP Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'ICMP Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'RPC Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'DCE-RPC Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'Other Services Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
                    if 'Service Groups Objects' in line:
                        used_total_services+=int(line.split('(x',1)[1].replace(') </h2>','').strip())
            #os.remove(args.path + '\\' + file)
            return used_total_networks, used_total_services, passed
    return 0, 0, passed

def read_rules(path):
    passed = False
    for file in os.listdir(path):
        if 'policy.sh' in file:
            passed = True
            total_rules=0
            rules_uncommented = 0
            rules_any = 0
            rules_any_source = 0
            rules_any_services = 0
            rules_any_destination = 0
            rules_disabled = 0
            rules_times = 0
            rules_non_logging=0
            rules_clean_up=0
            #print(file)
            with open(path + '\\' + file) as f:
                for index, line in enumerate(f):
                    if 'add access-rule' in line:
                        total_rules+=1
                        any = True
                        if 'comments "' not in line:
                            rules_uncommented+=1
                        if ' source "Any"' in line:
                            rules_any_source+=1
                            if any:
                                any = False
                                rules_any+=1
                        if ' service "Any"' in line:
                            rules_any_services+=1
                            if any:
                                any = False
                                rules_any+=1
                        if ' destination "Any"' in line:
                            rules_any_destination+=1
                            if any:
                                any = False
                                rules_any+=1
                        if 'enabled "false"' in line:
                            rules_disabled+=1
                        if 'track-settings.type "None"' in line:
                            rules_non_logging+=1
                        #print("{}".format(line.strip()))
                        if 'time "' in line:
                            rules_times+=1
            #os.remove(args.path + '\\' + file)
            return total_rules, rules_uncommented, rules_any, rules_any_source, rules_any_services, rules_any_destination, rules_disabled, rules_times, rules_non_logging, rules_clean_up, passed
    return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, passed

def read_opt_rules(path):
    passed = False
    for file in os.listdir(path):
        passed = True
        if 'policy_opt.sh' in file:
            rules_optimization_potential = 0
            #print(file)
            with open(path + '\\' + file) as f:
                for index, line in enumerate(f):
                    if 'add access-rule' in line:
                        rules_optimization_potential+=1
                        #print("{}".format(line.strip()))
            #os.remove(args.path + '\\' + file)
            return rules_optimization_potential, passed
    return 0, passed

def show_results(path, indexin, vendor):
    passed_file = False
    for file in os.listdir(path):
        passed_file = True
        if 'managment_report.html' in file:
            print(file)
            passed = "Passed"
            with open(path + '\\' + file) as f:
                for index, line in enumerate(f):
                    # NETWORK OBJECTS
                    if 'Total Network Objects' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip()) 
                        if abs(num - total_networks[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Total Network Objects', test_result,  total_networks[indexin], num ))
                    if 'Unused Network Objects' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip()) 
                        if abs(num - total_networks[indexin] + used_total_networks[indexin]) > 5 or num < 0 or num > total_networks[indexin]:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Unused Network Objects', test_result, total_networks[indexin] - used_total_networks[indexin] , num ))
                    # SERVICES OBJECTS
                    if 'Total Services Objects' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip()) 
                        if abs(num - total_services[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Total Services Objects', test_result, total_services[indexin], num))
                    if 'Unused Services Objects' in line:
                        test_result = "Passed"
                        num = int(line.split( '<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - total_services[indexin] + used_total_services[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Unused Services Objects',test_result, total_services[indexin] - used_total_services[indexin] , num ))
                    # RULES
                    if 'Total Rules' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - total_rules[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Total Rules', test_result, total_rules[indexin], num))
                    if 'Rules utilizing "Any"' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - rules_any[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Rules utilizing "Any"', test_result, rules_any[indexin], num))
                    #BLOCK ANY
                    if '- ANY in Source: ' in line:
                        test_result = "Passed"
                        num = int(line.split('- ANY in Source: ')[1].replace('</td></tr>','').strip())
                        if abs(num - rules_any_source[indexin]) > 5 or num < 0 or num > rules_any[indexin]:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{} {}, {} {}".format('- ANY in Source:', test_result, rules_any_source[indexin], num))
                    if '- ANY in Destination: ' in line:
                        test_result = "Passed"
                        num = int(line.split('- ANY in Destination: ')[1].replace('</td></tr>','').strip())
                        if abs(num - rules_any_destination[indexin]) > 5 or num < 0 or num > rules_any[indexin]:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{} {}, {} {}".format('- ANY in Destination:',test_result, rules_any_destination[indexin], num ))
                    if '- ANY in Service: ' in line:
                        test_result = "Passed"
                        num = int(line.split('- ANY in Service: ')[1].replace('</td></tr>','').strip())
                        if abs( num- rules_any_services[indexin]) > 5 or num < 0 or num > rules_any[indexin]:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{} {}, {} {}".format('- ANY in Service:', test_result, rules_any_services[indexin], num))
                    #OTHERS
                    if 'Disabled Rules' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - rules_disabled[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Disabled Rules',test_result, rules_disabled[indexin], num ))

                    if 'Times Rules' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - rules_times[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Times Rules', test_result, rules_times[indexin] , num))
                    if 'Non Logging Rules' in line and vendor not in [ 'CiscoASA', 'FirePower']:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - rules_non_logging[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Non Logging Rules',test_result, rules_non_logging[indexin], num))
                    if 'Cleanup Rule' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - rules_clean_up[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Cleanup Rule', test_result, rules_clean_up[indexin], num))
                    if 'Uncommented Rules' in line and vendor not in [ 'CiscoASA', 'FirePower']:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - rules_uncommented[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Uncommented Rules', test_result, rules_uncommented[indexin], num))
                    if 'Optimization Potential' in line:
                        test_result = "Passed"
                        num = int(line.split('<td style=\'font-size: 14px;\'>')[2].replace('</td>','').strip())
                        if abs(num - total_rules[indexin] + rules_optimization_potential[indexin]) > 5 or num < 0:
                            test_result = "Not Passed"
                            passed = test_result
                        print("{}: {}, {} {}".format('Optimization Potential', test_result, rules_optimization_potential[indexin], num))
            print(passed)
            return passed, passed_file
    if vendor not in [ 'CiscoASA', 'FirePower']:
        return "Passed", True
    return "Not Passed", passed_file

args_parser = argparse.ArgumentParser()

args_parser._optionals.title = "arguments"

args_parser.add_argument('-s', '--smart-move-path',
                         help="Path to SmartMove.exe")
args_parser.add_argument('-v', '--vendor',
                         help="Vendor Type")
args_parser.add_argument('-f', '--file',
                         help="Vendor file with objects")
args_parser.add_argument('-p', '--path',
                         help="Vendor file with objects")
args = args_parser.parse_args()

os.mkdir(args.path + '\\test')

args.path = args.path + '\\test'

#Create Job for SmartMove without unused objects
os.system('cmd /c {smpath} -s {source} -v {vendor} -t {path} –n true -k true -f text'.format(smpath=args.smart_move_path, source=args.file,vendor=args.vendor,path=args.path))

folder_list = [ name for name in os.listdir(args.path) if os.path.isdir(os.path.join(args.path, name)) ]
if len(folder_list) > 0:
    path_without_sub = False

print(folder_list)
#Calculate used objects
used_objects_readed = True
if path_without_sub:
    used_total_networks.append(0)
    used_total_services.append(0)
    used_total_networks[0], used_total_services[0], used_objects_readed = read_objects(args.path)
else:
    index = 0
    for folder in folder_list:
        used_total_networks.append(0)
        used_total_services.append(0)
        used_total_networks[index], used_total_services[index], used_objects_readed = read_objects(args.path + '\\' + folder )        
        index+=1


#Create Job for SmartMove with unused objects
os.system('cmd /c {smpath} -s {source} -v {vendor} -t {path} –n true -k false -f text'.format(smpath=args.smart_move_path, source=args.file,vendor=args.vendor,path=args.path))
#Create Job for SmartAnalyze
os.system('cmd /c {smpath} -s {source} -v {vendor} -t {path} –n true -k false -f text -a'.format(smpath=args.smart_move_path, source=args.file,vendor=args.vendor,path=args.path))
#Read sh file with rules
rules_readed = True
if path_without_sub:
    total_rules.append(0)
    rules_uncommented.append(0)
    rules_any.append(0)
    rules_any_source.append(0)
    rules_any_services.append(0)
    rules_any_destination.append(0)
    rules_disabled.append(0)
    rules_times.append(0)
    rules_non_logging.append(0)
    rules_clean_up.append(0)
    total_rules[0], rules_uncommented[0], rules_any[0], rules_any_source[0], rules_any_services[0], rules_any_destination[0], rules_disabled[0], rules_times[0], rules_non_logging[0], rules_clean_up[0], rules_readed = read_rules(args.path)
else:
    index = 0
    for folder in folder_list:
        total_rules.append(0)
        rules_uncommented.append(0)
        rules_any.append(0)
        rules_any_source.append(0)
        rules_any_services.append(0)
        rules_any_destination.append(0)
        rules_disabled.append(0)
        rules_times.append(0)
        rules_non_logging.append(0)
        rules_clean_up.append(0)
        total_rules[index], rules_uncommented[index], rules_any[index], rules_any_source[index], rules_any_services[index], rules_any_destination[index], rules_disabled[index], rules_times[index], rules_non_logging[index], rules_clean_up[index], rules_readed = read_rules(args.path + '\\' + folder)
        index+=1

#Read sh file with opt rules
opt_rules_readed = True
if path_without_sub:
    rules_optimization_potential.append(0)
    rules_optimization_potential[0], opt_rules_readed = read_opt_rules(args.path)
else:
    index = 0
    for folder in folder_list:
        rules_optimization_potential.append(0)
        rules_optimization_potential[index], opt_rules_readed = read_opt_rules(args.path + '\\' + folder)
        index+=1
#Read file with objects
objects_readed = True
if path_without_sub:
    total_networks.append(0)
    total_services.append(0)
    total_networks[0], total_services[0], objects_readed = read_objects(args.path)
else:
    index = 0
    for folder in folder_list:
        total_networks.append(0)
        total_services.append(0)
        total_networks[index], total_services[index], objects_readed = read_objects(args.path + '\\' + folder)
        index+=1


#Compare Results
managment_file = True
if path_without_sub:
    result, managment_file = show_results(args.path, 0, args.vendor)
    print(result)
else:
    result = "Passed"
    index = 0
    for folder in folder_list:
        print(folder)
        print(index)
        print(args.vendor)
        result_file, managment_file = show_results(args.path + '\\' + folder, index, args.vendor)
        if result_file != "Passed":
            result = result_file
        index+=1
    print(result)
    

for name in os.listdir(args.path):
    if os.path.isdir(os.path.join(args.path, name)):
        for name_in in os.listdir(os.path.join(args.path, name)):
            os.remove(os.path.join(args.path, name, name_in))
        os.rmdir(os.path.join(args.path, name))
    else:
        os.remove(args.path+'\\'+name)
    
os.rmdir(args.path) 
