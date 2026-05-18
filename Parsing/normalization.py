import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Parsing.parser import auth_parser,access_parser

result_auth = auth_parser()
result_access = access_parser()

auth_timestamps,auth_hostnames,auth_processes,auth_pid,auth_messages,auth_ips,auth_usernames,auth_raw_logs = result_auth
acc_ips,acc_users,acc_timestamps,acc_methods,acc_endpoints,acc_status,acc_sizes,acc_raw = result_access

def normalize_events():
    keyword = ["Failed password","Accepted password","Connection closed","Received disconnect","TTY=","not allowed to execute","session closed","session opened","CMD","Authentication failure","Successful su","Failed su","Reached target","Stopped","Starting","Started"]
    matched_events = [next((k for k in keyword if k.lower() in msg.lower()), None) for msg in auth_messages]
    transform_map = {
        "Failed password" : "failed_login",
        "Accepted password" : "successful_login"
    }
    event_types = [
        None if event is None else transform_map.get(event, event.replace(" ","_"))
        for event in matched_events
    ]
    normalized_events = []

    for i in range(len(auth_ips)):
        event  = {
        "timestamp" : None,
        "source_ip" : None,
        "event_type" : None,
        "user" : None,
        "status" : None,
        "severity" : None,
        "raw" : None
    }
        event["timestamp"] = auth_timestamps[i]
        event["source_ip"] = auth_ips[i]
        event["user"] = auth_usernames[i]
        event["raw"] = auth_raw_logs[i]
        event["event_type"] = event_types[i]

        normalized_events.append(event)
    
    for i in range(len(acc_ips)):
        event  = {
        "timestamp" : None,
        "source_ip" : None,
        "event_type" : None,
        "user" : None,
        "status" : None,
        "severity" : None,
        "raw" : None
    }
        event["timestamp"] = acc_timestamps[i]
        event["source_ip"] = acc_ips[i]
        event["user"] = acc_users[i]
        event["status"] = acc_status[i]
        event["raw"] = acc_raw[i]
        event["event_type"] = "web_request"

        normalized_events.append(event)

    return normalized_events



        
