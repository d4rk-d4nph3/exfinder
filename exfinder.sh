###################################################################
# Script Name	: exfinder.sh                                                                                         
# Description	: Search EVTX files like a SIEM
# Author       	: d4rk-d4nph3
# Created At    : Mar 27, 2021
# Version       : 0.1
# Remark        : Performance NOT tested on very large log files
#                 Currently only Event ID 4688 is supported
#                 Currently available search parameters:
#                 EventID, User, Host, Process, Parent, Command
###################################################################


QUERY=$1


# Extract the parameters

if [[ $QUERY =~ EventID=([0-9]+) ]]; then
    EVENTID=${BASH_REMATCH[1]}
    EVENTID_FILTER=".Event.System.EventID == $EVENTID"
else
    EVENTID_FILTER='NONE'
fi

if [[ $QUERY =~ Host=([0-9a-zA-Z\$\-_]+) ]]; then
    HOST=${BASH_REMATCH[1]}
    HOST_FILTER=".Event.System.Computer == \"$HOST\""
else
    HOST_FILTER='NONE'
fi

if [[ $QUERY =~ User=([0-9a-zA-Z_\$\-]+) ]]; then
    USER=${BASH_REMATCH[1]}
    USER_FILTER=".Event.EventData.SubjectUserName == \"$USER\""
else
    USER_FILTER='NONE'
fi

if [[ $QUERY =~ Process=([0-9a-zA-Z.\\]+) ]]; then
    PROCESS=${BASH_REMATCH[1]}
    PROCESS_FILTER="select(.Event.EventData.NewProcessName | contains(\"$PROCESS\"))"
else
    PROCESS_FILTER='NONE'
fi

if [[ $QUERY =~ Parent=([0-9a-zA-Z.\\]+) ]]; then
    PARENT_PROCESS=${BASH_REMATCH[1]}
    PARENT_PROCESS_FILTER="select(.Event.EventData.ParentProcessName | contains(\"$PARENT_PROCESS\"))"
else
    PARENT_PROCESS_FILTER='NONE'
fi

if [[ $QUERY =~ Command=([0-9a-zA-Z.\ _\-]+) ]]; then
    COMMAND=${BASH_REMATCH[1]}
    COMMAND_FILTER="select(.Event.EventData.CommandLine | contains(\"$COMMAND\"))"
else
    COMMAND_FILTER='NONE'
fi


# Check if 'project' is used

if [[ $QUERY =~ project.*User ]]; then
    USER_PROJECT=".Event.EventData.SubjectUserName"
else
    USER_PROJECT='NONE'
fi

if [[ $QUERY =~ project.*Command ]]; then
    COMMAND_PROJECT=".Event.EventData.CommandLine"
else
    COMMAND_PROJECT='NONE'
fi

if [[ $QUERY =~ project.*Host ]]; then
    HOST_PROJECT=".Event.System.Computer"
else
    HOST_PROJECT='NONE'
fi

if [[ $QUERY =~ project.*Process ]]; then
    PROCESS_PROJECT=".Event.EventData.NewProcessName"
else
    PROCESS_PROJECT='NONE'
fi

if [[ $QUERY =~ project.*Parent ]]; then
    PARENT_PROJECT=".Event.EventData.ParentProcessName"
else
    PARENT_PROJECT='NONE'
fi

# Prepare the final query
FINAL_QUERY='select('"$EVENTID_FILTER"' and '"$USER_FILTER"' and '"$HOST_FILTER"') | '"$PROCESS_FILTER"' | '"$PARENT_PROCESS_FILTER"' | '"$COMMAND_FILTER"' | ['$USER_PROJECT' , '$HOST_PROJECT' , '$COMMAND_PROJECT' , '$PROCESS_PROJECT' , '$PARENT_PROJECT']'

# Post-processing of the query
# This is required in the case when parameters are missing in the query
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/and NONE//g')
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/\| NONE//g')
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/NONE and//g') 
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/select(NONE ) \|//g')
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/NONE ,//g')
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/, NONE//g')
FINAL_QUERY=$(echo $FINAL_QUERY | sed 's/\| \[ NONE\]//g')

# Search 'em all
jq -c "$FINAL_QUERY" ProcJsonLog.txt
