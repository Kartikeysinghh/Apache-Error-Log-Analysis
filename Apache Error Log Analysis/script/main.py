import re
import pandas as pd
import matplotlib.pyplot as plt


with open("data/Apache_2k_clients.log","r") as logfile:
    lines=logfile.readlines()
print("Number Of Log Lines",len(lines))
print(lines[:5])

# regex where lines matching the pattern are saved
# /[ /] ---> opening and closing , to group under a name
# . ----> match any character , * ----> any number of times , ? ----> may or may no be always present
Log_Pattern = re.compile(
    r"""
    \[(?P<timestamp>.*?)\]                    
    \s+\[(?P<level>\w+)\]                     
    \s+\[client\s+(?P<client_ip>[\d\.]+)\]    
    \s+(?P<message>.*)                        
    """,
    re.VERBOSE                                # regex can be written over multiple lines
)

Structured_Logs=[]  
for line in lines:                                 # each line 
    match = Log_Pattern.search(line)                   # scan each line of pattern  
    if match:                                        
        timestamp = match.group("timestamp")
        log_level = match.group("level")
        client_ip = match.group("client_ip")
        message = match.group("message")
        Structured_Logs.append({
            "Timestamp": timestamp,
            "Level": log_level,
            "Client_ip": client_ip,
            "Message": message
        })



df = pd.DataFrame(Structured_Logs)
df.head()


df["Timestamp"] = pd.to_datetime(
    df["Timestamp"],
    format="%a %b %d %H:%M:%S %Y",
    errors="coerce") # if a timestamp does not match the date time format set it to NaT = Not a Time
df["Client_ip"] = df["Client_ip"].fillna("Not Applicable")
df["Level"] = df["Level"].str.upper()


# data validtaion
df.isnull().sum()
df["Level"].value_counts()
df["Client_ip"].value_counts().head()
df.isna().sum()
df = df.dropna(subset=["Timestamp"])
df["Message"] = df["Message"].str.strip()
df["Message"] = df["Message"].str.replace(r"\s+", " ", regex=True) # here multiplae spaces are replaced by single space


df.to_csv("data/Apache_Structured.csv", index=False)


# extract day date and hour with .dt accessor which converts string to datetime objects
df["hour"] = df["Timestamp"].dt.hour
df["day"] = df["Timestamp"].dt.day_name()
df["date"] = df["Timestamp"].dt.date


# data check before analysis
print(df.info())
print(df.head())
print(df.describe(include="all"))


df.to_csv("data/cleaned_Apache_Structured.csv", index=False)


print(df.columns)
# get information about which dataset dominates the "level" column
df["Level"].value_counts()
# get information about most traffic
df["hour"].value_counts().sort_index()
# get info about which client is using the server
df["Client_ip"].value_counts().head(10)
# get info about which logs have unspecified ip address
(df["Client_ip"] == "Not Applicable").sum()
# message length since error messages are usually longer in length 
df["Message_length"] = df["Message"].str.len()
# filtering of error logs 
error_df = df[df["Level"] == "ERROR"]
# check volume for error 
error_df.shape
error_df["Message"].value_counts().head(5)
# error per hour
error_df["hour"].value_counts().sort_index()


df.info()
df.head()


# traffic volume by hour , it shows at which time traffic peaks
hourly_traffic = df["hour"].value_counts().sort_index()
plt.figure()
plt.plot(hourly_traffic.index, hourly_traffic.values)
plt.xlabel("Hour")
plt.ylabel("Total Number of Requests")
plt.title("Distibution of Traffic per Hour")
plt.show()
#log level distribution , it shows the health of system , more error logs implies instability  
TrafficPerHour = df["Level"].value_counts()
plt.figure()
plt.bar(TrafficPerHour.index, TrafficPerHour.values)
plt.xlabel("Log Level")
plt.ylabel("Number of Occurences")
plt.title("Distribution of Log Levels")
plt.show()
# top clients . it suggests heavy users ,can help suspect bots
clients = df["Client_ip"].value_counts().head(3)
plt.figure()
plt.bar(clients.index, clients.values)
plt.xlabel("Client IP")
plt.ylabel("Requests")
plt.title("Top 3 Client IPs according to Traffic")
plt.xticks(rotation=45)
plt.show()


# SUSPICIOUS IP DETECTION = Rule based analysis
# remove N/A clients
ValidIP = df[df["Client_ip"] != "Not Applicable"]
# who is accessing the server most
MostRequestIP = ValidIP["Client_ip"].value_counts()
MostRequestIP.head(10)
MostRequestIP.describe()
# threshold for suspicious ip in terms of more number of requests , mathematically  
threshold = MostRequestIP.mean() + (MostRequestIP.std()) # abnormality = mean +  (2*standard deviation) is actual industry standard
# high traffic for ip with log levels equating 
MostErrorIP = (ValidIP[ValidIP["Level"] == "ERROR"]["Client_ip"].value_counts())
MostErrorIP.head(10)
# making dataframe for suspicious ips with requests and error in a dictionary 
SusIps = pd.DataFrame({"Total Requests": MostRequestIP,"Total Errors": MostErrorIP}).fillna(0)
SusIps.head()
# combination of high traffic clients which simultaneously produce most errors
FinalSusIps = SusIps[SusIps["Total Requests"] > threshold]
FinalSusIps = FinalSusIps[FinalSusIps["Total Errors"] > 2] # greater than 2 is adjusted value not the standard 
FinalSusIps.to_csv("report/Final_Suspicious_IP_Report.csv")

#visualization of suspicious ip
if FinalSusIps.empty:
    print("No suspicious IPs were found and the dataframe is empty") # empty dataframe cannot be plotted in case if line 146 has threshold too high
else:
    plt.figure(figsize=(10, 6))
    FinalSusIps.plot(kind="bar")
    plt.xlabel("Suspicious IP requests")
    plt.ylabel("Number of hits")
    plt.title("Suspicious IPs: Requests vs Errors")
    plt.xticks(rotation=45)
    plt.savefig("report/Final_Suspicious_IP_Plot.png")
    plt.show()












 








