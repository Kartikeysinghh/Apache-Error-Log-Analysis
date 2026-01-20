# APACHE ANOMOLY LOG DETECTION PIPELINE

# PROJECT OVERVIEW
This project an end-to-end data analysis project pipeline designed to parse unstructured Apache server logs, perform Exploratory Data Analysis , and detect suspicious client activity using statistical anomaly detection.

# ETL PROCESS 
The project follows the Extract, Transform, Load (ETL) framework:
1. Extract: Raw logs are read and parsed using REGULAR EXPRERSSIONS with named capture groups for high precision.
2. Transform: Data is cleaned using PANDAS, converting timestamps into datetime objects and handling missing IP addresses.
3. Load: The structured data is exported to CSV format for further business intelligence use.

# ANOMALY DETECTION PROCESS
To identify Suspicious IPs a Rule Based Statistical Model has been applied
- Volume Check: Flags IPs with requests exceeding the threshold of `Mean + 1 Standard Deviation`.
- Failure Check: Filters for IPs that generated more than 2 `ERROR` logs.
- Goal: This dual-layer filter distinguishes between high-traffic "power users" and potential "malicious bots" with high traffic and high error count

# FOLDER STRUCTURE
- 'data/': Raw log files and structured CSV outputs.
- 'script/': Python source code (`main.py`).
- 'reports/': Data visualizations that are Traffic trends, Log level and the Final Suspicious IP Report.

#DATA INSIGHTS AND VISUALIZATIONS 
By analyzing the Apache_2k_clients.log, the following trends were identified:
1.Hourly TrendS: Identifying the peak activity hours helps in server capacity planning and scheduling maintenance.
2. System Health (Log Level Analysis): The bar chart of TrafficPerHour (Log Levels) provides a snapshot of system stability.
3. Suspicious IP Analysis:IPs with high requests but low errors are likely heavy users or internal services.IPs with high requests and high errors are flagged as Suspicious. These represent potential automated bots

