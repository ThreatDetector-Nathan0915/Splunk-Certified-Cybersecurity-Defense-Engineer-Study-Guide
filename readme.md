# Splunk Certified Cybersecurity Defense Engineer Study Guide

## Overview
This study guide is designed to help you prepare for the **Splunk Certified Cybersecurity Defense Engineer** exam. It covers key topics, concepts, and resources that you need to master to pass the exam. Customize this template based on your progress and learning style.

---

## 1. Exam Information
- **Certification Name**: Splunk Certified Cybersecurity Defense Engineer
- **Exam Duration**: 60-90 minutes
- **Question Types**: Multiple choice, multiple response
- **Prerequisites**: Splunk Core Certified Power User, experience in cybersecurity operations

### Key Skills Measured:
- Using Splunk to identify and respond to cybersecurity threats
- Implementing best practices for security monitoring and incident response
- Working with Splunk Enterprise Security (ES) and Splunk Security Orchestration, Automation, and Response (SOAR)
- Advanced searches and dashboards to analyze security events

---
## 2. Key Study Topics

### 2.1 [Splunk Fundamentals](#splunk-fundamentals)
- **Splunk Architecture and Components**
  - Search Heads, Indexers, Forwarders, Deployment Servers
  - How data flows through Splunk (indexing, searching)
- **Data Inputs**
  - Adding data sources (syslog, HTTP Event Collector, etc.)
  - Parsing and index time vs search time operations
- **Search Processing Language (SPL) Basics**
  - Core SPL commands (stats, eval, table, sort, timechart)
  - Advanced SPL commands (join, transaction, append)
  - Writing and optimizing SPL queries for performance

### 2.2 [Splunk Enterprise Security (ES)](#splunk-enterprise-security-es)
- **Overview of Splunk ES**
  - Introduction to ES interface and components
  - Security domains: Asset and Identity Framework, Risk-Based Alerting (RBA)
  - Use Cases: Threat detection, vulnerability management, incident response
- **Correlation Searches**
  - Configuring and tuning correlation searches
  - Creating custom correlation searches for security incidents
- **Notable Events and Incident Review**
  - Managing and investigating notable events
  - Workflows for incident analysis and escalation

### 2.3 [Security Monitoring and Incident Response](#security-monitoring-and-incident-response)
- **Security Use Cases**
  - Detecting anomalies, malicious insider activities, phishing, malware
  - Monitoring and alerting for unauthorized access attempts
- **Incident Response Playbooks**
  - Automation of incident response using Splunk SOAR
  - Writing playbooks for common security incidents
- **Dashboarding and Reporting**
  - Creating security operations dashboards
  - Generating and sharing security reports
  - Using pre-built dashboards for security use cases (e.g., MITRE ATT&CK)

### 2.4 [Threat Intelligence and Automation](#threat-intelligence-and-automation)
- **Integration of Threat Feeds**
  - Integrating third-party threat intelligence sources with Splunk
  - Using Threat Intelligence Framework in Splunk ES
- **Automated Threat Detection**
  - Leveraging machine learning for threat detection
  - Anomaly detection techniques using Splunk's MLTK
- **SOAR Use Cases**
  - Automating responses to common threats (phishing, brute force attacks)
  - Integration of SOAR with other security tools (firewalls, IDS/IPS, etc.)

### 2.5 [Data Models and CIM (Common Information Model)](#data-models-and-cim-common-information-model)
- **CIM Overview**
  - Understanding the Common Information Model (CIM)
  - Mapping data to CIM-compliant data models
- **Pivot Reports**
  - Using Pivot to build CIM-compliant dashboards and reports
- **Normalization Techniques**
  - Data normalization using field extractions and lookups

### 2.6 [Splunk Administration (Optional)](#splunk-administration-optional)
- **User Management and RBAC**
  - Creating roles and managing users and permissions.
  - Controlling access to data using role-based access control (RBAC).
- **Index and Data Retention Policies**
  - Configuring indexes and setting up retention policies for log data.
- **Monitoring Splunk Deployment**
  - Monitoring health, performance, and troubleshooting issues.

### 2.7 [Advanced Security Use Cases in Splunk ES](#advanced-security-use-cases-in-splunk-es)
- **MITRE ATT&CK Framework Integration**
  - Mapping security events to the MITRE ATT&CK matrix.
- **Threat Hunting with Splunk ES**
  - Using Splunk for proactive threat hunting across various datasets.
- **Risk-Based Alerting (RBA)**
  - Prioritizing alerts based on risk using Splunk ES RBA.

### 2.8 [Data Onboarding Best Practices](#data-onboarding-best-practices)
- **Parsing and Normalization**
  - Techniques for field extraction and data normalization in Splunk.
- **Tuning Data Collection**
  - Best practices for optimizing data collection, including specific use cases like firewall logs and application data.
- **Using Splunk Add-ons**
  - Leveraging Splunk technology add-ons for common data sources (e.g., Windows, AWS, Cisco).

### 2.9 [Splunk SOAR (Optional)](#splunk-soar-optional)
- **Introduction to Splunk SOAR**
  - Overview of SOAR’s automation and orchestration capabilities.
- **Creating Playbooks**
  - Designing, testing, and optimizing playbooks for automated security responses.

### 2.10 [Security Frameworks and Compliance](#security-frameworks-and-compliance)
- **Using Splunk for Compliance**
  - Implementing Splunk for regulatory audits (e.g., PCI, GDPR, HIPAA).
- **Security Frameworks**
  - Using Splunk to implement NIST, CIS Controls, and other frameworks.

### 2.11 [Performance Tuning and Optimization](#performance-tuning-and-optimization)
- **Optimizing Search Performance**
  - Best practices for writing efficient SPL queries.
  - Using summary indexing and report acceleration.
- **Distributed Search Optimization**
  - Configuring distributed search for large-scale deployments.

### 2.12 [Disaster Recovery and High Availability](#disaster-recovery-and-high-availability)
- **Splunk Replication and Failover**
  - Configuring indexer and search head clustering for high availability.
- **Backup and Restore**
  - Backing up and restoring Splunk data and configurations.

---

## 3. Study Resources

### 3.1 Splunk Documentation
- [Splunk Docs](https://docs.splunk.com/Documentation) for:
  - Search Processing Language (SPL)
  - Splunk Enterprise Security (ES)
  - Splunk SOAR
  - Security Use Cases

### 3.2 Training Courses
- **Splunk Security Essentials**: Foundational security knowledge using Splunk
- **Splunk Enterprise Security Certified Admin**: Covers administration of Splunk ES
- **Splunk SOAR Fundamentals**: Learn automation and orchestration with SOAR

### 3.3 Practice Labs and Playgrounds
- **Splunk ES Sandbox**: Hands-on practice with Splunk ES
- **Splunk SOAR Trial**: Practice building automation workflows
- **Splunk’s Boss of the SOC (BOTS)**: Participate in simulated security challenges to improve threat-hunting skills

### 3.4 Study Materials and Books
- **The Essential Guide to Cybersecurity for Splunk** by Splunk
- **Splunk Enterprise Security Essentials** (available on GitHub or Splunkbase)

---

## 4. Study Plan Template

| **Week** | **Topics to Study** | **Tasks** | **Resources** | **Notes** |
|----------|---------------------|-----------|---------------|-----------|
| Week 1   | Splunk Fundamentals  | Watch SPL videos, review basic commands | Splunk Docs | Focus on data input and parsing |
| Week 2   | Splunk ES Overview   | Set up ES in a lab, review security domains | Splunk ES Sandbox | Pay attention to incident review workflows |
| Week 3   | Security Monitoring  | Practice detecting threats and using alerts | BOTS | Focus on phishing and insider threat use cases |
| Week 4   | Threat Intelligence  | Integrate threat feeds, explore automation | SOAR Trial | Build custom correlation searches |
| Week 5   | CIM & Data Models    | Create dashboards using CIM data | Splunk Docs | Practice using Pivot and normalization techniques |
| Week 6   | Final Review & Practice | Take practice exams, review weak areas | All resources | Final prep |

---

## 5. Practice Exams
- Splunk's official practice exams
- Mock exams available on [Splunkbase](https://splunkbase.splunk.com/)
- Third-party platforms offering Splunk ES and SOAR practice exams

---

## 6. Exam Tips
- Time management: Practice answering questions within the given time limit.
- Focus on hands-on experience: Set up a home lab using the free version of Splunk.
- Study the exam blueprint: Ensure you cover all topics outlined in the exam blueprint.
- Review your SPL commands: You’ll need to be comfortable writing advanced queries.

---

## 7. Additional Notes
- **Splunk Support**: Join Splunk Community forums for Q&A and peer support.
- **Certifications Pathway**: Review the next steps after becoming a Splunk Certified Cybersecurity Defense Engineer.

---

## 8. Progress Tracker

| **Topic**                          | **Status**     | **Notes**             |
|------------------------------------|----------------|-----------------------|
| Splunk Architecture and Components | In Progress    | Need to review Forwarders in detail |
| SPL Basics                         | Complete       | Feeling confident with stats and eval |
| Splunk ES Overview                 | In Progress    | Focus on correlation searches next |
| Incident Response Playbooks        | Not Started    | Plan to work on SOAR next week |

---

### 2.1 <a name="splunk-fundamentals"></a> Splunk Fundamentals

---

#### **Splunk Architecture and Components**

Understanding the key components of Splunk architecture is crucial for effectively using Splunk for security purposes. The architecture consists of the following elements:

- **Search Heads**: Responsible for performing searches across indexed data. 
  - Example: When you run a query, the Search Head distributes the search across multiple Indexers and aggregates the results.
  
- **Indexers**: Store and index data coming from different sources. Indexers also process incoming data and make it searchable.
  - Example: When logs are ingested from firewalls, they are parsed and stored by the Indexers.

- **Forwarders**: Forwarders collect and send data to Splunk Indexers. There are two types: **Universal Forwarder** (lightweight) and **Heavy Forwarder** (can parse data).
  - Example: Use a Universal Forwarder to collect logs from multiple servers and send them to the central Indexer.

- **Deployment Servers**: Deployment Servers manage configurations and distribute apps to all forwarders in your deployment.
  - Example: A Deployment Server can push a new configuration to all forwarders for logging Windows events.

**Data Flow in Splunk**:
- Data flows through **forwarders** to the **indexers**, which then process, store, and make the data searchable via **search heads**.

---

#### **Data Inputs**

Splunk can ingest data from various sources, and understanding how to configure data inputs is essential:

- **Syslog Input**: One of the most common methods for sending logs from network devices and servers.
  - Example: You can configure a syslog input to capture logs from a firewall by using the `UDP` protocol and listening on port 514.

- **HTTP Event Collector (HEC)**: A method for sending data to Splunk using HTTP/HTTPS.
  - Example: Sending data from cloud applications via HEC involves configuring an input on the HEC and using a POST request to send data.

- **File Monitoring**: Splunk can monitor files or directories for changes and index the data.
  - Example: Monitor `/var/log/auth.log` on a Linux system to capture login activity.

**Index Time vs Search Time Operations**:
- **Index Time**: When data is ingested, fields are extracted at index time, which allows for more efficient searching later.
  - Example: Source type, host, and other metadata are extracted during data ingestion.
  
- **Search Time**: Some fields (like complex key-value pairs or dynamic fields) can be extracted at search time, which allows for more flexible searching.
  - Example: Extracting HTTP response codes from logs dynamically during search.

---

#### **Search Processing Language (SPL) Basics**

SPL is the core language used to query and analyze data within Splunk. Mastering these commands is crucial for both exam preparation and real-world Splunk usage.

##### Core SPL Commands

- **`stats`**: Performs statistical calculations on your data.
  - Example: Calculate the count of events by HTTP status code.
    ```spl
    index=web_logs | stats count by status
    ```

- **`eval`**: Used to create new fields or manipulate existing fields.
  - Example: Create a new field based on conditional logic.
    ```spl
    index=web_logs | eval status_type = if(status >= 400, "Error", "Success")
    ```

- **`table`**: Format the output as a table.
  - Example: Display the IP and status fields in a table format.
    ```spl
    index=web_logs | table ip, status
    ```

- **`sort`**: Sort the results based on one or more fields.
  - Example: Sort results by timestamp in descending order.
    ```spl
    index=web_logs | sort - _time
    ```

- **`timechart`**: Create a time-based chart to visualize data over time.
  - Example: Count HTTP requests over time.
    ```spl
    index=web_logs | timechart count
    ```

##### Advanced SPL Commands

- **`join`**: Combine data from multiple indexes or data sources based on a common field.
  - Example: Join web logs and security logs by IP address.
    ```spl
    index=web_logs | join ip [search index=security_logs]
    ```

- **`transaction`**: Group events into transactions based on some criteria.
  - Example: Group all actions taken by a single user session.
    ```spl
    index=web_logs | transaction session_id
    ```

- **`append`**: Append results of a subsearch to the current search results.
  - Example: Append results from two different searches.
    ```spl
    index=web_logs | append [search index=security_logs]
    ```

---

#### **Writing and Optimizing SPL Queries for Performance**

Efficient query writing ensures that searches complete faster, especially in large-scale deployments.

1. **Use Index Early**: Always specify the index as early as possible in your searches to reduce the amount of data to scan.
   - Example: Start with `index=web_logs` instead of just searching globally.

2. **Limit Time Range**: Restrict searches to specific time periods.
   - Example: Use `earliest` and `latest` time modifiers.
    ```spl
    index=web_logs earliest=-1d latest=now
    ```

3. **Selective Field Search**: Use specific fields in the search to reduce the search scope.
   - Example: Instead of searching all fields, focus on required ones like `status`.
    ```spl
    index=web_logs status=404
    ```

4. **Avoid Unnecessary Commands**: Don't use commands like `join` unless absolutely necessary, as they can slow down performance.
   - Instead of using `join`, try restructuring your data model or use `lookup` or `stats` to achieve similar outcomes.

5. **Parallel Processing**: Use `map` to parallelize searches when necessary, but use it sparingly as it increases load.

   Example of using **`map`**:
   ```spl
   index=web_logs | map search="search index=security_logs ip=$ip$"
   ```
### 2.2 <a name="splunk-enterprise-security-es"></a> Splunk Enterprise Security (ES)


---

#### **Overview of Splunk ES**

Splunk Enterprise Security (ES) is a premium app that sits on top of Splunk and is tailored for security use cases. It provides a security-specific interface, along with prebuilt dashboards and workflows to help detect and respond to security incidents effectively.

##### Key Components of Splunk ES:

- **Incident Review Dashboard**: The main dashboard where notable events are reviewed and analyzed.
  - *Example*: Security analysts can review events categorized as notable based on predefined or custom security rules.

- **Security Domains**: Splunk ES organizes its content into several domains:
  - **Access**: Tracks user access attempts and logs for potential unauthorized access.
  - **Endpoint**: Focuses on monitoring endpoints for suspicious activity.
  - **Network**: Monitors network traffic for anomalies and intrusions.
  - **Identity**: Integrates identity-based information, like user accounts and privileges.
  - **Threat**: Detects known and emerging threats using threat intelligence feeds.

##### Security Domains: Asset and Identity Framework, Risk-Based Alerting (RBA)

- **Asset and Identity Framework**: Allows organizations to map data from hosts and users to assets and identities, adding context to events.
  - *Example*: When a security alert is triggered, ES can correlate the event with asset information (e.g., criticality) and identity (e.g., user roles) to prioritize responses.

- **Risk-Based Alerting (RBA)**: Instead of alerting on individual events, ES uses risk scores to identify threats by aggregating multiple alerts or behaviors.
  - *Example*: A user logging in from two different countries within a short timeframe might increase their risk score, triggering a notable event for investigation.

---

#### **Use Cases**

- **Threat Detection**: Identify and monitor for malware infections, unauthorized access, and suspicious activity using prebuilt and custom correlation searches.
  - *Example*: A malware infection can be detected by analyzing endpoint logs and flagging specific processes or IP addresses.

- **Vulnerability Management**: Integrate vulnerability scanners (e.g., Qualys, Tenable) to track and prioritize vulnerabilities based on risk.
  - *Example*: A report could show all critical vulnerabilities detected on high-priority assets to focus remediation efforts.

- **Incident Response**: Utilize the Incident Review dashboard to track incidents, assign ownership, and escalate based on priority.
  - *Example*: When a notable event is triggered, an analyst can investigate the alert, assign it for further investigation, and escalate to incident responders if necessary.

---

#### **Correlation Searches**

Correlation searches are the backbone of Splunk ES’s threat detection capability. They are pre-built or custom searches that automatically analyze incoming data for known patterns of security incidents.

##### Configuring and Tuning Correlation Searches

- **Built-in Correlation Searches**: Splunk ES comes with many predefined searches for common security use cases (e.g., brute-force attacks, malware detection).
  - *Example*: A correlation search may detect brute force login attempts by looking for multiple failed login attempts within a short timeframe.
    ```spl
    `failed_logins` | stats count by user, src_ip | where count > 5
    ```

- **Tuning Correlation Searches**: To avoid alert fatigue, it's important to adjust correlation searches to your environment.
  - *Example*: Adjust the threshold in a failed login correlation search to suit your environment (e.g., raising the threshold to 10 failed attempts instead of 5 for environments with frequent login errors).
    ```spl
    `failed_logins` | stats count by user, src_ip | where count > 10
    ```

- **Custom Correlation Searches**: You can create custom searches to monitor specific activities or behaviors.
  - *Example*: Create a custom correlation search to detect privilege escalation attempts by tracking changes in user roles.
    ```spl
    index=security_logs action="role_change" | stats count by user, new_role | where count > 1
    ```

##### Best Practices for Correlation Searches:

1. **Use Risk Scores**: Assign risk scores to events instead of triggering alerts for every correlation match to prioritize high-risk incidents.
2. **Optimize for Performance**: Keep searches efficient by specifying indexes and limiting the time range of searches.
3. **Tune for Specific Environments**: Adjust thresholds and conditions based on normal behavior in your organization to reduce false positives.

---

#### **Notable Events and Incident Review**

Notable events are the central mechanism for investigating incidents in Splunk ES. These are security events flagged by correlation searches, and they provide a structured workflow for incident management.

##### Managing and Investigating Notable Events

- **Notable Events**: These are security-relevant events that are surfaced based on correlation searches. Each notable event contains information such as time, affected assets, risk score, and associated logs.
  - *Example*: A notable event might be triggered when multiple failed login attempts are followed by a successful login from the same user.

- **Investigation Steps**: Analysts can review notable events in the Incident Review dashboard, where they can:
  1. View details of the event and relevant fields (e.g., source IP, username).
  2. Drill down into associated logs to analyze the root cause.
  3. Add comments, assign ownership, and escalate incidents based on severity.
     - *Example*: An event involving unauthorized access might be escalated to a different team for further investigation.

##### Workflows for Incident Analysis and Escalation

- **Incident Review Dashboard**: This dashboard is used to manage the entire lifecycle of a security incident, from detection to resolution.
  - **Status and Urgency**: Each event can be assigned a status (e.g., `New`, `In Progress`, `Resolved`) and urgency (e.g., `High`, `Low`) to prioritize incidents.
  - **Ownership and Escalation**: Incidents can be assigned to individual analysts or teams for investigation. If an incident is determined to be high risk, it can be escalated to a higher tier for further action.

##### Best Practices for Incident Review:

1. **Use Status and Urgency Fields**: Prioritize incidents based on their impact on business-critical assets and services.
2. **Leverage Asset and Identity Context**: Use the Asset and Identity Framework to add context to notable events, making investigations more efficient.
3. **Integrate with SOAR**: Consider integrating Splunk ES with Splunk SOAR for automated responses to high-severity incidents (e.g., automatically isolating a compromised host).

##### Example Workflow:

1. A notable event is triggered due to a suspicious login attempt.
2. The incident is assigned to a security analyst for review.
3. The analyst investigates the associated logs, identifies a successful login from an unusual location, and escalates the incident.
4. The incident is resolved after the user confirms the login was legitimate, or remediation actions are taken (e.g., disabling the user account).

### 2.3 <a name="security-monitoring-and-incident-response"></a> Security Monitoring and Incident Response


---

#### **Security Use Cases**

Security use cases in Splunk ES revolve around detecting, investigating, and responding to potential threats and suspicious activities. Some key use cases include:

##### Detecting Anomalies, Malicious Insider Activities, Phishing, and Malware

- **Anomaly Detection**: Detecting unusual behavior that deviates from normal patterns, such as an unexpected increase in network traffic from a specific host.

  - Example SPL query to detect anomalies in network traffic:
    ```spl
    index=network_logs | stats avg(bytes_in) as avg_bytes by src_ip 
    | where avg_bytes > 100000  # Adjust threshold based on normal behavior
    ```

- **Malicious Insider Activities**: Monitoring for unusual user activities, such as access to sensitive files at odd times or multiple failed login attempts.

  - Example SPL query to detect multiple failed login attempts:
    ```spl
    index=auth_logs action="failure" | stats count by user 
    | where count > 5
    ```

- **Phishing Detection**: Identifying phishing attempts through email headers, URLs, or file attachments that match known patterns of malicious content.

  - Example SPL query to identify emails with suspicious URLs:
    ```spl
    index=email_logs | search subject="*urgent*" OR subject="*password*" 
    | regex url="http(s)?://(.*)\.xyz"
    ```

- **Malware Detection**: Monitoring for signs of malware infection, such as unusual processes, file changes, or communications with known malicious domains.

  - Example SPL query to detect communication with known malware-related IPs:
    ```spl
    index=network_logs | join src_ip [| inputlookup malware_ips.csv] 
    | stats count by src_ip, dest_ip
    ```

##### Monitoring and Alerting for Unauthorized Access Attempts

Splunk can help monitor for unauthorized access attempts by setting up real-time alerts for suspicious behavior like failed login attempts, privilege escalations, or access from unusual locations.

- **Unauthorized Access Monitoring**: Detecting access attempts from blacklisted IPs or countries not typically associated with normal operations.

  - Example SPL query to alert on access from suspicious geolocations:
    ```spl
    index=auth_logs | lookup geoip ip as src_ip 
    | search country!="US"  # Replace with your primary country
    ```

- **Privilege Escalation Detection**: Monitoring for sudden changes in user privileges, especially if they occur outside of normal administrative procedures.

  - Example SPL query to detect privilege escalation:
    ```spl
    index=security_logs action="role_change" | stats count by user, new_role 
    | where new_role="admin"
    ```

---

#### **Incident Response Playbooks**

Incident response playbooks in Splunk automate the response to common security incidents. These playbooks define workflows that trigger specific actions when certain conditions are met, allowing faster and more consistent handling of security events.

##### Automation of Incident Response Using Splunk SOAR

Splunk SOAR (Security Orchestration, Automation, and Response) allows security teams to automate responses to incidents, minimizing manual effort and reducing response times.

- **Phishing Incident Playbook**: Automatically detects phishing emails, quarantines them, and notifies users.

  - Example Playbook Actions:
    1. Detect a suspicious email with a phishing pattern (using an email subject or suspicious URL).
    2. Extract sender information and quarantine the email.
    3. Block the sender's IP and domain.
    4. Notify the user and security team.

- **Brute Force Attack Playbook**: Detects brute-force login attempts, blocks the offending IP, and notifies the incident response team.

  - Example Playbook Actions:
    1. Monitor for multiple failed login attempts.
    2. Block the offending IP via firewall integration.
    3. Notify the SOC for further investigation.

##### Writing Playbooks for Common Security Incidents

To write playbooks in Splunk SOAR, you'll typically define the triggers (such as an alert or notable event), followed by the series of automated actions (response steps).

- Example JSON definition for a brute force attack playbook:

  ```json
  {
    "playbook_name": "Brute Force Attack Response",
    "trigger": {
      "event": "MultipleFailedLogins"
    },
    "actions": [
      {
        "type": "block_ip",
        "parameters": {
          "ip": "$src_ip"
        }
      },
      {
        "type": "notify_team",
        "parameters": {
          "team": "SOC",
          "message": "Brute force attack detected and mitigated"
        }
      }
    ]
  }
  ```
### Dashboarding and Reporting

Splunk provides powerful visualization and reporting capabilities, which allow security teams to monitor the environment in real-time and produce reports for management and compliance purposes.

---

#### **Creating Security Operations Dashboards**

Dashboards provide a real-time view into security operations, showing critical metrics like the number of incidents, types of threats, and active investigations.

- **Security Operations Center (SOC) Dashboard**: Displays key metrics like notable events, open incidents, and threat levels across the organization.

  - Example of a simple SPL query for a SOC dashboard:
    ```spl
    index=security_logs | stats count by threat_level
    ```

- **Custom MITRE ATT&CK Dashboard**: Map observed techniques and tactics in your environment to the MITRE ATT&CK framework.

  - Example SPL query to detect TTPs related to a specific MITRE technique (e.g., T1078 - Valid Accounts):
    ```spl
    index=auth_logs | search action="login" user!="admin" | stats count by src_ip, user
    ```

---

#### **Generating and Sharing Security Reports**

Splunk makes it easy to generate security reports that can be used for auditing, compliance, or executive communication. Reports can be scheduled and automatically sent to stakeholders.

- **Compliance Report**: Generate regular reports on log retention, system access, and incident response metrics.

  - Example SPL query for a report on access log activity:
    ```spl
    index=auth_logs | stats count by user, action, _time
    ```

- **Incident Summary Report**: A summary report that shows incident response times, incident categories, and resolutions for management oversight.

  - Example SPL query to create an incident summary:
    ```spl
    index=incident_review | stats count by incident_status, incident_category
    ```

---

#### **Using Pre-Built Dashboards for Security Use Cases (e.g., MITRE ATT&CK)**

Splunk ES includes several pre-built dashboards designed for specific security use cases, such as mapping security events to the MITRE ATT&CK framework. These dashboards provide an at-a-glance view of current threats and ongoing incidents.

- **MITRE ATT&CK Framework Dashboard**: Pre-built dashboard to track and map detected techniques and tactics to the MITRE framework.

  - You can customize this dashboard by adding your own searches and correlating data from internal logs with ATT&CK techniques.
 
    ## 2.4 <a name="threat-intelligence-and-automation"></a> Threat Intelligence and Automation


---

#### **Integration of Threat Feeds**

Threat feeds provide information about known malicious entities such as IP addresses, domains, file hashes, and other Indicators of Compromise (IOCs). Integrating these feeds with Splunk enables organizations to correlate external intelligence with internal data to detect potential threats.

##### Integrating Third-Party Threat Intelligence Sources with Splunk

Splunk can integrate with various third-party threat intelligence sources, such as VirusTotal, AlienVault, and IBM X-Force. These feeds are ingested and used for correlation to detect matches between internal network activity and known threats.

- **Threat Intelligence Integration**:
  - External threat feeds can be ingested as CSV, STIX, TAXII, or via API connections.

  Example of integrating a CSV-based threat feed:
  ```bash
  ./splunk add oneshot /path/to/threat_feed.csv -index threat_intel
  ```
  ### Using Scheduled Inputs for Continuous Updates

You can automate the pulling of threat data at regular intervals using `inputs.conf`.

**Example of scheduling a daily threat feed input:**

```ini
[script://./bin/get-threat-feed.sh]
interval = 86400  # Run every 24 hours
index = threat_intel
sourcetype = csv
```

### Using Threat Intelligence Framework in Splunk ES

Splunk ES includes a **Threat Intelligence Framework** that simplifies the process of managing, normalizing, and correlating threat intelligence with your organization's security data.

- **Threat Intelligence Manager**: A central interface in Splunk ES to manage threat feeds and cross-correlate them with internal logs.

  - **Example**: A malicious IP address from a feed can be automatically compared with internal network logs to flag suspicious activity.

  **Example SPL for correlating threat intelligence data with internal logs**:

  ```spl
  index=network_logs [| inputlookup threatintel_by_ip] | stats count by src_ip
  ```
### Risk-Based Scoring Using Threat Intelligence

Assign risk scores to assets or users based on threat intelligence, helping prioritize incidents with higher potential impact.

- **Example**: If a critical server communicates with a known malicious IP, its risk score is automatically elevated, triggering an alert.

---

### Automated Threat Detection

Automation in threat detection helps organizations identify emerging threats and respond more efficiently. Splunk’s **Machine Learning Toolkit (MLTK)** allows you to apply machine learning algorithms for proactive detection of anomalies and suspicious behavior.

---

#### Leveraging Machine Learning for Threat Detection

Splunk’s MLTK provides tools for applying both supervised and unsupervised machine learning models to detect unusual or malicious activity.

- **Unsupervised Learning**: This method can be used to group similar events or detect outliers (anomalies). A common use case is anomaly detection in network traffic.

  **Example of using k-means clustering to group similar traffic patterns**:

  ```spl
  | inputlookup network_logs.csv | kmeans k=5 action_field="group"
   ```
  ### Example of Training a Logistic Regression Model for Threat Detection

Splunk’s **MLTK** allows you to apply logistic regression to historical data for threat detection.

**Example SPL for training a logistic regression model**:

```spl
| inputlookup training_data.csv
| fit LogisticRegression "threat" from "src_ip", "bytes_in", "bytes_out"
 ```
### Anomaly Detection Techniques Using Splunk's MLTK

Anomaly detection techniques flag unusual activities that deviate from established baselines. These techniques are useful for detecting insider threats or advanced persistent threats (APTs).

---

#### Time Series Anomaly Detection

Identify deviations from normal behavior over time.

**Example SPL for time series-based anomaly detection**:

```spl
index=network_logs | timechart avg(bytes_out) by src_ip | anomalydetection action="filter"
```
### Adaptive Thresholding

Adaptive thresholding uses historical patterns to adjust thresholds dynamically, improving accuracy in threat detection.

**Example**: Detecting excessive login attempts by dynamically adjusting the threshold based on user activity history.

---

### SOAR Use Cases

**Splunk SOAR (Security Orchestration, Automation, and Response)** allows security teams to automate responses to incidents, reducing response time and ensuring consistent handling of threats. By integrating SOAR with Splunk, you can automate workflows (called playbooks) for common security use cases like phishing attacks and brute-force login attempts.

---

#### Automating Responses to Common Threats (Phishing, Brute Force Attacks)

- **Phishing Response Playbook**: SOAR can automatically detect phishing emails, quarantine them, and notify affected users and security personnel.

  **Example Phishing Response Playbook Actions**:
  1. Detect phishing email based on subject, content, or sender.
  2. Quarantine the email.
  3. Block the sender’s domain or IP.
  4. Notify the security team and user.

  **Example SPL query to detect potential phishing emails**:
  ```spl
  index=email_logs | search subject="*urgent*" OR url="*suspicious_domain*"
  ```
### Brute Force Attack Response Playbook

SOAR can detect brute-force attacks, automatically block the offending IP, and notify the SOC.

---

#### Example Brute Force Response Playbook Actions:

1. Detect multiple failed login attempts within a short time window.
2. Block the IP via firewall integration.
3. Notify the security operations center (SOC) for further review.

---

**Example SPL query to detect brute-force login attempts**:

```spl
index=auth_logs action="failure" | stats count by src_ip | where count > 10
```
### Integration of SOAR with Other Security Tools (Firewalls, IDS/IPS, etc.)

SOAR can integrate with various security tools to automate responses, such as blocking malicious IPs on a firewall, disabling user accounts in Active Directory, or isolating infected machines via endpoint detection and response (EDR) solutions.

---

#### Firewall Integration

Automatically block IPs identified as malicious by threat intelligence or anomaly detection.

**Example Playbook Action to Block IP**:

```json
{
  "action": "block_ip",
  "parameters": {
    "ip": "$src_ip"
  }
}
```
### IDS/IPS Integration

Automatically trigger rules on your intrusion detection/prevention systems (IDS/IPS) based on alerts from Splunk.

---

#### Example:

Create a Splunk alert to trigger a custom rule in **Snort** or **Suricata** when suspicious traffic is detected.

### 2.5 <a name="data-models-and-cim-common-information-model"></a> Data Models and CIM (Common Information Model)

---

#### **CIM Overview**

The **Common Information Model (CIM)** in Splunk is a shared data model framework that allows users to normalize data from various sources into a consistent structure. This enables cross-source correlation and analysis by mapping raw data into predefined fields and tags across different data sources.

##### Understanding the Common Information Model (CIM)

- **CIM Standardization**: The CIM provides a common format for data generated from different sources (e.g., firewall logs, proxy logs, endpoint security logs). By standardizing the data structure, Splunk ES users can perform searches, correlation, and reporting across different datasets more efficiently.

- **CIM Add-on**: The Splunk CIM add-on helps map your data to predefined data models by providing field extractions, lookups, and tags.

  **Example**: For network traffic logs, fields such as `src_ip`, `dest_ip`, and `action` are standardized across logs from firewalls, routers, and other network devices.

##### Mapping Data to CIM-Compliant Data Models

Mapping your data to the CIM involves ensuring that fields from your raw data are extracted and renamed to match the fields defined by the CIM.

- **CIM-Ready Add-Ons**: Many Splunk technology add-ons (TAs) are already CIM-compliant, meaning they automatically map the ingested data to the appropriate CIM data models. Examples include the Splunk Add-ons for Windows, Cisco ASA, and AWS.

  **Example**: When using the **Splunk Add-on for Windows**, the authentication logs from Windows systems are automatically mapped to the Authentication data model, using fields like `src`, `dest`, and `user`.

- **Custom Field Mapping**: If you're working with a custom data source, you may need to manually map fields to the appropriate CIM fields.

  **Example**: Manually mapping a custom data source to the Web data model:
  
  ```spl
  index=custom_logs sourcetype=custom_web_logs 
  | eval action=if(http_status=200, "allowed", "blocked")
  | eval user=user_name
  | eval src=client_ip
  ```
### Important CIM Data Models

Key data models you should be familiar with for the exam:

- **Authentication**: Tracks login activities, including successes, failures, and anomalies. Fields include `src`, `dest`, `user`, `app`, `action`.
- **Network Traffic**: Monitors network activity and security, including inbound and outbound traffic. Fields include `src_ip`, `dest_ip`, `bytes_in`, `bytes_out`, `action`.
- **Endpoint**: Monitors endpoint activities such as processes, file changes, and user logins. Fields include `file_name`, `process_name`, `user`, `src_ip`.
- **Web**: Logs web server activity and security, such as requests, errors, and actions. Fields include `http_method`, `src_ip`, `url`, `action`.

---

### Pivot Reports

Splunk’s **Pivot** feature allows you to build reports and dashboards without needing to write SPL. Pivot works by querying CIM-compliant data models, making it easier to create customized visualizations based on normalized data.

---

#### Using Pivot to Build CIM-Compliant Dashboards and Reports

- **Pivot Interface**: The Pivot interface provides a drag-and-drop way to create charts, tables, and visualizations by selecting fields from the underlying CIM data models.

  **Example**: Building a report to visualize the number of successful vs. failed login attempts over time.
  - Go to Pivot in Splunk.
  - Select the Authentication data model.
  - Drag `action` to the row field (filter for success and failure).
  - Drag `time` to the column field.
  - Choose a visualization (e.g., bar chart, line chart).

  This will create a visual report showing login activity over time, categorized by success and failure.

- **CIM Data Model Mapping for Pivot**: Since Pivot works only with CIM-compliant data, ensure your data is mapped correctly to the respective CIM fields for accurate reporting.

  **Example Pivot Use Case**:
  
  - **Security Dashboard**: Create a dashboard that displays security incidents across multiple data sources, such as authentication failures, network traffic anomalies, and endpoint activities.
  
    - Bar chart showing failed login attempts over the past 7 days.
    - Line chart tracking network traffic volume (`bytes_in` and `bytes_out`) by `src_ip` and `dest_ip`.

---

### Normalization Techniques

Normalization is the process of converting raw data into a standardized format. This allows data from different sources to be used in searches, reports, and dashboards consistently. Splunk uses field extractions and lookups to normalize data into the CIM.

---

#### Data Normalization Using Field Extractions

Field extractions in Splunk are used to map raw data to CIM fields by extracting key-value pairs from logs. These can be created manually or by using Splunk’s **Field Extractor tool**.

- **Field Extractor Tool**: This tool helps automatically identify and extract fields from raw events.

  **Example of creating a field extraction for HTTP logs**:

  ```regex
  (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?<time>[^\]]+)\] "(?<http_method>[^"]+) (?<url>[^"]+) HTTP/(?<version>[^"]+)" (?<http_status>\d+)
  ```
  This extraction will map the source IP, time, HTTP method, URL, and HTTP status code from the raw log to standardized field names.

---

### Data Normalization Using Lookups

Lookups are used to enhance your data by mapping fields from external data sources to fields within Splunk.

- **Lookup Table**: A table that contains information that can be referenced during a search to enrich or normalize data.

  **Example**: Normalizing IP addresses with geolocation data:

  ```spl
  index=network_logs | lookup geoip ip as src_ip OUTPUT city, country
  ```
  This lookup enriches the raw IP addresses with city and country fields, allowing for more detailed analysis.

---

### Best Practices for Data Normalization

- **Use Consistent Naming Conventions**: Ensure field names are consistent across different data sources by mapping them to CIM-compliant fields.
- **Test Your Extractions**: Validate field extractions in small datasets before applying them to larger data sources to avoid performance issues.
- **Leverage Automatic Lookups**: Configure automatic lookups in `props.conf` to ensure that fields are enriched automatically whenever data is ingested.

---

### Summary of Key Study Points

- **Understand the Purpose of CIM**: CIM is crucial for ensuring data from multiple sources can be analyzed consistently within Splunk ES.
- **Familiarize Yourself with Key Data Models**: Know the most important CIM data models (e.g., Authentication, Network Traffic, Web) and the fields they use.
- **Master Pivot for Reporting**: Practice creating reports and dashboards using the Pivot interface to ensure you're comfortable building CIM-compliant visualizations.
- **Practice Field Extractions and Lookups**: Ensure you understand how to extract fields and use lookups to normalize data into CIM-compliant formats.
- **Know How to Map Data to CIM**: Understand how to map custom data sources to the appropriate CIM data models by using field extractions and lookups.

---

This markdown structure maintains readability with proper headings, lists, and code blocks for examples. It ensures clean formatting for anyone referencing or studying the material.
### 2.6 [Splunk Administration (Optional)](#splunk-administration-optional)

---

#### **User Management and RBAC (Role-Based Access Control)**

Splunk provides robust **Role-Based Access Control (RBAC)** features that allow admins to control access to data, apps, and specific functionalities based on user roles.

##### Creating Roles

Roles define what a user is allowed to do and what data they can access. You can create custom roles or use built-in roles like `admin`, `power`, and `user`.

**Example**:
To create a new custom role (e.g., `security_analyst`) and assign specific capabilities:

1. Go to **Settings** → **Access controls** → **Roles**.
2. Click **New Role** and configure the role:
   - **Role Name**: `security_analyst`
   - **Inherit from**: `user` (to inherit basic search capabilities)
   - **Indexes**: Add the indexes (e.g., `security_logs`) that this role can access.
   - **Capabilities**: Select specific capabilities, such as:
     - `edit_search_scheduler` (to schedule searches)
     - `list_settings` (to view app settings)

**Capabilities Overview**:
- **Search-Related Capabilities**: Define the ability to search, schedule reports, and use real-time searches.
- **Admin Capabilities**: Include abilities like managing users, editing data models, and configuring indexes.

##### Managing Users and Assigning Roles

To assign roles to users:
1. Go to **Settings** → **Access controls** → **Users**.
2. Click **New User** or edit an existing user.
3. Specify:
   - **Username**: e.g., `jdoe`
   - **Role**: Assign the `security_analyst` role created earlier.

**Example** (CLI):

You can also add users via the CLI with the following command:
```bash
splunk add user jdoe -password changeme123 -role security_analyst -email jdoe@company.com
```
---

### Controlling Access to Data

RBAC allows fine-grained control over which indexes, apps, and search capabilities users have access to. For example, a `security_analyst` role might have access to only the `security_logs` index and not other operational data.

**Use Case**: Restrict security analysts from viewing operational logs by only giving access to the `security_logs` index.
- Configure the role with access to only the `security_logs` index in the role settings.

---

### Index and Data Retention Policies

Indexes store data in Splunk, and managing these indexes is crucial for ensuring data availability, performance, and retention requirements.

#### Configuring Indexes

Each index in Splunk is configured with specific settings related to data storage, retention, and access control.

**Example**: To create a new index called `security_logs`:

1. Go to **Settings** → **Indexes** → **New Index**.
2. Set the following configurations:
   - **Index Name**: `security_logs`
   - **Max Size**: Set the maximum size for the index (e.g., 500 GB).
   - **Data Retention**: Set the retention period (e.g., 90 days).
   - **Home Path**: Specify where the index data will be stored (e.g., `/opt/splunk/var/lib/splunk/security_logs`).

---

#### Data Retention Policies

Retention policies control how long Splunk retains data before it is deleted. You can set retention policies based on:

- **Maximum Index Size**: Once the index reaches this size, older data is deleted.
- **Retention Period**: Once data is older than the specified retention period, it is removed.

**Example**: Configure the `security_logs` index to retain data for 90 days:

1. Go to **Settings** → **Indexes**.
2. Click on the `security_logs` index.
3. Under **Time-based Retention**, set **Retention Period** to `90` days.

You can also set this via the `indexes.conf` configuration file:

```ini
[security_logs]
homePath = /opt/splunk/var/lib/splunk/security_logs/db
coldPath = /opt/splunk/var/lib/splunk/security_logs/colddb
thawedPath = /opt/splunk/var/lib/splunk/security_logs/thaweddb
maxTotalDataSizeMB = 500000
frozenTimePeriodInSecs = 7776000  # 90 days in seconds
```
## Archiving Data

Older data can be archived instead of being deleted. To enable archiving:

1. Set the `frozenTimePeriodInSecs` in the `indexes.conf` file.
2. Define a path to archive the frozen data (optional).

---

## Monitoring Splunk Deployment

Monitoring the health of your Splunk deployment is key to ensuring reliable performance and identifying issues before they affect users.

### Health Monitoring Dashboards

Splunk provides built-in monitoring dashboards to track the health of search heads, indexers, and forwarders.

- **Splunk Monitoring Console**: Go to **Settings** → **Monitoring Console** for an overview of your deployment’s health.
   - **Indexer Performance**: Monitors indexing throughput, disk space usage, and CPU utilization on each indexer.
   - **Search Head Performance**: Monitors search performance, load, and memory usage.
   - **Forwarder Management**: Displays the status and health of all forwarders sending data to your Splunk instance.

---

### Troubleshooting

Common issues to monitor and troubleshoot include:

- **Indexer Disk Space**: Monitor indexer disk usage to avoid data loss due to full disks.
- **Search Job Failures**: Identify and resolve failed search jobs using the monitoring console or search logs.

**Example**: To monitor disk space usage on indexers:

1. Open the **Monitoring Console**.
2. Navigate to **Indexer -> Indexing Performance -> Indexing Rate & Volume**.

You can also use an SPL query to monitor disk usage:

```spl
| dbinspect index=_internal | stats sum(rawSize) as total_size by splunk_server
```
 ### Alerts for Deployment Health

Create alerts to notify the Splunk admin when specific health issues arise, such as disk space running low or forwarders disconnecting.

**Example**: Create an alert to trigger when the disk space on an indexer is below 10%:

```spl
| rest /services/server/status/resource-usage/disk | search free < 10 | table splunk_server, free
```
1. **Save this search as an alert**:
   - After running the search, click on the "Save As" option.
   - Select "Alert" from the dropdown options.

2. **Set trigger conditions**:
   - Under the "Alert Type," choose "Once" if you want the alert to trigger one time or "Per result" for multiple triggers.
   - Set the condition to trigger when the disk space is below 10%.
   - Configure the alert to send a notification via email when the condition is met by entering the recipient's email address under the "Send Email" option.

---

### Key Concepts Covered:

- **User Management and RBAC**: Creating roles, assigning users, and controlling data access.
- **Index Configuration**: Setting up indexes and retention policies to manage log data efficiently.
- **Monitoring and Troubleshooting**: Using built-in dashboards and custom searches to monitor Splunk's health and identify issues early.

---

This section covers the key aspects of **Splunk Administration**, including managing users and roles, configuring indexes and data retention, and monitoring the health of your Splunk deployment. These skills are essential for ensuring your Splunk environment operates smoothly and securely.


