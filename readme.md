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

### 2.1 Splunk Fundamentals
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

### 2.2 Splunk Enterprise Security (ES)
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

### 2.3 Security Monitoring and Incident Response
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

### 2.4 Threat Intelligence and Automation
- **Integration of Threat Feeds**
  - Integrating third-party threat intelligence sources with Splunk
  - Using Threat Intelligence Framework in Splunk ES
- **Automated Threat Detection**
  - Leveraging machine learning for threat detection
  - Anomaly detection techniques using Splunk's MLTK
- **SOAR Use Cases**
  - Automating responses to common threats (phishing, brute force attacks)
  - Integration of SOAR with other security tools (firewalls, IDS/IPS, etc.)

### 2.5 Data Models and CIM (Common Information Model)
- **CIM Overview**
  - Understanding the Common Information Model (CIM)
  - Mapping data to CIM-compliant data models
- **Pivot Reports**
  - Using Pivot to build CIM-compliant dashboards and reports
- **Normalization Techniques**
  - Data normalization using field extractions and lookups

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

### 2.1 Splunk Fundamentals

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
