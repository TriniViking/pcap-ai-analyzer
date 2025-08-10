# AI App for Web‑Based and Windows PCAP Analysis – Research Summary (August 10 2025)

## Objective

The user requested an **AI-powered application** that allows people to upload and analyze network packet capture (PCAP) files in the cloud (web-based) or on a Windows machine.  The app should parse raw packet data, generate statistics (protocol breakdown, bandwidth usage per device), detect network anomalies, and provide hints about why a particular device is consuming the most bandwidth.  Key requirements include:

* **Platform support** – Run via a web browser and optionally as a Windows desktop application (e.g., packaged with Python for offline use).
* **Programming language/framework** – Flexible; Python offers rich network‑analysis libraries and rapid prototyping.
* **Analysis capabilities** – Provide protocol breakdown, intrusion/anomaly detection, and bandwidth usage per device with explanations.

This report summarises the open‑source tools and libraries researched to inform the design and architecture of the proposed app.

## Available open‑source tools and libraries

### Packet parsing and protocol analysis

* **Wireshark/libpcap** – Wireshark is a powerful open‑source network protocol analyzer that lets users capture and browse traffic interactively; it supports deep inspection of hundreds of protocols【949837252761407†L169-L173】.  Its low‑level capture library (libpcap) is widely used for packet capture and forms the basis of many other tools, but Wireshark itself is a full GUI application rather than a library suitable for integration in a web app.

* **Scapy / PyShark / PyPCAPKit** – Several Python libraries can parse PCAP files programmatically.  The PyPCAPKit library is a comprehensive Python-native packet analysis toolkit offering more detailed information than Scapy or PyShark and providing a simple interface to extract and dissect packets【807052182089827†L132-L147】.  For ease of integration and community support, the code uses **Scapy** (available via pip) to parse PCAPs and compute protocol breakdown; Scapy can dissect packets and provides results that are easily converted into pandas dataframes.

* **PCAP analysis tools** – Many open‑source projects exist to process PCAPs and detect threats.  Suricata and Snort are two major intrusion detection systems.  **Suricata** is a free open‑source network threat detection engine capable of real‑time intrusion detection, inline intrusion prevention, network security monitoring, and offline PCAP processing【817699540028695†L50-L55】.  **Snort** is a lightweight open‑source IDS/IPS that performs real‑time traffic analysis and packet recording; it uses a rule‑based language combining anomaly, protocol and signature inspection and runs on Linux/Unix/Windows【414316282772405†L302-L344】.  These engines could be integrated into a back‑end microservice to provide deeper signature‑based detection if needed.

* **Zeek** – Formerly known as Bro, Zeek is an open‑source network security monitoring tool that passively observes traffic and produces high‑fidelity transaction logs and file contents.  Zeek focuses on semantic analysis, producing logs ideal for manual review or integration with SIEMs【745234784077833†L88-L103】.  The *Book of Zeek* emphasises that while Zeek can carve files and do some intrusion detection, traditional byte-centric intrusion detection is better handled by Snort or Suricata【501479018270560†L3076-L3096】.  For our application, Zeek’s transaction logs could complement raw PCAP analysis but require significant server resources to process large captures.

* **Malcolm** – Malcolm is an open-source network traffic analysis tool suite that accepts PCAPs, Zeek logs and Suricata alerts.  It normalises and enriches data and provides dashboards via OpenSearch and Arkime; the platform runs as containerised components and is easy to deploy【147587170629601†L27-L63】.  Malcolm also includes anomaly detection based on OpenSearch’s Random Cut Forest algorithm, with detectors for network protocol, action/results per user, MIME type and total bytes【847762902120904†L24-L45】.  Malcolm inspired the design of the AI app’s anomaly detection component.

### Anomaly and intrusion detection algorithms

* **Rule‑based signatures** – Tools like Suricata and Snort rely on signature rules to detect known malicious behaviour (e.g., port scans, known attack patterns).  They combine signature, protocol and anomaly-based inspection【414316282772405†L302-L344】.  These rules provide high detection accuracy for known threats but may miss novel behaviours.

* **Anomaly detection** – Machine‑learning algorithms can identify traffic that deviates from normal behaviour.  Malcolm uses the Random Cut Forest algorithm to detect anomalies in real time across multiple fields【847762902120904†L24-L45】.  For our app, a simpler unsupervised anomaly detector like **Isolation Forest** from scikit‑learn suffices; it estimates how isolated a sample is in the feature space.

### Application frameworks

* **Streamlit** – A Python library for quickly building web apps.  Streamlit allows uploading files, displaying tables, charts and interactive visualisations with minimal code.  It runs on Windows and can be deployed as a web application.  Therefore, Streamlit is chosen as the front‑end for the AI app.

* **scikit‑learn & pandas** – Pandas is used for data manipulation and computing statistics.  scikit‑learn provides the Isolation Forest algorithm for anomaly detection.  Both are widely adopted and integrate seamlessly with Streamlit.

## Architecture of the AI PCAP‑analysis app

The final prototype is delivered as `pcap_ai_analyzer.py` (included separately).  The app’s major components are:

1. **PCAP parsing** – When the user uploads a PCAP file, the app uses Scapy to read packets and convert them into a pandas DataFrame.  Each row stores source and destination IPs, ports, protocol numbers and packet lengths.  Additional functions compute the **protocol breakdown** by counting the number of packets per protocol.

2. **Bandwidth usage and “top talker” analysis** – Bandwidth consumption is calculated by grouping packets by device (IP address) and summing the total bytes.  The top talker (device using the most bandwidth) is identified.  To explain why a device uses the most bandwidth, a dictionary maps common ports to services (e.g., port 443 → HTTPS, 80 → HTTP, 53 → DNS).  The app uses the most frequent destination ports of the top talker to guess the services causing high usage.

3. **Intrusion detection (port scan heuristic)** – A simple heuristic checks for port scans by counting how many unique destination ports each source IP contacts within a small time window.  If a source sends packets to an unusually large number of ports in a short period, it may indicate a scan.  While this is not as robust as Suricata/Snort’s rule‑based detection, it provides immediate alerts without external dependencies.

4. **Anomaly detection** – To detect unusual traffic patterns, the app uses scikit‑learn’s Isolation Forest.  It trains on features such as packet length, protocol number and inter‑arrival time and flags packets with high anomaly scores.  This replicates Malcolm’s concept of using machine‑learning to detect anomalies in network logs【847762902120904†L24-L45】 but in a simplified form.

5. **User interface** – Streamlit provides a web interface where users upload PCAP files and view results.  The app displays the protocol breakdown pie chart, lists the top talkers with their traffic share and heuristically guessed reasons for their bandwidth usage, summarises any detected port scans, and shows a table of anomalous packets with their anomaly scores.  Users running the app locally on Windows can open it in a browser at `http://localhost:8501` after running the script.

## Advantages and limitations

**Advantages:**

* Uses **open‑source libraries**; no licensing costs.
* Runs on both web and Windows; Streamlit simplifies deployment.
* Provides immediate insights (protocol breakdown, bandwidth usage, port‑scan detection, anomaly scores) from raw PCAPs.
* Extensible: advanced users could integrate Snort/Suricata rules or Zeek logs for deeper analysis.

**Limitations:**

* The simple port‑scan heuristic may generate false positives; true intrusion detection requires signature engines like Suricata or Snort【414316282772405†L302-L344】.
* Isolation Forest identifies generic anomalies but does not attribute them to specific causes; users should investigate flagged packets manually.
* Running on large PCAPs (GBs) may be slow; consider using distributed platforms like Malcolm for large‑scale analysis【147587170629601†L27-L63】.

## Conclusion

The research demonstrates that an AI‑powered PCAP analysis app is feasible using existing open‑source technologies.  Python’s Scapy and pandas can parse packets and compute statistics, while scikit‑learn’s Isolation Forest offers a simple anomaly detector.  Streamlit provides a user‑friendly interface for both web‑based and Windows deployments.  Although deeper intrusion detection might require integration with established engines like Suricata or Snort【817699540028695†L50-L55】【414316282772405†L302-L344】, the prototype offers a practical starting point for network traffic analysis and can be extended with additional modules as needed.