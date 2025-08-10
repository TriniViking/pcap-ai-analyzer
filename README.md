<!-- Cover image -->
![Cover](cover.png)

# PCAP AI Analyzer

**PCAP AI Analyzer** is a web‑based and Windows‑compatible tool that uses Python and Streamlit to make network packet‑capture analysis accessible to anyone.  Upload a `.pcap` file and the app automatically parses packets, calculates protocol distribution, identifies the biggest bandwidth consumers, flags port scans and runs an unsupervised anomaly detector using scikit‑learn.  The project was inspired by established network‑monitoring tools such as Suricata, Snort and Zeek, but it aims to provide a lightweight, user‑friendly alternative for quick inspections.

## Features

- **Protocol breakdown:** Counts packets by protocol (TCP, UDP, ICMP, etc.) and displays the results as a pie chart.
- **Top talkers:** Computes total bytes sent/received by each IP address and identifies the device using the most bandwidth.  A simple port‑to‑service mapping is used to guess what service is responsible (e.g., high traffic on port 443 implies HTTPS).
- **Port scan detection:** Flags source IPs that contact an unusually large number of destination ports in a short time window.
- **Anomaly detection:** Uses an Isolation Forest to score packets based on features such as packet length, protocol number and inter‑arrival time.  Points with a high anomaly score may indicate unusual behaviour.
- **Streamlit interface:** Runs locally on Windows or in the browser.  Drag‑and‑drop PCAP upload with interactive tables and charts.
 - **Extensible design:** You can integrate signature‑based engines like Suricata or Snort for deeper intrusion detection or feed Zeek logs into the data pipeline.

## Installation

1. **Install Python 3.10 or 3.11** (earlier or pre‑release versions such as 3.13 may not have compiled wheels for pandas).  On Windows you can download installers from [python.org](https://www.python.org/downloads/windows/); on macOS you can install Python via Homebrew with `brew install python@3.11`, and on Linux you can use your distribution’s package manager (for example `sudo apt install python3.11` on Ubuntu) or download installers from [python.org](https://www.python.org/downloads/).
2. **Clone this repository** or download the files to a folder.
3. **Set up a virtual environment and install dependencies:**

   **On Windows**:

   ```bash
   # create a virtual environment
   python -m venv pcap-env
   # activate it
   pcap-env\Scripts\activate

   # install the required packages
   pip install streamlit scapy pandas scikit-learn
   ```

   **On macOS or Linux**:

   ```bash
   # ensure you have Python 3.10 or 3.11 installed (use your package manager or Homebrew)
   # create a virtual environment
   python3 -m venv pcap-env
   # activate it
   source pcap-env/bin/activate

   # install the required packages
   pip install streamlit scapy pandas scikit-learn
   ```

4. **Run the app:**

   ```bash
   streamlit run pcap_ai_analyzer.py
   ```

   Streamlit will print a local URL (e.g., `http://localhost:8501`).  Open it in your browser to access the interface.

## Usage

1. **Upload a PCAP file** using the file‑uploader widget.  The app will parse packets and display summary statistics.
2. **Review the protocol breakdown** pie chart to understand the mix of protocols in the capture.
3. **Check the Top Talkers** table to see which devices are generating the most traffic and which services (ports) are involved.
4. **Inspect port‑scan warnings** if any source IPs attempted many port connections in a short window.
5. **Explore anomalous packets** flagged by the Isolation Forest to identify unusual patterns or outliers.

## FAQ

### Why do I need Python 3.10 or 3.11?

Many third‑party packages (notably pandas) publish binary wheels for stable Python releases but not for pre‑release versions such as 3.13.  Using a supported version ensures that pip can download prebuilt wheels instead of attempting to compile from source, which requires additional build tools.

### Can I integrate Suricata or Snort into this app?

Yes.  The current version uses a simple heuristic for port‑scan detection.  For more comprehensive intrusion detection, you can set up Suricata or Snort on the same machine or in a separate container and feed their alert logs into the app.  Suricata is an open‑source engine capable of real‑time intrusion detection, inline intrusion prevention and offline PCAP processing, while Snort combines signature, protocol and anomaly‑based inspection to detect malicious behaviour.

### Does the app handle large PCAP files?

The app loads the entire PCAP into memory and is best suited for small‑to‑medium captures (tens of megabytes).  For multi‑gigabyte captures, consider pre‑processing the data with tools like Zeek or using a full‑featured platform such as Malcolm.

## Troubleshooting

- **pip cannot find pandas wheel / “Failed to build wheel for pandas”:** Use Python 3.10 or 3.11 and upgrade pip with `pip install --upgrade pip setuptools wheel`.  Alternatively, install pandas with `pip install pandas==1.5.3 --only-binary=:all:` or use Conda.
- **Streamlit says modules are missing:** Ensure you’ve activated the correct virtual environment and installed all required packages.  You can reinstall them with `pip install --force-reinstall streamlit scapy pandas scikit-learn`.
- **No web page appears after running `streamlit run …`:** Check your firewall prompts and allow Python to open network ports.  Then open the URL shown in the terminal (usually `http://localhost:8501`).

## Contributing

Feel free to fork the repository and submit pull requests.  Ideas for improvement include:

- Adding support for Suricata/Snort log ingestion.
- Incorporating more advanced anomaly‑detection algorithms.
- Improving UI responsiveness for large files.
