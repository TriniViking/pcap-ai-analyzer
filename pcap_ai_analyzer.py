"""
pcap_ai_analyzer.py
====================

This module implements a simple, web‑based packet capture (PCAP) analysis tool
that harnesses machine learning to identify anomalies and suspicious traffic.

The goal of the application is to provide a cross‑platform (Windows, Linux,
macOS) experience and a browser‑based user interface.  Under the hood it
leverages Streamlit for the UI, Scapy for packet parsing, Pandas for data
manipulation, and scikit‑learn for unsupervised anomaly detection.  These
dependencies are not included in this repository; users should install them
via pip before running the application (see the README section at the bottom
of this file).

Key features provided by this application include:

* Protocol breakdown – counts of each network protocol observed in the PCAP.
* Top talkers – identification of hosts that send/receive the most bytes.
* Bandwidth reasoning – a best‑effort explanation of why a top host uses
  significant bandwidth, based on service port heuristics.
* Anomaly detection – detection of traffic outliers using an isolation forest.
* Basic intrusion detection – simple port‑scan detection by counting unique
  destination ports contacted by each host.

The application is designed as a starting point for more sophisticated
analysis.  By swapping out or extending the heuristic functions it can be
adapted to call external engines like Suricata or Snort, integrate
pre‑trained models, or visualise results in other ways.
"""

import io
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

import pandas as pd

try:
    # Importing scapy may fail if it is not installed.  The program will
    # present an informative error message to the user via Streamlit in
    # such cases.
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:  # pragma: no cover
    rdpcap = None  # type: ignore
    IP = None      # type: ignore
    TCP = None     # type: ignore
    UDP = None     # type: ignore

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover
    IsolationForest = None  # type: ignore

try:
    import streamlit as st
except ImportError:  # pragma: no cover
    # If streamlit is unavailable the script can still be imported for
    # command‑line use, but the UI will not launch.
    st = None  # type: ignore


def parse_pcap(pcap_bytes: bytes) -> pd.DataFrame:
    """Parse a PCAP file into a pandas DataFrame.

    Parameters
    ----------
    pcap_bytes:
        Raw bytes of the PCAP file as read from an uploaded file or disk.

    Returns
    -------
    pandas.DataFrame
        A DataFrame with columns: ``src``, ``dst``, ``proto``, ``length``,
        ``timestamp``, ``sport``, and ``dport``.  Only IP packets are
        recorded; non‑IP packets are ignored.

    Notes
    -----
    This function relies on scapy's `rdpcap` to read packets.  If scapy is
    not installed, it will raise a RuntimeError explaining that the
    dependency is missing.
    """
    if rdpcap is None:
        raise RuntimeError(
            "Scapy is required to parse PCAP files. Please install it via pip:"
            "\n    pip install scapy"
        )
    # Use a BytesIO buffer so scapy can read from bytes
    buffer = io.BytesIO(pcap_bytes)
    packets = rdpcap(buffer)
    rows = []
    for pkt in packets:
        # Only consider IP packets
        if IP and IP in pkt:
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            proto = ip_layer.proto
            length = len(pkt)
            timestamp = pkt.time  # epoch seconds
            sport: Optional[int] = None
            dport: Optional[int] = None
            if TCP and TCP in pkt:
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif UDP and UDP in pkt:
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            rows.append({
                'src': src,
                'dst': dst,
                'proto': proto,
                'length': length,
                'timestamp': timestamp,
                'sport': sport,
                'dport': dport,
            })
    df = pd.DataFrame(rows)
    return df


def protocol_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """Return counts for each protocol observed in the capture.

    Parameters
    ----------
    df:
        DataFrame produced by :func:`parse_pcap`.

    Returns
    -------
    pandas.DataFrame
        A DataFrame with protocol name and counts, sorted in descending order.
    """
    # Mapping from IP protocol numbers to human‑readable names
    proto_map = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        # Additional protocols can be added here
    }
    counts = df['proto'].value_counts().reset_index()
    counts.columns = ['proto', 'count']
    counts['name'] = counts['proto'].map(lambda x: proto_map.get(x, f'Protocol {x}'))
    return counts[['name', 'count']].sort_values('count', ascending=False)


def compute_bandwidth_usage(df: pd.DataFrame) -> pd.DataFrame:
    """Compute total bytes sent and received per host.

    Returns a DataFrame sorted by total bytes in descending order with
    columns ``host``, ``bytes_sent``, ``bytes_received`` and ``total_bytes``.
    """
    bytes_sent = df.groupby('src')['length'].sum().rename('bytes_sent')
    bytes_recv = df.groupby('dst')['length'].sum().rename('bytes_received')
    combined = pd.concat([bytes_sent, bytes_recv], axis=1).fillna(0)
    combined['total_bytes'] = combined['bytes_sent'] + combined['bytes_received']
    combined = combined.sort_values('total_bytes', ascending=False)
    combined.reset_index(inplace=True)
    combined.rename(columns={'index': 'host'}, inplace=True)
    return combined


def top_talkers_reason(df: pd.DataFrame, host: str, top_n_ports: int = 3) -> str:
    """Provide a heuristic explanation for why a host might be consuming bandwidth.

    The function inspects source and destination ports used by the specified host
    and returns a string describing the top few services observed.  It uses a
    predefined mapping of well‑known port numbers to service names; unknown
    ports are labelled as "Unknown".

    Parameters
    ----------
    df:
        DataFrame containing the parsed packets.
    host:
        IP address of the host to analyse.
    top_n_ports:
        Number of top ports to include in the explanation.

    Returns
    -------
    str
        A human‑readable explanation of the dominant services.
    """
    # Map well‑known ports to service descriptions
    port_service_map: Dict[int, str] = {
        20: 'FTP data',
        21: 'FTP control',
        22: 'SSH remote access',
        23: 'Telnet',
        25: 'SMTP email',
        53: 'DNS queries',
        80: 'HTTP web traffic',
        110: 'POP3 email',
        123: 'NTP time sync',
        143: 'IMAP email',
        161: 'SNMP',
        194: 'IRC chat',
        443: 'HTTPS web traffic',
        465: 'SMTPS email',
        587: 'SMTP email',
        993: 'IMAPS email',
        995: 'POP3S email',
        3306: 'MySQL database',
        3389: 'RDP remote desktop',
        5060: 'SIP/VoIP',
        554: 'RTSP streaming',
        1935: 'RTMP streaming',
        6881: 'BitTorrent peer‑to‑peer',
        8000: 'Web/video streaming',
        8080: 'HTTP proxy',
        8443: 'HTTPS proxy',
    }
    # Filter all packets where the host appears as source or destination
    relevant = df[(df['src'] == host) | (df['dst'] == host)].copy()
    # Concatenate source and destination ports to a single series and drop NaNs
    port_series = pd.concat([relevant['sport'], relevant['dport']]).dropna().astype(int)
    if port_series.empty:
        return "No transport‑layer ports observed for this host."
    top_ports = port_series.value_counts().head(top_n_ports).index.tolist()
    descriptions = []
    for port in top_ports:
        service = port_service_map.get(port, f'Port {port}')
        descriptions.append(service)
    explanation = ', '.join(descriptions)
    return f"Major services observed: {explanation}."


def detect_port_scans(df: pd.DataFrame, threshold: int = 100) -> List[Tuple[str, int]]:
    """Detect simple TCP/UDP port scans based on the number of unique destination ports.

    A host is flagged if it initiates connections (as source) to more than
    ``threshold`` unique destination ports.  Only packets containing a source
    port are considered; thus purely passive traffic (e.g. responses) does not
    trigger a false positive.

    Returns
    -------
    List of tuples (host, port_count) for each host exceeding the threshold.
    """
    # Consider only packets with valid source and destination ports
    port_df = df.dropna(subset=['sport', 'dport'])
    # For each source IP, count distinct destination ports contacted
    port_counts = port_df.groupby('src')['dport'].nunique()
    flagged = [(host, int(count)) for host, count in port_counts.items() if count > threshold]
    return flagged


def compute_anomaly_scores(df: pd.DataFrame, n_estimators: int = 100) -> pd.DataFrame:
    """Compute anomaly scores using the Isolation Forest algorithm.

    The isolation forest is trained on a small set of features derived from
    packets: packet length and time delta from the previous packet (for the
    entire capture).  Because PCAPs can contain a large number of packets,
    users should be cautious when analysing very large captures; subsampling
    may be necessary for performance.

    Returns the original DataFrame with two new columns: ``time_delta`` and
    ``anomaly_score``.  A lower score indicates a more anomalous packet.
    """
    if IsolationForest is None:
        raise RuntimeError(
            "scikit‑learn is required for anomaly detection. Please install it via pip:"
            "\n    pip install scikit‑learn"
        )
    # Sort by timestamp and compute inter‑arrival time delta
    df = df.sort_values('timestamp').copy()
    df['time_delta'] = df['timestamp'].diff().fillna(0)
    # Select features for the model
    features = df[['length', 'time_delta']].values
    clf = IsolationForest(n_estimators=n_estimators, contamination='auto', random_state=42)
    clf.fit(features)
    scores = clf.score_samples(features)
    df['anomaly_score'] = scores
    return df


def run_ui() -> None:
    """Launch the Streamlit user interface.

    This function should be called from the ``__main__`` block.  It builds
    an interactive web app that runs locally and can be accessed via a
    browser.  Users can upload PCAP files, view basic statistics, detect
    anomalies, and download reports.
    """
    if st is None:
        raise RuntimeError(
            "Streamlit is not installed. Please install it via pip:\n    pip install streamlit"
        )
    st.set_page_config(page_title="AI PCAP Analyzer", layout="wide")
    st.title("AI‑Powered PCAP Analyzer")
    st.write(
        "Upload a network capture (PCAP) file to analyse protocols, "
        "identify top talkers, detect potential intrusions, and find anomalies."
    )
    uploaded_file = st.file_uploader("PCAP file", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        pcap_bytes = uploaded_file.read()
        try:
            df = parse_pcap(pcap_bytes)
        except RuntimeError as exc:
            st.error(str(exc))
            return
        st.subheader("Protocol Breakdown")
        proto_counts = protocol_breakdown(df)
        st.dataframe(proto_counts, use_container_width=True)

        st.subheader("Top Talkers")
        bw_df = compute_bandwidth_usage(df)
        st.dataframe(bw_df.head(10), use_container_width=True)
        if not bw_df.empty:
            top_host = bw_df.iloc[0]['host']
            reason = top_talkers_reason(df, top_host)
            st.info(f"The host {top_host} is the top talker. {reason}")

        st.subheader("Intrusion Detection (Port Scans)")
        scans = detect_port_scans(df)
        if scans:
            for host, count in scans:
                st.warning(f"Potential port scan detected from {host} (contacted {count} unique ports)")
        else:
            st.success("No obvious port scans detected.")

        st.subheader("Anomaly Detection")
        if st.checkbox("Run anomaly detection (may be slow)"):
            try:
                anomaly_df = compute_anomaly_scores(df)
            except RuntimeError as exc:
                st.error(str(exc))
                return
            st.write(
                "Anomaly scores (lower means more anomalous). "
                "Displaying the 10 most anomalous packets:"
            )
            top_anomalies = anomaly_df.nsmallest(10, 'anomaly_score')
            st.dataframe(
                top_anomalies[['src', 'dst', 'length', 'time_delta', 'anomaly_score']],
                use_container_width=True
            )

    st.markdown(
        """
        ### Instructions

        1. Install the required dependencies:
           ```bash
           pip install streamlit scapy pandas scikit‑learn
           ```
        2. Save this script as `pcap_ai_analyzer.py`.
        3. Run the app with:
           ```bash
           streamlit run pcap_ai_analyzer.py
           ```
        4. Open the provided URL in your browser (usually `http://localhost:8501`).

        **Note**: Large PCAP files can take considerable time and memory to process.  For
        production environments you may wish to integrate a more scalable parser such
        as PyPCAPKit【807052182089827†L132-L146】 or adopt dedicated tools like Malcolm【147587170629601†L27-L63】,
        Suricata【817699540028695†L50-L55】, Snort【414316282772405†L302-L329】, or Zeek【745234784077833†L88-L103】【501479018270560†L3076-L3096】.
        """
    )


# Only run the UI if this script is executed directly
if __name__ == "__main__":  # pragma: no cover
    if st is not None:
        run_ui()
    else:
        print(
            "Streamlit is not installed. Install the dependencies and run this script "
            "with `streamlit run pcap_ai_analyzer.py` to launch the web UI."
        )