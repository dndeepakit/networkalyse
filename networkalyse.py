# app.py
import streamlit as st
import subprocess
import tempfile
import os
import csv
from datetime import datetime
import pandas as pd
import time
from pathlib import Path

st.set_page_config(page_title="RCA — Top Talkers Capture", layout="wide")
st.title("🔍 RCA Capture — Top Talkers (short window)")

st.markdown("""
Run a short packet capture on the host to identify **top talkers** (IPs consuming the most bytes) during the window.
**NOTE:** This app requires `tshark` installed on the host and permission to capture packets (may require sudo).
""")

# -------- UI inputs --------
col1, col2, col3 = st.columns([1,1,1])
with col1:
    iface = st.text_input("Interface to capture (e.g., eth0)", value="eth0")
with col2:
    duration = st.number_input("Capture duration (seconds)", min_value=5, max_value=600, value=60, step=5)
with col3:
    top_n = st.number_input("Top N hosts to show", min_value=5, max_value=200, value=20, step=1)

st.markdown("---")

# -------- helpers --------
def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except Exception:
        return False

def run_tshark_capture(iface, duration, pcap_path):
    # write pcap file
    cmd = ["tshark", "-i", iface, "-a", f"duration:{duration}", "-w", pcap_path]
    # Note: may require sudo depending on host
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc

def parse_conv_ip_from_pcap(pcap_path):
    # Use tshark to output conv,ip summary (text) and parse it
    cmd = ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    text = out.stdout or out.stderr
    lines = text.splitlines()
    entries = []
    capture = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("IPv4 Conversations") or line.startswith("IPv6 Conversations"):
            capture = True
            continue
        if capture:
            # lines with IP convs often have structure: <ip1> <ip2> <frames1> <bytes1> <frames2> <bytes2> ...
            parts = line.split()
            if len(parts) >= 6 and parts[0].count(".") in (3,0) and parts[1].count(".") in (3,0):
                # try to parse
                try:
                    src = parts[0]
                    dst = parts[1]
                    bytes_src = int(parts[3])
                    bytes_dst = int(parts[5])
                    entries.append((src, bytes_src))
                    entries.append((dst, bytes_dst))
                except Exception:
                    continue
    # aggregate bytes per ip
    agg = {}
    for ip, b in entries:
        if ip.count(".") != 3:  # ignore non-ip tokens
            continue
        agg[ip] = agg.get(ip, 0) + b
    return agg

def read_arp_map():
    arp = {}
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4]
                arp[ip] = mac
    except Exception:
        try:
            out = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0].count(".") == 3:
                    ip = parts[0]; mac = parts[2]
                    arp[ip] = mac
        except Exception:
            pass
    return arp

def save_csv(rows, out_path):
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rank","ip","mac","bytes"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

# -------- Run capture action --------
if st.button("▶ Run RCA Capture Now"):
    st.info(f"Starting capture on interface `{iface}` for {duration} seconds...")
    if not check_tshark():
        st.error("tshark not found on host. Install tshark and ensure the Streamlit process can run it (may require sudo).")
    else:
        tmp_pcap = Path(tempfile.mktemp(suffix=".pcap"))
        try:
            proc = run_tshark_capture(iface, duration, str(tmp_pcap))
            if proc.returncode != 0:
                st.error(f"tshark returned error. Output:\n{proc.stderr}")
            else:
                st.success("Capture complete — parsing conversations...")
                agg = parse_conv_ip_from_pcap(str(tmp_pcap))
                if not agg:
                    st.warning("No IP conversations parsed from capture. Try a longer duration or a different interface.")
                else:
                    arp_map = read_arp_map()
                    rows = []
                    for i, (ip, b) in enumerate(sorted(agg.items(), key=lambda x: x[1], reverse=True)[:top_n], start=1):
                        rows.append({"rank": i, "ip": ip, "mac": arp_map.get(ip, ""), "bytes": b})
                    df = pd.DataFrame(rows)
                    st.subheader("Top talkers (by bytes) during capture window")
                    st.dataframe(df)
                    # human-readable sizes
                    df["bytes_human"] = df["bytes"].apply(lambda x: f"{x/1024/1024:.2f} MB")
                    st.table(df[["rank","ip","mac","bytes_human"]])

                    # save CSV
                    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    out_name = f"top_talkers_{ts}.csv"
                    save_csv(rows, out_name)
                    with open(out_name, "rb") as f:
                        st.download_button("⬇️ Download CSV Report", data=f, file_name=out_name, mime="text/csv")
                    st.info("CSV saved on host and available for download. You can map MAC → user from your inventory.")
        except Exception as e:
            st.error(f"Capture failed: {e}")
        finally:
            try:
                if tmp_pcap.exists():
                    tmp_pcap.unlink()
            except Exception:
                pass

st.markdown("---")
st.markdown("**Notes & guidance**")
st.markdown("""
- The capture runs on the host where Streamlit is deployed (so run this app on a server inside your LAN for useful results).  
- `tshark` must be installed. On Debian/Ubuntu: `sudo apt-get install -y tshark`.  
- Capturing packets may require sudo privileges, or run Streamlit as a user in the `wireshark` group (system-dependent).  
- For continuous historical flow-based reports, consider enabling NetFlow/sFlow on your router and running a flow collector (pmacct/softflowd) which integrates much easier with dashboards.
""")
