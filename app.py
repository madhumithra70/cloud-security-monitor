import streamlit as st
import pandas as pd
import psutil
import platform
import subprocess
import socket
import random
import time
import json
from datetime import datetime
from pathlib import Path

st.set_page_config(page_title="Cloud Security Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ Multi-Agent AI Framework for Autonomous Security Monitoring")
st.caption("Windows Host Agent • Ubuntu Guest Agent (SSH) • Hypervisor Agent • Network Agent • Risk Analysis")

if "events" not in st.session_state:
    st.session_state.events = []
if "simulated" not in st.session_state:
    st.session_state.simulated = False

def add_event(source, severity, title, details, simulated=False, score=0):
    st.session_state.events.insert(0, {
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source": source,
        "Severity": severity,
        "Event": title,
        "Details": details,
        "Risk Score": score,
        "Mode": "SIMULATED" if simulated else "LIVE"
    })
    st.session_state.events = st.session_state.events[:300]

def risk_for(cpu, mem, disk, connections):
    score = 0
    reasons = []
    if cpu >= 90:
        score += 35; reasons.append(f"very high CPU ({cpu:.0f}%)")
    elif cpu >= 75:
        score += 20; reasons.append(f"high CPU ({cpu:.0f}%)")
    if mem >= 90:
        score += 30; reasons.append(f"very high memory ({mem:.0f}%)")
    elif mem >= 80:
        score += 15; reasons.append(f"high memory ({mem:.0f}%)")
    if disk >= 95:
        score += 25; reasons.append(f"very high disk usage ({disk:.0f}%)")
    elif disk >= 85:
        score += 10; reasons.append(f"high disk usage ({disk:.0f}%)")
    if connections >= 250:
        score += 20; reasons.append(f"many connections ({connections})")
    score = min(score, 100)
    severity = "Low" if score <= 30 else "Medium" if score <= 60 else "High"
    return score, severity, "; ".join(reasons) if reasons else "No configured resource threshold exceeded."

def run_command(args, timeout=4):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.stdout.strip(), p.returncode
    except Exception as e:
        return str(e), 1



def collect_ubuntu_metrics(host, port, username, password, timeout=8):
    """Collect a read-only snapshot from Ubuntu over SSH using Paramiko."""
    try:
        import paramiko
    except ImportError:
        return None, "Paramiko is not installed. Run: pip install paramiko"

    client = paramiko.SSHClient()
    # Suitable for this local student project; production deployments should verify host keys.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=int(port), username=username, password=password,
                       timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                       look_for_keys=False, allow_agent=False)
        command = "python3 -c 'import json,socket,platform,psutil; print(json.dumps({\"hostname\":socket.gethostname(),\"os\":platform.platform(),\"cpu_percent\":psutil.cpu_percent(interval=0.4),\"memory_percent\":psutil.virtual_memory().percent,\"memory_total_gb\":round(psutil.virtual_memory().total/1024**3,2),\"disk_percent\":psutil.disk_usage(\"/\").percent,\"processes\":sorted([ {\"pid\":p.info[\"pid\"],\"name\":p.info[\"name\"],\"cpu_percent\":p.info[\"cpu_percent\"] or 0,\"memory_percent\":p.info[\"memory_percent\"] or 0} for p in psutil.process_iter([\"pid\",\"name\",\"cpu_percent\",\"memory_percent\"]) ],key=lambda x:x[\"cpu_percent\"],reverse=True)[:15]}))'"
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        error = stderr.read().decode('utf-8', errors='replace').strip()
        if not output:
            return None, error or "Ubuntu returned no metrics. Check Python 3 and psutil in Ubuntu."
        return json.loads(output), None
    except Exception as exc:
        return None, "Ubuntu VM monitoring is temporarily unavailable. Check that the VM is running and SSH is configured."
    finally:
        client.close()

# Agent 1: host/system metrics
cpu = psutil.cpu_percent(interval=0.5)
mem = psutil.virtual_memory().percent
try:
    disk = psutil.disk_usage("C:\\" if platform.system() == "Windows" else "/").percent
except Exception:
    disk = 0
processes = []
for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
    try:
        processes.append(p.info)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
process_df = pd.DataFrame(processes)
if not process_df.empty:
    process_df["cpu_percent"] = pd.to_numeric(process_df["cpu_percent"], errors="coerce").fillna(0)
    process_df["memory_percent"] = pd.to_numeric(process_df["memory_percent"], errors="coerce").fillna(0)
    process_df = process_df.sort_values("cpu_percent", ascending=False)

# Agent 2: hypervisor / VirtualBox info
vbox_out, vbox_rc = run_command(["VBoxManage", "list", "runningvms"])
if vbox_rc != 0:
    # Windows common install location fallback
    candidates = [
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
    ]
    found = False
    if platform.system() == "Windows":
        for exe in candidates:
            if Path(exe).exists():
                vbox_out, vbox_rc = run_command([exe, "list", "runningvms"])
                found = True
                break
    if not found and vbox_rc != 0:
        vbox_out = "VBoxManage unavailable. Install VirtualBox or add its folder to PATH."
running_vms = [x for x in vbox_out.splitlines() if x.strip() and x.strip().startswith('"')]

# Agent 3: local network connections (metadata only; no packet payload capture)
try:
    conns = psutil.net_connections(kind="inet")
    conn_count = len(conns)
    established = sum(1 for c in conns if getattr(c, "status", "") == "ESTABLISHED")
    listening = sum(1 for c in conns if getattr(c, "status", "") == "LISTEN")
except (psutil.AccessDenied, OSError):
    conns, conn_count, established, listening = [], 0, 0, 0
    network_note = "Some connection details are unavailable; try running with appropriate permissions."
else:
    network_note = "Connection metadata only. Packet capture and full-network visibility are not enabled by this starter app."

score, severity, reason = risk_for(cpu, mem, disk, conn_count)
if score > 0:
    add_event("Risk Engine", severity, "Resource/network threshold warning", reason, score=score)

# Sidebar controls
st.sidebar.header("Controls")
refresh = st.sidebar.checkbox("Auto-refresh every 10 seconds", value=False)
st.sidebar.write("Current OS:", platform.system(), platform.release())
st.sidebar.write("Hostname:", socket.gethostname())
st.sidebar.subheader("Ubuntu VM SSH")
ssh_enabled = st.sidebar.checkbox("Enable Ubuntu guest monitoring", value=True)
ssh_host = st.sidebar.text_input("SSH host", value="127.0.0.1")
ssh_port = st.sidebar.number_input("SSH host port", min_value=1, max_value=65535, value=2222, step=1)
ssh_user = st.sidebar.text_input("Ubuntu username", value="clouduser")
ssh_password = st.sidebar.text_input("Ubuntu password", type="password")
fetch_ubuntu = st.sidebar.button("Collect Ubuntu metrics")
if "ubuntu_metrics" not in st.session_state:
    st.session_state.ubuntu_metrics = None
if "ubuntu_error" not in st.session_state:
    st.session_state.ubuntu_error = "Enter credentials and click 'Collect Ubuntu metrics' to fetch a live snapshot."
if fetch_ubuntu and ssh_enabled:
    if not ssh_password:
        st.session_state.ubuntu_metrics = None
        st.session_state.ubuntu_error = "Enter the Ubuntu password in the sidebar first."
    else:
        with st.spinner("Connecting to Ubuntu over SSH..."):
            guest_data, guest_error = collect_ubuntu_metrics(ssh_host, int(ssh_port), ssh_user, ssh_password)
        st.session_state.ubuntu_metrics = guest_data
        st.session_state.ubuntu_error = guest_error or "Connected successfully."
if st.sidebar.button("Generate simulated suspicious event"):
    options = [
        ("VM Agent", "High", "Simulated resource spike", "Test CPU spike detected in simulation.", 78),
        ("Network Agent", "High", "Simulated unusual connection burst", "Synthetic connection burst generated for demonstration.", 82),
        ("Hypervisor Agent", "Medium", "Simulated VM state warning", "Synthetic VM state change warning.", 48)
    ]
    item = random.choice(options)
    add_event(*item[:4], simulated=True, score=item[4])
    st.session_state.simulated = True
    st.rerun()
if st.sidebar.button("Clear event history"):
    st.session_state.events = []
    st.rerun()

# Header status cards
c1, c2, c3, c4 = st.columns(4)
c1.metric("CPU Usage", f"{cpu:.1f}%")
c2.metric("Memory Usage", f"{mem:.1f}%")
c3.metric("Disk Usage", f"{disk:.1f}%")
c4.metric("Network Connections", conn_count)

if severity == "High":
    st.error(f"Overall risk: {severity} — {score}/100. {reason}")
elif severity == "Medium":
    st.warning(f"Overall risk: {severity} — {score}/100. {reason}")
else:
    st.success(f"Overall risk: {severity} — {score}/100. {reason}")

st.caption("Risk score is a project-defined heuristic, not a certified security rating or proof of an attack.")

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Overview", "Host Processes", "Hypervisor", "Network & Alerts", "Ubuntu VM Monitor"])

with tab1:
    st.subheader("Resource usage")
    chart_df = pd.DataFrame({"Metric": ["CPU", "Memory", "Disk"], "Usage (%)": [cpu, mem, disk]})
    st.bar_chart(chart_df.set_index("Metric"))
    st.subheader("Agent status")
    status_data = [
        {"Agent": "VM/System Agent", "Status": "Running", "Data": "Live host metrics via psutil"},
        {"Agent": "Hypervisor Agent", "Status": "Connected" if vbox_rc == 0 else "Unavailable", "Data": "VirtualBox CLI" if vbox_rc == 0 else "VirtualBox CLI not detected"},
        {"Agent": "Network Agent", "Status": "Running" if conn_count >= 0 else "Limited", "Data": f"{conn_count} local connection entries"}
    ]
    st.dataframe(pd.DataFrame(status_data), use_container_width=True, hide_index=True)
    st.info("Ubuntu guest metrics are collected separately in the Ubuntu VM Monitor tab over SSH.")

with tab2:
    st.subheader("Windows host process list")
    st.caption("Process visibility depends on your account permissions.")
    if not process_df.empty:
        st.dataframe(process_df.head(100), use_container_width=True, hide_index=True)
    else:
        st.info("No process data available.")

with tab3:
    st.subheader("VirtualBox hypervisor monitoring")
    if vbox_rc == 0:
        if running_vms:
            st.success(f"{len(running_vms)} running VM(s) found.")
            st.code("\n".join(running_vms))
        else:
            st.info("VirtualBox CLI responded, but no running VMs were reported.")
        all_out, all_rc = run_command(["VBoxManage", "list", "vms"])
        if all_rc == 0:
            with st.expander("All registered VirtualBox VMs"):
                st.code(all_out or "No registered VMs returned.")
    else:
        st.warning(vbox_out)
        st.write("This agent cannot report real hypervisor state until VirtualBox CLI is accessible.")

with tab4:
    st.subheader("Network connection summary")
    n1, n2, n3 = st.columns(3)
    n1.metric("Connection entries", conn_count)
    n2.metric("Established", established)
    n3.metric("Listening", listening)
    st.info(network_note)
    if conns:
        rows = []
        for c in conns[:300]:
            try:
                rows.append({
                    "Family": str(c.family),
                    "Type": str(c.type),
                    "Local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "Remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "Status": c.status,
                    "PID": c.pid
                })
            except Exception:
                pass
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    st.subheader("Security event history")
    if st.session_state.events:
        event_df = pd.DataFrame(st.session_state.events)
        st.dataframe(event_df, use_container_width=True, hide_index=True)
        st.download_button("Download event history CSV", event_df.to_csv(index=False).encode("utf-8"), "security_events.csv", "text/csv")
    else:
        st.info("No alert events recorded yet. Use the sidebar button to test a clearly labelled simulated event.")

with tab5:
    st.subheader("Ubuntu guest operating-system monitoring")
    st.caption("Live snapshot from inside CloudSecurity-VM1 via SSH port forwarding; separate from Windows host metrics.")
    guest = st.session_state.ubuntu_metrics
    if guest:
        g1, g2, g3, g4 = st.columns(4)
        g1.metric("Ubuntu CPU Usage", f"{guest.get('cpu_percent', 0):.1f}%")
        g2.metric("Ubuntu Memory Usage", f"{guest.get('memory_percent', 0):.1f}%")
        g3.metric("Ubuntu Disk Usage", f"{guest.get('disk_percent', 0):.1f}%")
        g4.metric("Guest Processes Listed", len(guest.get('processes', [])))
        st.success(f"Connected to {guest.get('hostname', 'Ubuntu')} — {guest.get('os', 'Linux')}")
        guest_chart = pd.DataFrame({"Metric": ["CPU", "Memory", "Disk"], "Usage (%)": [guest.get("cpu_percent", 0), guest.get("memory_percent", 0), guest.get("disk_percent", 0)]})
        st.bar_chart(guest_chart.set_index("Metric"))
        st.subheader("Top Ubuntu processes by CPU")
        guest_processes = pd.DataFrame(guest.get("processes", []))
        if not guest_processes.empty:
            st.dataframe(guest_processes, use_container_width=True, hide_index=True)
        else:
            st.info("No process details were returned.")
    else:
        st.warning(st.session_state.ubuntu_error)
        st.markdown("Make sure Ubuntu is running, SSH is active, and VirtualBox forwards host port **2222** to guest port **22**. Enter the Ubuntu username and password in the sidebar, then click **Collect Ubuntu metrics**.")
        st.code("ssh -p 2222 clouduser@127.0.0.1", language="bash")

st.caption(f"Last refresh: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
if refresh:
    time.sleep(10)
    st.rerun()
