# Multi-Agent AI Framework for Autonomous Security Monitoring

## Features
- VM/system agent: host CPU, memory, disk and process metrics
- Hypervisor agent: checks VirtualBox CLI (`VBoxManage`) and lists running/registered VMs when available
- Network agent: local network connection metadata using psutil
- Risk engine: transparent, configurable heuristic scoring and severity labels
- Streamlit dashboard, event history, simulated test event, CSV export

## Windows setup
Install Python 3.10+ from https://www.python.org/downloads/ and select **Add Python to PATH** during installation.

Open Command Prompt in this folder and run:

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If `python` is not recognized, try `py` in place of `python`.

Open the local URL printed by Streamlit, usually http://localhost:8501.

## VirtualBox integration
Install VirtualBox on the Windows host. If `VBoxManage` is not found, the app tries the common Windows installation paths. You can add the VirtualBox installation folder to PATH and restart Command Prompt.

## Important limitations
- Host metrics are not the same as guest VM metrics. Run a guest agent inside each guest VM for real guest-internal metrics.
- Network data is connection metadata; this app does not capture packet payloads or guarantee visibility into every interface.
- Simulated alerts are labelled SIMULATED. They are for demonstrations and are not evidence of an actual attack.
- Risk scores are demonstration heuristics, not a validated security product.
- Do not use destructive automated responses. Investigate alerts and test only on systems you are authorized to monitor.
