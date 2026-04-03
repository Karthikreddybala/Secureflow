#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║        SecureFlow DEMO — Attack Simulator v1.0              ║
# ║   Copy-paste this into Termux on Phone 2 (Attacker)         ║
# ║   Run:  bash demo_attack.sh                                 ║
# ╚══════════════════════════════════════════════════════════════╝

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

clear
echo ""
echo -e "${RED}${BLD}"
echo "  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗"
echo "  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝"
echo "  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  "
echo "  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  "
echo "  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗"
echo "  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝"
echo -e "${RST}"
echo -e "${YEL}         DEMO ATTACK SIMULATOR — Phone 2 (Attacker)${RST}"
echo -e "${CYN}  ──────────────────────────────────────────────────${RST}"
echo ""

# ── Step 1: Install nmap if not present ───────────────────────
if ! command -v nmap &> /dev/null; then
    echo -e "${YEL}[*] nmap not found. Installing...${RST}"
    pkg update -y -q && pkg install nmap -y -q
    echo -e "${GRN}[✓] nmap installed!${RST}"
else
    echo -e "${GRN}[✓] nmap already installed${RST}"
fi
echo ""

# ── Step 2: Auto-detect gateway (SecureFlow laptop IP) ────────
echo -e "${CYN}[*] Detecting SecureFlow gateway...${RST}"

GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)

if [ -z "$GATEWAY" ]; then
    # Fallback: try common hotspot gateway IP
    GATEWAY="192.168.137.1"
fi

echo -e "${GRN}[✓] Target Gateway: ${BLD}$GATEWAY${RST}"

# Get our own IP
MY_IP=$(ip route get "$GATEWAY" 2>/dev/null | grep src | awk '{print $5}' | head -1)
echo -e "${GRN}[✓] Attacker IP:    ${BLD}$MY_IP${RST}"
echo ""

# ── Confirm before attacking ───────────────────────────────────
echo -e "${YEL}┌─────────────────────────────────────────────┐${RST}"
echo -e "${YEL}│  Ready to launch demo attacks on:           │${RST}"
echo -e "${YEL}│  Target: ${BLD}$GATEWAY                         ${YEL}│${RST}"
echo -e "${YEL}│                                             │${RST}"
echo -e "${YEL}│  Attacks: PortScan → DoS Ping → SYN Flood  │${RST}"
echo -e "${YEL}└─────────────────────────────────────────────┘${RST}"
echo ""
echo -e "  Press ${BLD}ENTER${RST} to begin attack demo..."
read -r

# ═══════════════════════════════════════════════════════════════
#  ATTACK 1 — PORT SCAN  (triggers: PortScan • T1046 • High)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${RED}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${RED}${BLD}║  ATTACK 1: PORT SCAN                        ║${RST}"
echo -e "${RED}${BLD}║  Expected Alert: PortScan • HIGH • T1046    ║${RST}"
echo -e "${RED}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo ""
echo -e "${CYN}[*] Running SYN port scan on $GATEWAY ...${RST}"
echo -e "${CYN}[*] Watch the SecureFlow ALERTS page 👁️${RST}"
echo ""

# Aggressive scan: fast timing, common ports → generates many SYN packets
# This creates many short flows rapidlydistinct destination ports → PortScan classification
nmap -sS -T4 -p 21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5000,5173,8000,8080,8443,9090 "$GATEWAY" 2>/dev/null

echo ""
echo -e "${GRN}[✓] Port scan complete! Check dashboard for PORTSCAN alert.${RST}"
echo ""
echo -e "  Press ${BLD}ENTER${RST} to launch Attack 2..."
read -r

# ═══════════════════════════════════════════════════════════════
#  ATTACK 2 — ICMP FLOOD  (triggers: DoS • T1498 • High)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${RED}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${RED}${BLD}║  ATTACK 2: ICMP PING FLOOD (DoS)            ║${RST}"
echo -e "${RED}${BLD}║  Expected Alert: DoS • HIGH • T1498         ║${RST}"
echo -e "${RED}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo ""
echo -e "${CYN}[*] Flooding $GATEWAY with 500 large pings...${RST}"
echo -e "${CYN}[*] This generates high-volume ICMP traffic → DoS classification${RST}"
echo ""

# 500 pings, 1400-byte payload, minimal interval
# Generates: high Flow Bytes/s + high Flow Packets/s → DoS label
ping -c 500 -s 1400 -i 0.02 "$GATEWAY" 2>/dev/null | tail -3

echo ""
echo -e "${GRN}[✓] ICMP flood complete! Check dashboard for DoS alert.${RST}"
echo ""
echo -e "  Press ${BLD}ENTER${RST} to launch Attack 3..."
read -r

# ═══════════════════════════════════════════════════════════════
#  ATTACK 3 — RAPID HTTP REQUESTS  (triggers: Anomaly/DDoS)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${RED}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${RED}${BLD}║  ATTACK 3: HTTP RAPID-FIRE (DDoS Sim)       ║${RST}"
echo -e "${RED}${BLD}║  Expected Alert: Anomaly/DDoS • HIGH        ║${RST}"
echo -e "${RED}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo ""
echo -e "${CYN}[*] Sending 200 rapid HTTP connections to port 8000...${RST}"
echo -e "${CYN}[*] Saturates flow table → anomaly/DDoS detection${RST}"
echo ""

# Install curl if needed
if ! command -v curl &> /dev/null; then
    pkg install curl -y -q
fi

# Fire 200 concurrent HTTP requests in batches
HITS=0
for batch in $(seq 1 20); do
    for i in $(seq 1 10); do
        curl -s --max-time 1 "http://$GATEWAY:8000/" > /dev/null 2>&1 &
    done
    HITS=$((HITS + 10))
    echo -ne "\r  ${YEL}Requests sent: ${BLD}$HITS/200${RST}  "
    sleep 0.3
done
wait

echo ""
echo ""
echo -e "${GRN}[✓] HTTP flood complete! Check dashboard for DDoS/Anomaly alert.${RST}"
echo ""

# ═══════════════════════════════════════════════════════════════
#  ATTACK 4 — SUBNET DISCOVERY (shows both phones in dashboard)
# ═══════════════════════════════════════════════════════════════
echo -e "  Press ${BLD}ENTER${RST} for final bonus attack (subnet scan)..."
read -r

echo ""
echo -e "${RED}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${RED}${BLD}║  BONUS: NETWORK RECON / SUBNET SCAN         ║${RST}"
echo -e "${RED}${BLD}║  Shows BOTH phones in Hotspot Devices page  ║${RST}"
echo -e "${RED}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo ""

# Derive subnet from gateway
SUBNET=$(echo "$GATEWAY" | cut -d. -f1-3)
echo -e "${CYN}[*] Scanning entire subnet: ${SUBNET}.0/24${RST}"
echo -e "${CYN}[*] Watch Hotspot Devices page — both phones will appear!${RST}"
echo ""

nmap -sn -T4 "${SUBNET}.0/24" 2>/dev/null | grep -E "scan report|MAC"

echo ""

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════════╗${RST}"
echo -e "${GRN}${BLD}║           DEMO COMPLETE! ✓                      ║${RST}"
echo -e "${GRN}${BLD}╠══════════════════════════════════════════════════╣${RST}"
echo -e "${GRN}${BLD}║  Attacks launched from:  ${BLD}$MY_IP${GRN}    ║${RST}"
echo -e "${GRN}${BLD}║                                                 ║${RST}"
echo -e "${GRN}${BLD}║  Expected alerts on SecureFlow dashboard:       ║${RST}"
echo -e "${GRN}${BLD}║   🔴 PortScan   — MITRE T1046 — HIGH           ║${RST}"
echo -e "${GRN}${BLD}║   🔴 DoS        — MITRE T1498 — HIGH           ║${RST}"
echo -e "${GRN}${BLD}║   🟡 Anomaly    — MITRE T1499 — MEDIUM         ║${RST}"
echo -e "${GRN}${BLD}║                                                 ║${RST}"
echo -e "${GRN}${BLD}║  Your IP should now be AUTO-BLOCKED 🚫          ║${RST}"
echo -e "${GRN}${BLD}╚══════════════════════════════════════════════════╝${RST}"
echo ""
