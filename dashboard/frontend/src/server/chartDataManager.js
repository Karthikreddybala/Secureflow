// Chart Data Manager - maintains chart data across component navigation
class ChartDataManager {
    constructor() {
        if (ChartDataManager.instance) {
            return ChartDataManager.instance;
        }
        
        this.networkTrafficData = {
            labels: [],
            datasets: [
                {
                    label: 'Network Packets',
                    data: [],
                    borderColor: 'rgb(54, 162, 235)',
                    backgroundColor: 'rgba(54, 162, 235, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 6
                },
                {
                    label: 'Security Alerts',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 6
                }
            ]
        };

        this.protocolData = {
            TCP: 0,
            UDP: 0,
            ICMP: 0,
            Other: 0
        };

        this.attackData = {
            normal: 0,
            attacks: 0,
            total: 0
        };

        this.totalCount = 0;

        ChartDataManager.instance = this;
        return this;
    }

    // Update network traffic chart data
    updateNetworkTraffic(data, isAlert = false) {
        const now = new Date();
        const timeLabel = now.toLocaleTimeString();
        const value = isAlert ? 1 : (Array.isArray(data) ? data.length : 1);

        // Update labels and data
        this.networkTrafficData.labels.push(timeLabel);
        this.networkTrafficData.datasets[0].data.push(isAlert ? 0 : value);
        this.networkTrafficData.datasets[1].data.push(isAlert ? value : 0);

        // Keep only last 20 data points for performance
        if (this.networkTrafficData.labels.length > 20) {
            this.networkTrafficData.labels.shift();
            this.networkTrafficData.datasets[0].data.shift();
            this.networkTrafficData.datasets[1].data.shift();
        }
    }

    // Update protocol pie chart data
    updateProtocolData(data) {
        // Handle batch data
        const packets = Array.isArray(data) ? data : [data];
        
        packets.forEach(packet => {
            const proto = packet.proto || packet.protocol || packet.proto || "Unknown";
            if (proto === 6 || proto === "6" || proto === "TCP") {
                this.protocolData.TCP++;
            } else if (proto === 17 || proto === "17" || proto === "UDP") {
                this.protocolData.UDP++;
            } else if (proto === 1 || proto === "1" || proto === "ICMP") {
                this.protocolData.ICMP++;
            } else {
                this.protocolData.Other++;
            }
        });

        this.totalCount += packets.length;
    }

    // Update protocol data from alerts
    updateProtocolFromAlert(alertData) {
        if (alertData && alertData.protocol) {
            const proto = alertData.protocol;
            if (proto === 6 || proto === "6" || proto === "TCP") {
                this.protocolData.TCP++;
            } else if (proto === 17 || proto === "17" || proto === "UDP") {
                this.protocolData.UDP++;
            } else if (proto === 1 || proto === "1" || proto === "ICMP") {
                this.protocolData.ICMP++;
            } else {
                this.protocolData.Other++;
            }
            this.totalCount++;
        }
    }

    // Update attack distribution data
    updateAttackData(isAttack = false) {
        if (isAttack) {
            this.attackData.attacks++;
        } else {
            this.attackData.normal++;
        }
        this.attackData.total++;
    }

    // Get current attack data
    getAttackData() {
        return {
            ...this.attackData
        };
    }

    // Get current network traffic data
    getNetworkTrafficData() {
        return JSON.parse(JSON.stringify(this.networkTrafficData));
    }

    // Get current protocol data
    getProtocolData() {
        return {
            ...this.protocolData,
            totalCount: this.totalCount
        };
    }

    // Reset data (optional)
    reset() {
        this.networkTrafficData.labels = [];
        this.networkTrafficData.datasets[0].data = [];
        this.networkTrafficData.datasets[1].data = [];
        this.protocolData.TCP = 0;
        this.protocolData.UDP = 0;
        this.protocolData.ICMP = 0;
        this.protocolData.Other = 0;
        this.totalCount = 0;
    }
}

// Create singleton instance
const chartDataManager = new ChartDataManager();

export default chartDataManager;