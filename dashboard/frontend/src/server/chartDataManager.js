const HISTORY_LIMIT = 5000
const MAX_Y_VALUE = 100

const createNetworkTrafficTemplate = () => ({
    labels: [],
    datasets: [
        {
            label: 'Network Packets',
            data: [],
            borderColor: 'rgb(54, 162, 235)',
            backgroundColor: 'rgba(54, 162, 235, 0.08)',
            borderWidth: 2,
            fill: false,
            tension: 0,
            pointRadius: 0,
            pointHoverRadius: 4
        },
        {
            label: 'Security Alerts',
            data: [],
            borderColor: 'rgb(255, 99, 132)',
            backgroundColor: 'rgba(255, 99, 132, 0.08)',
            borderWidth: 2,
            fill: false,
            tension: 0,
            pointRadius: 0,
            pointHoverRadius: 4
        }
    ]
})

const normalizeProtocol = (protocolValue) => {
    const protocol = String(protocolValue ?? '').toUpperCase()
    if (protocol === '6' || protocol === 'TCP') return 'TCP'
    if (protocol === '17' || protocol === 'UDP') return 'UDP'
    if (protocol === '1' || protocol === 'ICMP') return 'ICMP'
    return 'Other'
}

const clampY = (value) => Math.max(0, Math.min(MAX_Y_VALUE, Number(value || 0)))

class ChartDataManager {
    constructor() {
        if (ChartDataManager.instance) {
            return ChartDataManager.instance
        }

        this.networkTrafficData = createNetworkTrafficTemplate()
        this.protocolData = {
            TCP: 0,
            UDP: 0,
            ICMP: 0,
            Other: 0
        }
        this.attackData = {
            normal: 0,
            attacks: 0,
            total: 0
        }
        this.totalCount = 0

        ChartDataManager.instance = this
        return this
    }

    updateNetworkTraffic(data, isAlert = false) {
        const timeLabel = new Date().toLocaleTimeString()
        const value = isAlert ? 1 : (Array.isArray(data) ? data.length : 1)
        const boundedValue = clampY(value)

        this.networkTrafficData.labels.push(timeLabel)
        this.networkTrafficData.datasets[0].data.push(isAlert ? 0 : boundedValue)
        this.networkTrafficData.datasets[1].data.push(isAlert ? boundedValue : 0)

        if (this.networkTrafficData.labels.length > HISTORY_LIMIT) {
            this.networkTrafficData.labels.shift()
            this.networkTrafficData.datasets[0].data.shift()
            this.networkTrafficData.datasets[1].data.shift()
        }
    }

    updateProtocolData(data) {
        const packets = Array.isArray(data) ? data : [data]

        packets.forEach((packet) => {
            const protocol = normalizeProtocol(packet?.proto ?? packet?.protocol)
            this.protocolData[protocol] += 1
        })

        this.totalCount += packets.length
    }

    updateProtocolFromAlert(alertData) {
        const protocol = normalizeProtocol(alertData?.protocol)
        this.protocolData[protocol] += 1
        this.totalCount += 1
    }

    updateAttackData(isAttack = false) {
        if (isAttack) {
            this.attackData.attacks += 1
        } else {
            this.attackData.normal += 1
        }
        this.attackData.total += 1
    }

    getAttackData() {
        return { ...this.attackData }
    }

    getNetworkTrafficData() {
        return JSON.parse(JSON.stringify(this.networkTrafficData))
    }

    getProtocolData() {
        return {
            ...this.protocolData,
            totalCount: this.totalCount
        }
    }

    reset() {
        this.networkTrafficData = createNetworkTrafficTemplate()
        this.protocolData = { TCP: 0, UDP: 0, ICMP: 0, Other: 0 }
        this.attackData = { normal: 0, attacks: 0, total: 0 }
        this.totalCount = 0
    }
}

const chartDataManager = new ChartDataManager()
export default chartDataManager
