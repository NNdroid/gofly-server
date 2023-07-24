const ctx = document.getElementById('traffic_chart');
var trafficData = {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'download',
                data: [],
                borderWidth: 1
            },
            {
                label: 'upload',
                data: [],
                borderWidth: 1
            }
        ]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true,
                ticks: {
                    callback: function(value) {
                        return getFriendlyByteString(value)
                    }
                }
            }
        }
    }
};

const trafficChart = new Chart(ctx, trafficData);

updateYourInfo()

var currentTrafficRX = 0
var currentTrafficTX = 0
setInterval(updateTrafficData, 1000, trafficChart, trafficData)
setInterval(updateOnlineClientCount, 1000)
setInterval(tableGenerateList, 1000)


function updateYourInfo() {
    const yourClientIPElement = document.getElementById('your_client_ip');
    // const yourAreFromElement = document.getElementById('your_are_from');
    fetch('/api/v1/myinfo')
        .then(r => r.json())
        .then(r => {
            yourClientIPElement.innerText = r.ip
            // yourAreFromElement.innerText = r.connection
        })
        .catch(err => {
            new $.zui.Messager(err,{}).show();
        })
}

function updateOnlineClientCount() {
    const clientCountElement = document.getElementById('online_client_count');
    fetch('/api/v1/online/count')
        .then(r => r.text())
        .then(n => {
            clientCountElement.innerHTML = `<span>${n}</span>`
        })
        .catch(err => {
            new $.zui.Messager(err,{}).show();
        })
}

function updateTrafficData(chart, data) {
    const trafficTotalRxElement = document.getElementById("traffic_total_rx")
    const trafficTotalTxElement = document.getElementById("traffic_total_tx")
    fetch('/api/v1/traffic')
        .then(r => r.json())
        .then(r => {
            trafficTotalRxElement.innerText = getFriendlyByteStringB(r.rx)
            trafficTotalTxElement.innerText = getFriendlyByteStringB(r.tx)
            let diffRX = currentTrafficRX !== 0 ? r.rx - currentTrafficRX : 0
            let diffTX = currentTrafficTX !== 0 ? r.tx - currentTrafficTX : 0
            data.data.labels.push(getNowTime())
            data.data.datasets[0].data.push(diffTX)
            data.data.datasets[1].data.push(diffRX)
            chart.update()
            currentTrafficRX = r.rx
            currentTrafficTX = r.tx
        })
        .catch(err => {
            new $.zui.Messager(err,{}).show();
        })
}

function getNowTime() {
    const date = new Date();
    return `${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}`
}

function convertUnitToMbs(n) {
    return (n * 8 / 1024 / 1024).toFixed(3)
}

function getFriendlyByteStringB(n) {
    if (n < 1024) {
        return `${n}B`
    } else if (n < 1024 * 1024) {
        return (n / 1024).toFixed(3)+"KB"
    } else if (n < 1024 * 1024 * 1024) {
        return (n / 1024 / 1024).toFixed(3)+"MB"
    } else if (n < 1024 * 1024 * 1024 * 1024) {
        return (n / 1024 / 1024 / 1024).toFixed(3)+"GB"
    }
}

function getFriendlyByteString(n) {
    if (n < 1024) {
        return `${n*8}bps`
    } else if (n < 1024 * 1024) {
        return (n / 1024 * 8).toFixed(3)+"Kbps"
    } else if (n < 1024 * 1024 * 1024) {
        return (n / 1024 / 1024 * 8).toFixed(3)+"Mbps"
    } else if (n < 1024 * 1024 * 1024 * 1024) {
        return (n / 1024 / 1024 / 1024 * 8).toFixed(3)+"Gbps"
    }
}

function tableGenerateList() {
    const clientListTableElement = document.getElementById('table_client_list');
    fetch('/api/v1/clients')
        .then(r => r.json())
        .then(r => {
            clientListTableElement.querySelectorAll('*').forEach( n => n.remove() );
            return r.data
        })
        .then(r => {
            r.forEach(it => {
                let tr = document.createElement("tr");
                let addressTd = document.createElement("td");
                let onlineTimeTd = document.createElement("td");
                let offlineTimeTd = document.createElement("td");
                let uploadTd = document.createElement("td");
                let downloadTd = document.createElement("td");
                const addressTdContent = document.createTextNode(`${it.addr.IP}:${it.addr.Port}`);
                const onlineTimeTdContent = document.createTextNode(it.online_time);
                const offlineTimeTdContent = document.createTextNode(it.offline_time);
                const uploadTdContent = document.createTextNode(getFriendlyByteStringB(it.tx));
                const downloadTdContent = document.createTextNode(getFriendlyByteStringB(it.rx));
                addressTd.appendChild(addressTdContent)
                onlineTimeTd.appendChild(onlineTimeTdContent)
                offlineTimeTd.appendChild(offlineTimeTdContent)
                uploadTd.appendChild(uploadTdContent)
                downloadTd.appendChild(downloadTdContent)
                tr.appendChild(addressTd)
                tr.appendChild(onlineTimeTd)
                tr.appendChild(offlineTimeTd)
                tr.appendChild(uploadTd)
                tr.appendChild(downloadTd)
                if(it.online) {
                    tr.classList.add('success')
                } else {
                    tr.classList.add('danger')
                }
                clientListTableElement.appendChild(tr)
            })
        })
        .catch(err => {
            new $.zui.Messager(err,{}).show();
        })
}