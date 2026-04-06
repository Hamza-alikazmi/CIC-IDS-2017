function log(msg) {
    let logs = document.getElementById("logs");
    let div = document.createElement("div");
    div.innerText = msg;
    logs.appendChild(div);
    logs.scrollTop = logs.scrollHeight;
}

function updateUI(data, result) {
    document.getElementById("fd").innerText = data["Flow Duration"];
    document.getElementById("fb").innerText = data["Flow Bytes/s"];
    document.getElementById("fp").innerText = data["Flow Packets/s"];

    let box = document.getElementById("statusBox");
    let text = document.getElementById("statusText");

    if (result === "ATTACK") {
        box.className = "attack";
        text.innerText = "ATTACK DETECTED";
        log("Attack detected");
    } else {
        box.className = "safe";
        text.innerText = "Normal Traffic";
        log("Normal traffic");
    }
}

function fetchData() {
    fetch("/live-data")
    .then(res => res.json())
    .then(data => {
        fetch("/predict", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(data)
        })
        .then(res => res.json())
        .then(res => {
            updateUI(data, res.prediction);
        });
    });
}

setInterval(fetchData, 2000);
