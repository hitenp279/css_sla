const API = "http://localhost:3000/api";

async function issueCert() {
  const user = document.getElementById("user").value;

  const res = await fetch(`${API}/issue`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ user })
  });

  const data = await res.json();

  document.getElementById("result").innerText =
    "Cert ID: " + data.certId;

  document.getElementById("privateKey").value =
    data.privateKey;
}

async function verifyCert() {
  const certId = document.getElementById("certId").value;

  const res = await fetch(`${API}/verify`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ certId })
  });

  const data = await res.json();
  document.getElementById("result").innerText = data.status;
}

async function revokeCert() {
  const certId = document.getElementById("certId").value;

  await fetch(`${API}/revoke`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ certId })
  });

  document.getElementById("result").innerText = "Revoked";
}

async function loadAll() {
  const res = await fetch(`${API}/all`);
  const data = await res.json();
  document.getElementById("result").innerText =
    JSON.stringify(data, null, 2);
}

async function proveOwnership() {
  const certId = document.getElementById("certId").value;

  const c = await fetch(`${API}/challenge`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ certId })
  });

  const { challenge } = await c.json();

  const signedChallenge = challenge;

  const res = await fetch(`${API}/validate-challenge`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ certId, signedChallenge })
  });

  const data = await res.json();
  document.getElementById("result").innerText = data.result;
}