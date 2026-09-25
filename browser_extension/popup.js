// popup.js
fetch('http://127.0.0.1:8000/health')
    .then(r => r.json())
    .then(d => {
        document.getElementById('backend-status').innerText = '🟢 Backend Connected (' + d.version + ')';
    })
    .catch(e => {
        let el = document.getElementById('backend-status');
        el.innerText = '🔴 Backend Disconnected';
        el.style.backgroundColor = '#ffebee';
        el.style.color = '#c62828';
        el.style.borderColor = '#ef9a9a';
    });
