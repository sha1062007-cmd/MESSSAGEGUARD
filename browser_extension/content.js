// Gmail Content Script
function scanEmail() {
    // Basic extraction
    let subjectElement = document.querySelector('h2[data-legacy-message-id]');
    let senderElement = document.querySelector('.gD'); // Name / Email
    let bodyElement = document.querySelector('.a3s');

    if (!subjectElement || !senderElement || !bodyElement) return;

    let subject = subjectElement.innerText;
    let sender = senderElement.getAttribute('email') || senderElement.innerText;
    let body = bodyElement.innerText;
    
    // Extract URLs
    let links = Array.from(bodyElement.querySelectorAll('a')).map(a => a.href);
    
    // Call backend
    chrome.runtime.sendMessage({
        action: 'scan',
        payload: {
            sender: sender,
            subject: subject,
            snippet: body.substring(0, 100),
            body: body,
            urls: links
        }
    });
}

// Observe Gmail DOM
const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        if (mutation.addedNodes.length) {
            let emailBody = document.querySelector('.a3s');
            if (emailBody && !emailBody.dataset.scanned) {
                emailBody.dataset.scanned = 'true';
                scanEmail();
            }
        }
    });
});

observer.observe(document.body, { childList: true, subtree: true });

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'show_verdict') {
        let verdictCard = document.createElement('div');
        verdictCard.style.position = 'fixed';
        verdictCard.style.top = '10px';
        verdictCard.style.right = '10px';
        verdictCard.style.zIndex = '9999';
        verdictCard.style.padding = '15px';
        verdictCard.style.backgroundColor = request.data.risk_color;
        verdictCard.style.color = 'white';
        verdictCard.style.borderRadius = '5px';
        verdictCard.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
        verdictCard.innerHTML = `
            <h3 style="margin-top:0">MessageGuard Alert</h3>
            <p><strong>Verdict:</strong> ${request.data.verdict}</p>
            <p><strong>Risk Score:</strong> ${request.data.risk_score}</p>
            <a href="${request.data.report_url}" target="_blank" style="color:white; text-decoration:underline;">View Forensic Report</a>
        `;
        document.body.appendChild(verdictCard);
        
        setTimeout(() => {
            verdictCard.remove();
        }, 8000);
    }
});
