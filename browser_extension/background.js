chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scan') {
        fetch('http://127.0.0.1:8000/api/analyze-trigger', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request.payload)
        })
        .then(response => response.json())
        .then(data => {
            console.log('Backend response:', data);
            chrome.tabs.sendMessage(sender.tab.id, {
                action: 'show_verdict',
                data: data
            });
        })
        .catch(error => {
            console.error('Error contacting backend:', error);
        });
        return true;
    }
});
