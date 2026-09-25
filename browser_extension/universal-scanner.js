// Universal Scanner for other websites
console.log('MessageGuard Universal Scanner loaded.');

function scanPage() {
    let title = document.title;
    let bodyText = document.body.innerText;
    let urls = Array.from(document.querySelectorAll('a')).map(a => a.href);

    // Call backend
    chrome.runtime.sendMessage({
        action: 'scan',
        payload: {
            sender: "WebPage: " + window.location.hostname,
            subject: title,
            snippet: bodyText.substring(0, 100),
            body: bodyText.substring(0, 5000), // Trim for payload size
            urls: urls
        }
    });
}

// Initial scan
setTimeout(scanPage, 1000);
