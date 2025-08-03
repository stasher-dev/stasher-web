// Stasher Bookmarklet - Opens crypto tool in popup window
// To use: Copy the javascript: URL below and save as a bookmark

// Minified bookmarklet (copy this as bookmark URL):
javascript:(function(){var w=window.open('https://app.stasher.dev/','stasher','width=800,height=450,resizable=yes,scrollbars=no,status=no,location=no,toolbar=no,menubar=no');if(w){w.focus();}else{alert('Popup blocked - please allow popups for this site');}})();

// Readable version for development:
/*
javascript:(function(){
    var popup = window.open(
        'https://app.stasher.dev/',
        'stasher',
        'width=800,height=450,resizable=yes,scrollbars=no,status=no,location=no,toolbar=no,menubar=no'
    );
    if (popup) {
        popup.focus();
    } else {
        alert('Popup blocked - please allow popups for this site');
    }
})();
*/