# Stasher Web App

Static website for the Stasher secure secret sharing platform.  Deployed at [app.stasher.dev](https://app.stasher.dev).

**Bookmarklet (Recommended)**
1. Visit **[stasher.dev](https://stasher.dev)** and drag the bookmarklet to your bookmark bar
2. Or create a bookmark manually with this URL:
   ```javascript
   javascript:(function(){var left=Math.floor(screen.width/2-400);var top=Math.floor(screen.height/2-225);var features='width=800,height=450,resizable=yes,scrollbars=no,status=no,location=no,toolbar=no,menubar=no,left='+left+',top='+top+',noopener,noreferrer';var w=window.open('https://app.stasher.dev/','stasher',features);if(w){w.focus();}else{alert("Popup blocked – please allow popups for this site");}})();
   ```
3. Click the bookmark on any page to open Stasher in a secure window
