(function () {
  // --- Initialize Google Consent v2 FIRST (before any Google scripts load) ---
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  
  // Set default consent to 'denied' for all Google services
  gtag('consent', 'default', {
    'analytics_storage': 'denied',
    'ad_storage': 'denied',
    'ad_personalization': 'denied',
    'ad_user_data': 'denied',
    'personalization_storage': 'denied',
    'functionality_storage': 'granted',
    'security_storage': 'granted'
  });

  // --- Hardcoded Encryption Keys (matching server) ---
  const ENCRYPTION_KEY = "t95w6oAeL1hr0rrtCGKok/3GFNwxzfLxiWTETfZurpI="; // Base64 encoded 256-bit key
  const ENCRYPTION_IV = "yVSYDuWajEid8kDz"; // Base64 encoded 128-bit IV

  // --- Helper functions ---
  function setConsentCookie(name, value, days) {
    let expires = "";
    if (days) {
      const date = new Date();
      date.setTime(date.getTime() + (days*24*60*60*1000));
      expires = "; expires=" + date.toUTCString();
    }
    let cookieString = name + "=" + value + expires + "; path=/; SameSite=Lax";
    if (location.protocol === 'https:') {
      cookieString += "; Secure";
    }
    document.cookie = cookieString;
  }
  function getConsentCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }
  function blockScriptsByCategory() {
    // Block scripts only in head section
    var scripts = document.head.querySelectorAll('script[data-category]');
    scripts.forEach(function(script) {
      var category = script.getAttribute('data-category');
      if (category && script.type !== 'text/plain') {
        // Handle comma-separated categories
        var categories = category.split(',').map(function(cat) { return cat.trim(); });
        
        // Check if ANY category is necessary or essential (these should never be blocked)
        var hasEssentialCategory = categories.some(function(cat) { 
          var lowercaseCat = cat.toLowerCase();
          return lowercaseCat === 'necessary' || lowercaseCat === 'essential'; 
        });
        
        // Only block if NO categories are essential/necessary
        if (!hasEssentialCategory) {
          // Block ALL scripts with data-category by changing type (including Google scripts)
          script.type = 'text/plain';
          script.setAttribute('data-blocked-by-consent', 'true');
        }
      }
    });
    
    // Block all scripts without data-category in head only
    blockNonGoogleScripts();
  }
  function enableAllScriptsWithDataCategory() {
    // Enable ALL scripts with data-category attribute (regardless of category value) only in head section
    var scripts = document.head.querySelectorAll('script[type="text/plain"][data-category]');
    scripts.forEach(function(oldScript) {
      var newScript = document.createElement('script');
      for (var i = 0; i < oldScript.attributes.length; i++) {
        var attr = oldScript.attributes[i];
        if (attr.name === 'type') {
          newScript.type = 'text/javascript';
        } else if (attr.name !== 'data-blocked-by-consent' && attr.name !== 'data-blocked-by-ccpa') {
          newScript.setAttribute(attr.name, attr.value);
        }
      }
      if (oldScript.innerHTML) {
        newScript.innerHTML = oldScript.innerHTML;
      }
      oldScript.parentNode.replaceChild(newScript, oldScript);
    });
  }
  function enableScriptsByCategories(allowedCategories) {
    // Enable scripts based on categories (including Google scripts) only in head section
    var scripts = document.head.querySelectorAll('script[type="text/plain"][data-category]');
    scripts.forEach(function(oldScript) {
      var category = oldScript.getAttribute('data-category');
      if (category) {
        var categories = category.split(',').map(function(cat) { return cat.trim(); });
        var shouldEnable = categories.some(function(cat) { 
          return allowedCategories.includes(cat); 
        });
        if (shouldEnable) {
          var newScript = document.createElement('script');
          for (var i = 0; i < oldScript.attributes.length; i++) {
            var attr = oldScript.attributes[i];
            if (attr.name === 'type') {
              newScript.type = 'text/javascript';
            } else if (attr.name !== 'data-blocked-by-consent' && attr.name !== 'data-blocked-by-ccpa') {
              newScript.setAttribute(attr.name, attr.value);
            }
          }
          if (oldScript.innerHTML) {
            newScript.innerHTML = oldScript.innerHTML;
          }
          oldScript.parentNode.replaceChild(newScript, oldScript);
        }
      }
    });
  }
  function updateGtagConsent(preferences) {
    if (typeof gtag === "function") {
      gtag('consent', 'update', {
        'analytics_storage': preferences.Analytics ? 'granted' : 'denied',
        'functionality_storage': 'granted',
        'ad_storage': preferences.Marketing ? 'granted' : 'denied',
        'ad_personalization': preferences.Marketing ? 'granted' : 'denied',
        'ad_user_data': preferences.Marketing ? 'granted' : 'denied',
        'personalization_storage': preferences.Personalization ? 'granted' : 'denied',
        'security_storage': 'granted'
      });
    }
    
    // Push consent update event to dataLayer
    if (typeof window.dataLayer !== 'undefined') {
      window.dataLayer.push({
        'event': 'consent_update',
        'consent_analytics': preferences.Analytics,
        'consent_marketing': preferences.Marketing,
        'consent_personalization': preferences.Personalization
      });
    }
  }
  function setConsentState(preferences, cookieDays) {
    ['Analytics', 'Marketing', 'Personalization'].forEach(function(category) {
      setConsentCookie(
        'cb-consent-' + category.toLowerCase() + '_storage',
        preferences[category] ? 'true' : 'false',
        cookieDays || 365
      );
    });
    
    // Save CCPA "do-not-share" preference if it exists
    if (preferences.hasOwnProperty('donotshare')) {
      setConsentCookie(
        'cb-consent-donotshare',
        preferences.donotshare ? 'true' : 'false',
        cookieDays || 365
      );
    }
    
    updateGtagConsent(preferences);
    const expiresAt = Date.now() + (cookieDays * 24 * 60 * 60 * 1000);
    localStorage.setItem('consentExpiresAt', expiresAt.toString());
    localStorage.setItem('consentExpirationDays', cookieDays.toString());
  }
  function getConsentPreferences() {
    return {
      Analytics: getConsentCookie('cb-consent-analytics_storage') === 'true',
      Marketing: getConsentCookie('cb-consent-marketing_storage') === 'true',
      Personalization: getConsentCookie('cb-consent-personalization_storage') === 'true',
      donotshare: getConsentCookie('cb-consent-donotshare') === 'true'
    };
  }
  function showBanner(banner) {
    if (banner) {
      banner.style.setProperty("display", "block", "important");
      banner.style.setProperty("visibility", "visible", "important");
      banner.style.setProperty("opacity", "1", "important");
      banner.classList.add("show-banner");
      banner.classList.remove("hidden");
    }
  }
  function hideBanner(banner) {
    if (banner) {
      banner.style.setProperty("display", "none", "important");
      banner.style.setProperty("visibility", "hidden", "important");
      banner.style.setProperty("opacity", "0", "important");
      banner.classList.remove("show-banner");
      banner.classList.add("hidden");
    }
  }
async  function hideAllBanners(){
    hideBanner(document.getElementById("consent-banner"));
    hideBanner(document.getElementById("initial-consent-banner"));
    hideBanner(document.getElementById("main-banner"));
    hideBanner(document.getElementById("main-consent-banner"));
    hideBanner(document.getElementById("simple-consent-banner"));
    // Show or hide the toggle-consent-btn based on consent state
    const toggleConsentBtn = document.getElementById('toggle-consent-btn');
    if (toggleConsentBtn) {
      const consentGiven = localStorage.getItem("consent-given");
      if (consentGiven === "true") {
        toggleConsentBtn.style.display = "block";
      } else {
        toggleConsentBtn.style.display = "none";
      }
    }
  }
  function showAllBanners(){
    showBanner(document.getElementById("consent-banner"));
    showBanner(document.getElementById("initial-consent-banner"));
    showBanner(document.getElementById("main-banner"));
    showBanner(document.getElementById("main-consent-banner"));
    showBanner(document.getElementById("simple-consent-banner"));
  }

  // --- Encryption Helper Functions ---
  function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function uint8ArrayToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }

  async function importHardcodedKey() {
    const keyBytes = base64ToUint8Array(ENCRYPTION_KEY);
    return crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptWithHardcodedKey(data) {
    try {
      const key = await importHardcodedKey();
      const iv = base64ToUint8Array(ENCRYPTION_IV);
      const encoder = new TextEncoder();
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(data)
      );
      return uint8ArrayToBase64(new Uint8Array(encryptedBuffer));
    } catch (error) {
      throw error;
    }
  }

  // --- Advanced: Visitor session token generation ---
  function isTokenExpired(token) {
    if (!token) return true;
    const [payloadBase64] = token.split('.');
    if (!payloadBase64) return true;
    try {
      const payload = JSON.parse(atob(payloadBase64));
      if (!payload.exp) return true;
      return payload.exp < Math.floor(Date.now() / 1000);
    } catch {
      return true;
    }
  }
  async function getOrCreateVisitorId() {
    let visitorId = localStorage.getItem('visitorId');
    if (!visitorId) {
      visitorId = crypto.randomUUID();
      localStorage.setItem('visitorId', visitorId);
    }
    return visitorId;
  }
  async function cleanHostname(hostname) {
    let cleaned = hostname.replace(/^www\./, '');
    cleaned = cleaned.split('.')[0];
    return cleaned;
  }
  
  // Add session cleanup function
  function clearVisitorSession() {
    localStorage.removeItem('visitorId');
    localStorage.removeItem('visitorSessionToken');
    localStorage.removeItem('consent-given');
    localStorage.removeItem('consentExpiresAt');
    localStorage.removeItem('consentExpirationDays');
  }
  
  // Add flag to prevent concurrent token requests
  let tokenRequestInProgress = false;
  
  async function getVisitorSessionToken() {
    try {
      // Prevent concurrent requests
      if (tokenRequestInProgress) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const existingToken = localStorage.getItem('visitorSessionToken');
        if (existingToken && !isTokenExpired(existingToken)) {
          return existingToken;
        }
      }
      
      const existingToken = localStorage.getItem('visitorSessionToken');
      if (existingToken && !isTokenExpired(existingToken)) {
        return existingToken;
      }
      
      // Set flag to prevent concurrent requests
      tokenRequestInProgress = true;
    
      const visitorId = await getOrCreateVisitorId();
      const siteName = await cleanHostname(window.location.hostname);
      const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          visitorId: visitorId,
          // userAgent: navigator.userAgent, // Removed to fix fingerprinting warnings
          siteName: siteName
        })
      });
      
      if (!response.ok) {
        // Handle 500 errors by clearing stale data and retrying
        if (response.status === 500) {
          clearVisitorSession();
          
          // Generate new visitor ID and retry once
          const newVisitorId = await getOrCreateVisitorId();
          const retryResponse = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              visitorId: newVisitorId,
              // userAgent: navigator.userAgent, // Removed to fix fingerprinting warnings
              siteName: siteName
            })
          });
          
          if (!retryResponse.ok) {
            throw new Error(`Retry failed after clearing session: ${retryResponse.status}`);
          }
          
          const retryData = await retryResponse.json();
          // Store token immediately
          localStorage.setItem('visitorSessionToken', retryData.token);
          return retryData.token;
        }
        
        throw new Error(`Failed to get visitor session token: ${response.status}`);
      }
      
      const data = await response.json();
      // Store token immediately to prevent timing issues
      localStorage.setItem('visitorSessionToken', data.token);
      return data.token;
    } catch (error) {
      return null;
    } finally {
      // Always reset the flag regardless of success or failure
      tokenRequestInProgress = false;
    }
  }

  // --- Advanced: Fetch cookie expiration days from server ---
  async function fetchCookieExpirationDays() {
    const sessionToken = localStorage.getItem("visitorSessionToken");
    if (!sessionToken) return 180;
    try {
      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/app-data?siteName=${encodeURIComponent(siteName)}`;
      const response = await fetch(apiUrl, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${sessionToken}`,
          "Accept": "application/json"
        }
      });
      if (!response.ok) return 180;
      const data = await response.json();
      if (data && data.cookieExpiration !== null && data.cookieExpiration !== undefined) {
        return parseInt(data.cookieExpiration, 10);
      }
      return 180;
    } catch {
      return 180;
    }
  }

  // --- Manual override for testing purposes ---
  function getTestLocationOverride() {
    // Check if there's a manual override in localStorage for testing
    const override = localStorage.getItem('test_location_override');
    if (override) {
      try {
        return JSON.parse(override);
      } catch {
        return null;
      }
    }
    return null;
  }

  // --- Advanced: Detect location and banner type ---
  let country = null;
  async function detectLocationAndGetBannerType() {
    try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      
      if (!sessionToken) {
        return null;
      }
      
      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/v2/cmp/detect-location?siteName=${encodeURIComponent(siteName)}`;
      
      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
      });
      
      if (!response.ok) {
        return null;
      }
      
      const data = await response.json();
      
      if (!data.bannerType) {
        return null;
      }
      
      country = data.country;
      const locationData = {
        country: data.country || 'UNKNOWN',
        continent: data.continent || 'UNKNOWN',
        state: data.state || null,
        bannerType:data.bannerType
        };
      currentLocation = locationData;
      country = locationData.country;
      return data;
    } catch (error) {
      return null;
    }
  }

  // --- Advanced: Encrypt and save consent preferences to server ---
  async function saveConsentStateToServer(preferences, cookieDays, includeUserAgent) {
    try {
      const clientId = window.location.hostname;
      const visitorId = localStorage.getItem("visitorId");
      const policyVersion = "1.2";
      const timestamp = new Date().toISOString();
      const sessionToken = localStorage.getItem("visitorSessionToken");
      
      if (!sessionToken) {
        return;
      }

      // Prepare the complete payload first
      const fullPayload = {
        clientId,
        visitorId,
        preferences, // Raw preferences object, not encrypted individually
        policyVersion,
        timestamp,
        country: country || "IN",
        bannerType: preferences.bannerType || "GDPR",
        expiresAtTimestamp: Date.now() + ((cookieDays || 365) * 24 * 60 * 60 * 1000),
        expirationDurationDays: cookieDays || 365,
        metadata: {
          ...(includeUserAgent && { userAgent: navigator.userAgent }), // Only include userAgent if allowed
          language: navigator.language,
          platform: navigator.userAgentData?.platform || "unknown",
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        }
      };

      // Encrypt the entire payload as one encrypted string
      const encryptedPayload = await encryptWithHardcodedKey(JSON.stringify(fullPayload));

      // Send only the encrypted payload
      const requestBody = {
        encryptedData: encryptedPayload
      };

      const response = await fetch("https://cb-server.web-8fb.workers.dev/api/v2/cmp/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Server error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      
    } catch (error) {
      // Silent error handling
    }
  }

  // --- Advanced: Show saved preferences in preferences panel ---
  function updatePreferenceForm(preferences) {
    const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
    const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
    const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
    const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
    if (necessaryCheckbox) {
      necessaryCheckbox.checked = true;
      necessaryCheckbox.disabled = true;
    }
    if (marketingCheckbox) {
      marketingCheckbox.checked = Boolean(preferences.Marketing);
    }
    if (personalizationCheckbox) {
      personalizationCheckbox.checked = Boolean(preferences.Personalization);
    }
    if (analyticsCheckbox) {
      analyticsCheckbox.checked = Boolean(preferences.Analytics);
    }
  }

  // --- CCPA: Update CCPA preference form checkboxes ---
  function updateCCPAPreferenceForm(preferences) {
    // Update main "Do Not Share" checkbox based on saved preference
    const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
    if (doNotShareCheckbox) {
      // Use saved donotshare preference if available, otherwise check if any category is false
      if (preferences.hasOwnProperty('donotshare')) {
        doNotShareCheckbox.checked = preferences.donotshare;
      } else {
        // Fallback: If any category is false (blocked), then "Do Not Share" should be checked
        const shouldCheck = !preferences.Analytics || !preferences.Marketing || !preferences.Personalization;
        doNotShareCheckbox.checked = shouldCheck;
      }
    }
    
    // Update individual CCPA category checkboxes (if they exist)
    const ccpaToggleCheckboxes = document.querySelectorAll('.consentbit-ccpa-prefrence-toggle input[type="checkbox"]');
    ccpaToggleCheckboxes.forEach(checkbox => {
      const checkboxName = checkbox.name || checkbox.getAttribute('data-category') || '';
      // In CCPA, checked means "Do Not Share" (block/false)
      if (checkboxName.toLowerCase().includes('analytics')) {
        checkbox.checked = !Boolean(preferences.Analytics);
      } else if (checkboxName.toLowerCase().includes('marketing') || checkboxName.toLowerCase().includes('advertising')) {
        checkbox.checked = !Boolean(preferences.Marketing);
      } else if (checkboxName.toLowerCase().includes('personalization') || checkboxName.toLowerCase().includes('functional')) {
        checkbox.checked = !Boolean(preferences.Personalization);
      }
    });
  }

  // --- Publishing status and removal helpers ---
  async function checkPublishingStatus() {
    try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      if (!sessionToken) {
        return false;
      }
      const siteDomain = window.location.hostname;
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/site/subscription-status?siteDomain=${encodeURIComponent(siteDomain)}`;
      const response = await fetch(apiUrl, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${sessionToken}`,
          "Accept": "application/json"
        }
      });
      if (!response.ok) {
        return false;
      }
      const data = await response.json();
      return data.canPublishToCustomDomain === true;
    } catch (error) {
      return false;
    }
  }
  function removeConsentElements() {
    const selectors = [
      '.consentbit-gdpr-banner-div',
      '.consentbit-preference-div',
      '.consentbit-change-preference',
      '.consentbit-ccpa-banner-div',
      '.consentbit-ccpa_preference',
    ];
    selectors.forEach(selector => {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => el.remove());
    });
  }
  function isStagingHostname() {
    const hostname = window.location.hostname;
    return hostname.includes('.webflow.io') || hostname.includes('localhost') || hostname.includes('127.0.0.1');
  }

  // --- Load Consent Styles ---
  function loadConsentStyles() {
    try {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@d6b0288/consentbitstyle.css";
      link.type = "text/css";
      const link2 = document.createElement("link");
      link2.rel = "stylesheet";
      link2.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@8c69a0b/consentbit.css";
      document.head.appendChild(link2);
      link.onerror = function () {};
      link.onload = function () {};
      document.head.appendChild(link);
    } catch (error) {
      // Silent error handling
    }
  }
    // --- Monitor for dynamically added non-Google scripts ---
  function monitorDynamicScripts() {
    const observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        mutation.addedNodes.forEach(function(node) {
          if (node.nodeType === 1 && node.tagName === 'SCRIPT') {
            // Check if this is a non-Google analytics script
            if (node.src && (
              node.src.includes('facebook.net') ||
              node.src.includes('fbcdn.net') ||
              node.src.includes('hotjar.com') ||
              node.src.includes('mixpanel.com') ||
              node.src.includes('intercom.io') ||
              node.src.includes('klaviyo.com') ||
              node.src.includes('tiktok.com') ||
              node.src.includes('linkedin.com') ||
              node.src.includes('twitter.com') ||
              node.src.includes('adobe.com')
            )) {
              // Check current consent state
              const analyticsConsent = localStorage.getItem("cb-consent-analytics_storage");
              const marketingConsent = localStorage.getItem("cb-consent-marketing_storage");
              
              // Block if consent is denied (non-Google scripts need traditional blocking)
              if (analyticsConsent === "false" && marketingConsent === "false") {
                node.type = 'text/plain';
                node.setAttribute('data-blocked-by-consent', 'true');
              }
            }
          }
        });
      });
    });
    
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }
  
  // Start monitoring when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', monitorDynamicScripts);
  } else {
    monitorDynamicScripts();
  }


  // --- Helper Functions (must be declared before DOMContentLoaded) ---
  async function checkConsentExpiration() {
    const expiresAt = localStorage.getItem('consentExpiresAt');
    if (expiresAt && Date.now() > parseInt(expiresAt, 10)) {
      // Consent expired: clear consent state
      localStorage.removeItem('consent-given');
      localStorage.removeItem('consent-preferences');
      localStorage.removeItem('consentExpiresAt');
      localStorage.removeItem('consentExpirationDays');
      // Optionally, clear consent cookies as well
      ['analytics', 'marketing', 'personalization'].forEach(category => {
        setConsentCookie('cb-consent-' + category + '_storage', '', -1);
      });
    }
  }

  async function disableScrollOnSite(){
    const scrollControl = document.querySelector('[scroll-control="true"]');
    function toggleScrolling() {
      const banner = document.querySelector('[data-cookie-banner="true"]');
      if (!banner) return;
      const observer = new MutationObserver(() => {
        const isVisible = window.getComputedStyle(banner).display !== "none";
        document.body.style.overflow = isVisible ? "hidden" : "";
      });
      // Initial check on load
      const isVisible = window.getComputedStyle(banner).display !== "none";
      document.body.style.overflow = isVisible ? "hidden" : "";
      observer.observe(banner, { attributes: true, attributeFilter: ["style", "class"] });
    }
    if (scrollControl) {
      toggleScrolling();
    }
  }

 
  document.addEventListener('DOMContentLoaded', async function() {
    await hideAllBanners();
    await checkConsentExpiration();
    await disableScrollOnSite();

    let canPublish = false;
    let isStaging = false;
    let locationData = null;
    
    // Set up toggle consent button FIRST (outside conditional blocks)
    const toggleConsentBtn = document.getElementById('toggle-consent-btn');
    
    if (toggleConsentBtn) {
      toggleConsentBtn.onclick = function(e) {
        e.preventDefault();
        
        // Find banner elements
        const consentBanner = document.getElementById("consent-banner");
        const ccpaBanner = document.getElementById("initial-consent-banner");
        const mainBanner = document.getElementById("main-banner");
        
        // Force show appropriate banner
        if (locationData && locationData.bannerType === "CCPA" && ccpaBanner) {
          hideAllBanners();
          showBanner(ccpaBanner);
          
          // Force display with additional methods if needed
          ccpaBanner.style.display = "block";
          ccpaBanner.style.visibility = "visible";
          ccpaBanner.hidden = false;
          ccpaBanner.classList.remove("hidden");
          ccpaBanner.classList.add("show-banner");
          
          // Update CCPA preference form with saved preferences
          updateCCPAPreferenceForm(getConsentPreferences());
        } else if (consentBanner) {
          hideAllBanners();
          showBanner(consentBanner);
          
          // Force display with additional methods if needed
          consentBanner.style.display = "block";
          consentBanner.style.visibility = "visible";
          consentBanner.hidden = false;
          consentBanner.classList.remove("hidden");
          consentBanner.classList.add("show-banner");
        }
        
        // Update preferences if function exists
        if (typeof updatePreferenceForm === 'function') {
          updatePreferenceForm(getConsentPreferences());
        }
      };
    }
    
    try {
      const token = await getVisitorSessionToken();
      if (!token) {
        // Instead of immediate reload, try clearing session and retry once
        clearVisitorSession();
        const retryToken = await getVisitorSessionToken();
        if (!retryToken) {
          // Only reload if we absolutely can't get a token after retry
          setTimeout(() => location.reload(), 3000);
          return;
        }
        localStorage.setItem('visitorSessionToken', retryToken);
        await scanAndSendHeadScriptsIfChanged(retryToken);
      } else {
        // Store token immediately if not already stored
        if (!localStorage.getItem('visitorSessionToken')) {
          localStorage.setItem('visitorSessionToken', token);
        }
        await scanAndSendHeadScriptsIfChanged(token);
      }
      canPublish = await checkPublishingStatus();
      isStaging = isStagingHostname();
      
      if (!canPublish && !isStaging) {
        removeConsentElements();
        return;
      }
    } catch (error) {
      // Don't immediately reload on error, try to continue
      clearVisitorSession();
      // Only reload if critical functionality fails
      setTimeout(() => location.reload(), 5000);
      return;
    }

    // Always detect location on every load
    const testOverride = getTestLocationOverride();
    if (testOverride) {
      locationData = testOverride;
      country = testOverride.country;
    } else {
      locationData = await detectLocationAndGetBannerType();
    }

    const consentGiven = localStorage.getItem("consent-given");
    let cookieDays = await fetchCookieExpirationDays();
    const prefs = getConsentPreferences();
    updatePreferenceForm(prefs);

    // If consent is already given, hide all banners and do not show any
    if (consentGiven === "true") {
      await hideAllBanners();
      // Do not show any banner unless user clicks the icon
      return;
    }

    // Only show banners if consent not given AND location data is available
    if (!consentGiven && locationData) {
      if (["CCPA", "VCDPA", "CPA", "CTDPA", "UCPA"].includes(locationData.bannerType)) {
        // US Privacy Laws: Unblock all scripts initially (opt-out model)
        unblockScriptsWithDataCategory();
        showBanner(document.getElementById("initial-consent-banner"));
        hideBanner(document.getElementById("consent-banner"));
        
        // Force display US privacy banner
        if (document.getElementById("initial-consent-banner")) {
          document.getElementById("initial-consent-banner").style.display = "block";
          document.getElementById("initial-consent-banner").style.visibility = "visible";
          document.getElementById("initial-consent-banner").hidden = false;
          document.getElementById("initial-consent-banner").classList.remove("hidden");
          document.getElementById("initial-consent-banner").classList.add("show-banner");
        }
      } else {
        // Show GDPR banner (default for EU and other locations)
        showBanner(document.getElementById("consent-banner"));
        hideBanner(document.getElementById("initial-consent-banner"));
        blockScriptsByCategory();
      }
    }
    
    // Accept all
    const acceptBtn = document.getElementById('accept-btn');
    if (acceptBtn) {
      acceptBtn.onclick = async function(e) {
        e.preventDefault();
        const preferences = { Analytics: true, Marketing: true, Personalization: true, donotshare: false, bannerType: locationData ? locationData.bannerType : undefined };
        setConsentState(preferences, cookieDays);
        
        // Enable ALL scripts with data-category (regardless of category value)
        enableAllScriptsWithDataCategory();
        
        hideBanner(document.getElementById("consent-banner"));
        hideBanner(document.getElementById("initial-consent-banner"));
        hideBanner(document.getElementById("main-banner"));
        localStorage.setItem("consent-given", "true");
        await saveConsentStateToServer(preferences, cookieDays, true); // Pass true to include userAgent
        updatePreferenceForm(preferences);
      };
    }
    // Reject all
    const declineBtn = document.getElementById('decline-btn');
    if (declineBtn) {
      declineBtn.onclick = async function(e) {
        e.preventDefault();
        const preferences = { Analytics: false, Marketing: false, Personalization: false, donotshare: true, bannerType: locationData ? locationData.bannerType : undefined };
        
        // Update Google Consent v2 to deny tracking (let Google handle privacy-preserving mode)
        if (typeof gtag === "function") {
          gtag('consent', 'update', {
            'analytics_storage': 'denied',
            'ad_storage': 'denied',
            'ad_personalization': 'denied',
            'ad_user_data': 'denied',
            'personalization_storage': 'denied',
            'functionality_storage': 'granted',
            'security_storage': 'granted'
          });
        }
        
        // Set consent state and block ALL scripts (including Google scripts)
        setConsentState(preferences, cookieDays);
        blockScriptsByCategory();
        hideBanner(document.getElementById("consent-banner"));
        hideBanner(document.getElementById("initial-consent-banner"));
        hideBanner(document.getElementById("main-banner"));
        localStorage.setItem("consent-given", "true");
        await saveConsentStateToServer(preferences, cookieDays, false);
        updatePreferenceForm(preferences);
      };
    }
    // Do Not Share (CCPA)
    const doNotShareBtn = document.getElementById('do-not-share-link');
    if (doNotShareBtn) {
      doNotShareBtn.onclick = function(e) {
        e.preventDefault();
        
        // Hide initial CCPA banner with FORCE
        const initialBanner = document.getElementById('initial-consent-banner');
        if (initialBanner) {
          hideBanner(initialBanner);
        }
        
        // Show CCPA preference panel instead of main consent banner
        const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
        if (ccpaPreferencePanel) {
          showBanner(ccpaPreferencePanel);
          
          // Update CCPA preference form with saved preferences
          updateCCPAPreferenceForm(getConsentPreferences());
        }
      };
    }
    
    // CCPA Preference Accept button
    const ccpaPreferenceAcceptBtn = document.getElementById('consebit-ccpa-prefrence-accept');
  
    if (ccpaPreferenceAcceptBtn) {
ccpaPreferenceAcceptBtn.onclick = async function(e) {
  e.preventDefault();
  
  // Read the do-not-share checkbox value
  const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
  let preferences;
  
  if (doNotShareCheckbox && doNotShareCheckbox.checked) {
    // Checkbox checked means "Do Not Share" - block based on US law type
    preferences = { 
      Analytics: false, 
      Marketing: false, 
      Personalization: false,
      donotshare: true,
      bannerType: locationData ? locationData.bannerType : undefined 
    };
    
    // Apply law-specific blocking based on banner type
    if (locationData && ["VCDPA", "CPA", "CTDPA", "UCPA"].includes(locationData.bannerType)) {
      // Enhanced privacy laws with granular opt-out requirements
      blockTargetedAdvertisingScripts();
      blockSaleScripts();
      blockProfilingScripts();
      blockCrossContextBehavioralAdvertising();
      blockAutomatedDecisionScripts();
    } else {
      // CCPA - block all scripts  
      blockScriptsWithDataCategory();
      blockNonGoogleScripts();
    }
  } else {
    // Checkbox unchecked means "Allow" - unblock all scripts
    preferences = { 
      Analytics: true, 
      Marketing: true, 
      Personalization: true,
      donotshare: false,
      bannerType: locationData ? locationData.bannerType : undefined 
    };
    // Unblock all scripts
    unblockScriptsWithDataCategory();
  }
  
  // Save consent state
  setConsentState(preferences, cookieDays);
  
  // Hide banners
  hideBanner(document.getElementById("initial-consent-banner"));
  const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
  hideBanner(ccpaPreferencePanel);
  const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
  hideBanner(ccpaBannerDiv);
  
  // Set consent as given
  localStorage.setItem("consent-given", "true");
  
  // Save to server
  await saveConsentStateToServer(preferences, cookieDays, true);
  updatePreferenceForm(preferences);
};
    }
      // CCPA Preference Decline button
      const ccpaPreferenceDeclineBtn = document.getElementById('consebit-ccpa-prefrence-decline');
      if (ccpaPreferenceDeclineBtn) {
        ccpaPreferenceDeclineBtn.onclick = async function(e) {
          e.preventDefault();
          
          // Decline means block all scripts (all false)
          const preferences = { 
            Analytics: false, 
            Marketing: false, 
            Personalization: false, 
            donotshare: true, // CCPA Decline means do not share = true
            bannerType: locationData ? locationData.bannerType : undefined 
          };
          
          // Save consent state
          setConsentState(preferences, cookieDays);
          
          // Block all scripts (including Google scripts)
          blockScriptsByCategory();
          
          // Hide both CCPA banners using hideBanner function
          hideBanner(document.getElementById("initial-consent-banner"));
          const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
          hideBanner(ccpaPreferencePanel);
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          hideBanner(ccpaBannerDiv);
          
          // Set consent as given
          localStorage.setItem("consent-given", "true");
          
          // Save to server (original CCPA logic - always include userAgent)
          await saveConsentStateToServer(preferences, cookieDays, true);
          updatePreferenceForm(preferences);
        };
      }
      
      // Save button (CCPA)
      const saveBtn = document.getElementById('save-btn');
      if (saveBtn) {
        saveBtn.onclick = async function(e) {
          e.preventDefault();
          
          // Read the do-not-share checkbox value
          const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
          let preferences;
          let includeUserAgent;
          
          if (doNotShareCheckbox && doNotShareCheckbox.checked) {
            // Checkbox checked means "Do Not Share" - block all scripts and restrict userAgent
            preferences = { 
              Analytics: false, 
              Marketing: false, 
              Personalization: false,
              donotshare: true,
              bannerType: locationData ? locationData.bannerType : undefined 
            };
            includeUserAgent = false; // Restrict userAgent
          } else {
            // Checkbox unchecked means "Allow" - unblock all scripts and allow userAgent
            preferences = { 
              Analytics: true, 
              Marketing: true, 
              Personalization: true,
              donotshare: false,
              bannerType: locationData ? locationData.bannerType : undefined 
            };
            includeUserAgent = true; // Allow userAgent
          }
          
          // Save consent state
          setConsentState(preferences, cookieDays);
          
          // Handle script blocking/unblocking based on checkbox state (including Google scripts)
          if (doNotShareCheckbox && doNotShareCheckbox.checked) {
            // CCPA: Block all scripts with data-category attribute (including Google scripts)
            blockScriptsWithDataCategory();
          } else {
            // CCPA: Unblock all scripts with data-category attribute (including Google scripts)
            unblockScriptsWithDataCategory();
          }
          
          // Hide both CCPA banners - close everything
          const mainConsentBanner = document.getElementById('main-consent-banner');
          const initialConsentBanner = document.getElementById('initial-consent-banner');
          
          if (mainConsentBanner) {
            hideBanner(mainConsentBanner);
          }
          if (initialConsentBanner) {
            hideBanner(initialConsentBanner);
          }
          
          // Set consent as given
          localStorage.setItem("consent-given", "true");
          
          // Save to server with appropriate userAgent setting based on checkbox
          await saveConsentStateToServer(preferences, cookieDays, includeUserAgent);
          updatePreferenceForm(preferences);
        };
      }
      
      // Preferences button (show preferences panel)
      const preferencesBtn = document.getElementById('preferences-btn');
      if (preferencesBtn) {
        preferencesBtn.onclick = function(e) {
          e.preventDefault();
          hideBanner(document.getElementById("consent-banner"));
          showBanner(document.getElementById("main-banner"));
          updatePreferenceForm(getConsentPreferences());
        };
      }
      // Save Preferences button
      const savePreferencesBtn = document.getElementById('save-preferences-btn');
      if (savePreferencesBtn) {
        savePreferencesBtn.onclick = async function(e) {
          e.preventDefault();
          // Read checkboxes
          const analytics = !!document.querySelector('[data-consent-id="analytics-checkbox"]:checked');
          const marketing = !!document.querySelector('[data-consent-id="marketing-checkbox"]:checked');
          const personalization = !!document.querySelector('[data-consent-id="personalization-checkbox"]:checked');
          const preferences = {
            Analytics: analytics,
            Marketing: marketing,
            Personalization: personalization,
            bannerType: locationData ? locationData.bannerType : undefined
          };
          setConsentState(preferences, cookieDays);
          // First block ALL scripts except necessary/essential (including Google scripts)
          blockScriptsByCategory();
          // Then enable only scripts for selected categories (including Google scripts)
          const selectedCategories = Object.keys(preferences).filter(k => preferences[k] && k !== 'bannerType');
          if (selectedCategories.length > 0) {
            enableScriptsByCategories(selectedCategories);
          }
          hideBanner(document.getElementById("main-banner"));
          hideBanner(document.getElementById("consent-banner"));
          hideBanner(document.getElementById("initial-consent-banner"));
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays, true); // Include userAgent for preferences
          updatePreferenceForm(preferences);
        };
      }


   // Cancel button (go back to main banner)
   const cancelGDPRBtn = document.getElementById('cancel-btn');
   if (cancelGDPRBtn) {
    cancelGDPRBtn.onclick = async function(e) {
       e.preventDefault();
       
       // STEP 1: Block all scripts except necessary/essential
       blockScriptsByCategory();
       
       // STEP 2: Also block any scripts that are already running by disabling them
       // Disable Google Analytics if present
       if (typeof gtag !== 'undefined') {
         gtag('consent', 'update', {
           'analytics_storage': 'denied',
           'ad_storage': 'denied',
           'ad_personalization': 'denied',
           'ad_user_data': 'denied',
           'personalization_storage': 'denied'
         });
       }
       
       // Disable Google Tag Manager if present
       if (typeof window.dataLayer !== 'undefined') {
         window.dataLayer.push({
           'event': 'consent_denied',
           'analytics_storage': 'denied',
           'ad_storage': 'denied'
         });
       }
       
       // STEP 3: Uncheck all preference checkboxes
       const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
       const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
       const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
       
       if (analyticsCheckbox) {
         analyticsCheckbox.checked = false;
       }
       if (marketingCheckbox) {
         marketingCheckbox.checked = false;
       }
       if (personalizationCheckbox) {
         personalizationCheckbox.checked = false;
       }
       
       // STEP 4: Save consent state with all preferences as false (like decline behavior)
       const preferences = { 
         Analytics: false, 
         Marketing: false, 
         Personalization: false, 
         bannerType: locationData ? locationData.bannerType : undefined 
       };
       
       setConsentState(preferences, cookieDays);
       updateGtagConsent(preferences);
       
       // STEP 5: Set consent as given and save to server
       localStorage.setItem("consent-given", "true");
       
       try {
         await saveConsentStateToServer(preferences, cookieDays, false); // Exclude userAgent like decline
       } catch (error) {
         // Silent error handling
       }
       
       // STEP 6: Hide banners
       hideBanner(document.getElementById("main-banner"));
       hideBanner(document.getElementById("consent-banner"));
     };
    }


      // Cancel button (go back to main banner)
      const cancelBtn = document.getElementById('close-consent-banner');
      if (cancelBtn) {
        cancelBtn.onclick = async function(e) {
          e.preventDefault();
          
          // Always hide main-consent-banner when cancel is clicked
          const mainConsentBanner = document.getElementById('main-consent-banner');
          if (mainConsentBanner) {
            hideBanner(mainConsentBanner);
          }
          
          // Show initial banner if it exists
          const initialConsentBanner = document.getElementById('initial-consent-banner');
          if (initialConsentBanner) {
            showBanner(initialConsentBanner);
          }
        };
      }
      // CCPA Link Block - Show CCPA Banner
      const ccpaLinkBlock = document.getElementById('consentbit-ccpa-linkblock');
      if (ccpaLinkBlock) {
        ccpaLinkBlock.onclick = function(e) {
          e.preventDefault();
          
          // Show CCPA banner using showBanner function
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          showBanner(ccpaBannerDiv);
          
          // Also show the CCPA banner if it exists
          showBanner(document.getElementById("initial-consent-banner"));
        };
      }
      
      // Close Consent Banner functionality (CCPA only)
    
      
      // Load consent styles after banners are shown
      loadConsentStyles();
  });
  
 // End DOMContentLoaded event listener

    // --- CCPA-specific script handling functions ---
    function unblockScriptsWithDataCategory() {
      // CCPA: Unblock ALL scripts with data-category attribute (including Google scripts) only in head section
      var scripts = document.head.querySelectorAll('script[type="text/plain"][data-category]');
      scripts.forEach(function(oldScript) {
        var newScript = document.createElement('script');
        for (var i = 0; i < oldScript.attributes.length; i++) {
          var attr = oldScript.attributes[i];
          if (attr.name === 'type') {
            newScript.type = 'text/javascript';
          } else if (attr.name !== 'data-blocked-by-ccpa') {
            newScript.setAttribute(attr.name, attr.value);
          }
        }
        if (oldScript.innerHTML) {
          newScript.innerHTML = oldScript.innerHTML;
        }
        oldScript.parentNode.replaceChild(newScript, oldScript);
      });
    }
   
    function blockScriptsWithDataCategory() {
      // CCPA: Block ALL scripts with data-category attribute (including Google scripts) only in head section
      var scripts = document.head.querySelectorAll('script[data-category]');
      scripts.forEach(function(script) {
        if (script.type !== 'text/plain') {
          script.type = 'text/plain';
          script.setAttribute('data-blocked-by-ccpa', 'true');
        }
      });
    }
  
async function hashStringSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function scanAndSendHeadScriptsIfChanged(sessionToken) {
  const headScripts = document.head.querySelectorAll('script');
  const scriptData = Array.from(headScripts).map(script => ({
    src: script.src || null,
    content: script.src ? null : script.innerHTML,
    dataCategory: script.getAttribute('data-category') || null
  }));
  const scriptDataString = JSON.stringify(scriptData);
  const scriptDataHash = await hashStringSHA256(scriptDataString);

  const cachedHash = localStorage.getItem('headScriptsHash');
if (cachedHash !== scriptDataHash) {
}
  if (cachedHash === scriptDataHash) {
    return; // No change, do nothing
  }

  try {
    const encryptedScriptData = await encryptWithHardcodedKey(scriptDataString);
    
    // Get siteName from hostname
    const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
    
    // Build API URL with siteName parameter
    const apiUrl = `https://cb-server.web-8fb.workers.dev/api/v2/cmp/head-scripts?siteName=${encodeURIComponent(siteName)}`;
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({ encryptedData: encryptedScriptData }),
    });
    
    if (response.ok) {
      localStorage.setItem('headScriptsHash', scriptDataHash);
    } else {
      console.error('Failed to send head scripts to API:', response.status);
    }
  } catch (e) {
    console.error('Error sending head scripts to API:', e);
  }
}

function blockNonGoogleScripts() {
  // Block all scripts (including Google scripts) only in head section
  var scripts = document.head.querySelectorAll('script[src]');
  scripts.forEach(function(script) {
      if (script.type !== 'text/plain') {
          script.type = 'text/plain';
          script.setAttribute('data-blocked-by-consent', 'true');
      }
  });

  // Block inline scripts only in head section
  var inlineScripts = document.head.querySelectorAll('script:not([src])');
  inlineScripts.forEach(function(script) {
      if (script.innerHTML && script.type !== 'text/plain') {
          script.type = 'text/plain';
          script.setAttribute('data-blocked-by-consent', 'true');
      }
  });
}
 


function blockTargetedAdvertisingScripts() {
  const targetedAdvertisingPatterns = /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|doubleclick|adwords|adsense|adservice|pixel|quantserve|scorecardresearch|moat|integral-marketing|comscore|nielsen|quantcast|adobe/i;
  
  const scripts = document.head.querySelectorAll('script[src]');
  scripts.forEach(script => {
    if (targetedAdvertisingPatterns.test(script.src)) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-targeted-advertising', 'true');
      }
    }
  });
}

function blockSaleScripts() {
  const salePatterns = /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|doubleclick|adwords|adsense|adservice|pixel|quantserve|scorecardresearch|moat|integral-marketing|comscore|nielsen|quantcast|adobe|marketo|hubspot|salesforce|pardot|eloqua|act-on|mailchimp|constantcontact|sendgrid|klaviyo|braze|iterable/i;
  
  const scripts = document.head.querySelectorAll('script[src]');
  scripts.forEach(script => {
    if (salePatterns.test(script.src)) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-sale', 'true');
      }
    }
  });
}

function blockProfilingScripts() {
  const profilingPatterns = /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat|clarity|hotjar|mouseflow|fullstory|logrocket|mixpanel|segment|amplitude|heap|kissmetrics|matomo|piwik|plausible|woopra|crazyegg|clicktale|chartbeat|parse\.ly/i;
  
  const scripts = document.head.querySelectorAll('script[src]');
  scripts.forEach(script => {
    if (profilingPatterns.test(script.src)) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-profiling', 'true');
      }
    }
  });
}

function blockCrossContextBehavioralAdvertising() {
  const crossContextPatterns = /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|doubleclick|adwords|adsense|adservice|pixel|quantserve|scorecardresearch|moat|integral-marketing|comscore|nielsen|quantcast|adobe/i;
  
  const scripts = document.head.querySelectorAll('script[src]');
  scripts.forEach(script => {
    if (crossContextPatterns.test(script.src)) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-cross-context', 'true');
      }
    }
  });
}

function blockAutomatedDecisionScripts() {
  const automatedDecisionPatterns = /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat|clarity|hotjar|mouseflow|fullstory|logrocket|mixpanel|segment|amplitude|heap|kissmetrics|matomo|piwik|plausible|woopra|crazyegg|clicktale|chartbeat|parse\.ly/i;
  
  const scripts = document.head.querySelectorAll('script[src]');
  scripts.forEach(script => {
    if (automatedDecisionPatterns.test(script.src)) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-automated-decision', 'true');
      }
    }
  });
}
})(); 
