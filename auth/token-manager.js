/**
 * Token management for Microsoft Graph API authentication
 * With automatic token refresh support
 */
const fs = require('fs');
const https = require('https');
const querystring = require('querystring');
const config = require('../config');

// Load environment variables from .env file
require('dotenv').config();

// Global variable to store tokens
let cachedTokens = null;
let isRefreshing = false;
let refreshPromise = null;

/**
 * Loads authentication tokens from the token file
 * @returns {object|null} - The loaded tokens or null if not available
 */
function loadTokenCache() {
  try {
    const tokenPath = config.AUTH_CONFIG.tokenStorePath;
    
    if (!fs.existsSync(tokenPath)) {
      console.error('[TOKEN] Token file does not exist');
      return null;
    }
    
    const tokenData = fs.readFileSync(tokenPath, 'utf8');
    const tokens = JSON.parse(tokenData);
    
    if (!tokens.access_token) {
      console.error('[TOKEN] No access_token found in tokens');
      return null;
    }
    
    // Update the cache
    cachedTokens = tokens;
    return tokens;
  } catch (error) {
    console.error('[TOKEN] Error loading token cache:', error.message);
    return null;
  }
}

/**
 * Saves authentication tokens to the token file
 * @param {object} tokens - The tokens to save
 * @returns {boolean} - Whether the save was successful
 */
function saveTokenCache(tokens) {
  try {
    const tokenPath = config.AUTH_CONFIG.tokenStorePath;
    fs.writeFileSync(tokenPath, JSON.stringify(tokens, null, 2));
    console.error('[TOKEN] Tokens saved successfully');
    
    // Update the cache
    cachedTokens = tokens;
    return true;
  } catch (error) {
    console.error('[TOKEN] Error saving token cache:', error.message);
    return false;
  }
}

/**
 * Check if token is expired or about to expire (with 5 minute buffer)
 * @param {object} tokens - Token object
 * @returns {boolean} - True if token needs refresh
 */
function isTokenExpired(tokens) {
  if (!tokens || !tokens.expires_at) {
    return true;
  }
  
  const now = Date.now();
  const expiresAt = tokens.expires_at;
  const bufferMs = 5 * 60 * 1000; // 5 minutes buffer
  
  return now >= (expiresAt - bufferMs);
}

/**
 * Refresh access token using refresh token
 * @param {string} refreshToken - The refresh token
 * @returns {Promise<object>} - New token response
 */
function refreshAccessToken(refreshToken) {
  return new Promise((resolve, reject) => {
    const clientId = process.env.MS_CLIENT_ID || config.AUTH_CONFIG.clientId;
    const clientSecret = process.env.MS_CLIENT_SECRET || config.AUTH_CONFIG.clientSecret;
    
    if (!clientId || !clientSecret) {
      reject(new Error('MS_CLIENT_ID or MS_CLIENT_SECRET not configured'));
      return;
    }
    
    const scopes = [
      'offline_access',
      'User.Read',
      'Mail.Read',
      'Mail.Send',
      'Calendars.Read',
      'Calendars.ReadWrite',
      'Contacts.Read'
    ];
    
    const postData = querystring.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: scopes.join(' ')
    });

    const options = {
      hostname: 'login.microsoftonline.com',
      path: '/common/oauth2/v2.0/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(response);
          } else {
            reject(new Error(`Token refresh failed: ${response.error_description || response.error}`));
          }
        } catch (e) {
          reject(new Error(`Error parsing token response: ${e.message}`));
        }
      });
    });

    req.on('error', (error) => {
      reject(new Error(`Network error during token refresh: ${error.message}`));
    });
    
    req.write(postData);
    req.end();
  });
}

/**
 * Perform token refresh and save to file
 * @returns {Promise<string>} - New access token
 */
async function performTokenRefresh() {
  const tokens = cachedTokens || loadTokenCache();
  
  if (!tokens || !tokens.refresh_token) {
    throw new Error('No refresh token available');
  }
  
  console.error('[TOKEN] Refreshing access token...');
  
  try {
    const response = await refreshAccessToken(tokens.refresh_token);
    
    // Update tokens
    tokens.access_token = response.access_token;
    if (response.refresh_token) {
      tokens.refresh_token = response.refresh_token;
    }
    tokens.expires_in = response.expires_in;
    tokens.expires_at = Date.now() + (response.expires_in * 1000);
    tokens.scope = response.scope;
    tokens.token_type = response.token_type;
    
    // Save to file
    saveTokenCache(tokens);
    
    console.error(`[TOKEN] Token refreshed successfully, expires at: ${new Date(tokens.expires_at).toLocaleString()}`);
    
    return tokens.access_token;
  } catch (error) {
    console.error('[TOKEN] Token refresh failed:', error.message);
    throw error;
  }
}

/**
 * Gets the current access token, automatically refreshing if expired
 * @returns {Promise<string|null>} - The access token or null if not available
 */
async function getAccessToken() {
  // Use cached tokens if available
  let tokens = cachedTokens;
  
  // Load from file if not cached
  if (!tokens) {
    tokens = loadTokenCache();
  }
  
  if (!tokens || !tokens.access_token) {
    console.error('[TOKEN] No access token available');
    return null;
  }
  
  // Check if token needs refresh
  if (isTokenExpired(tokens)) {
    console.error('[TOKEN] Token expired or expiring soon, attempting refresh...');
    
    // Prevent concurrent refresh attempts
    if (isRefreshing) {
      console.error('[TOKEN] Token refresh already in progress, waiting...');
      return refreshPromise;
    }
    
    isRefreshing = true;
    refreshPromise = performTokenRefresh()
      .finally(() => {
        isRefreshing = false;
        refreshPromise = null;
      });
    
    return refreshPromise;
  }
  
  // Token is still valid
  return tokens.access_token;
}

/**
 * Gets the current access token synchronously (without auto-refresh)
 * Use this only when you don't need auto-refresh
 * @returns {string|null} - The access token or null if not available
 */
function getAccessTokenSync() {
  if (cachedTokens && cachedTokens.access_token) {
    return cachedTokens.access_token;
  }
  
  const tokens = loadTokenCache();
  return tokens ? tokens.access_token : null;
}

/**
 * Creates a test access token for use in test mode
 * @returns {object} - The test tokens
 */
function createTestTokens() {
  const testTokens = {
    access_token: "test_access_token_" + Date.now(),
    refresh_token: "test_refresh_token_" + Date.now(),
    expires_at: Date.now() + (3600 * 1000) // 1 hour
  };
  
  saveTokenCache(testTokens);
  return testTokens;
}

module.exports = {
  loadTokenCache,
  saveTokenCache,
  getAccessToken,
  getAccessTokenSync,
  createTestTokens,
  isTokenExpired,
  refreshAccessToken
};
