/**
 * Google Apps Script Web App API for Google Sheets User Database
 * 
 * Features:
 * - Worksheet: Users
 * - Columns: userId | hashedPassword | publicKey
 * - JSON-based API using doPost(e) and doGet(e)
 * - Shared secret / API Key validation
 * - Concurrency control with LockService
 * - Strict validation: Rejects plaintext passwords and private keys
 */

// Configuration - can also be overridden via Script Properties (API_KEY)
var DEFAULT_SHEET_NAME = "Users";
var HEADER_ROW = ["userId", "hashedPassword", "publicKey"];

/**
 * Get API key from Script Properties or return default fallback for testing
 */
function getApiKey() {
  var props = PropertiesService.getScriptProperties();
  var key = props.getProperty("API_KEY");
  return key || "";
}

/**
 * Helper to produce standardized JSON HTTP responses
 */
function createJsonResponse(data, statusCode) {
  var output = ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
  return output;
}

/**
 * Ensure the "Users" sheet exists and has proper column headers
 */
function getOrCreateUsersSheet() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName(DEFAULT_SHEET_NAME);
  
  if (!sheet) {
    sheet = ss.insertSheet(DEFAULT_SHEET_NAME);
  }
  
  // Verify or insert header row
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(HEADER_ROW);
    sheet.getRange(1, 1, 1, HEADER_ROW.length).setFontWeight("bold");
  } else {
    var headers = sheet.getRange(1, 1, 1, HEADER_ROW.length).getValues()[0];
    if (headers[0] !== HEADER_ROW[0] || headers[1] !== HEADER_ROW[1] || headers[2] !== HEADER_ROW[2]) {
      sheet.getRange(1, 1, 1, HEADER_ROW.length).setValues([HEADER_ROW]).setFontWeight("bold");
    }
  }
  
  return sheet;
}

/**
 * Validate incoming API key
 */
function validateApiKey(requestKey) {
  var expectedKey = getApiKey();
  if (!expectedKey) {
    // If no script property is set, pass-through or allow setting via request
    return true;
  }
  return requestKey === expectedKey;
}

/**
 * GET Endpoint handler
 */
function doGet(e) {
  try {
    var params = e ? e.parameter : {};
    var action = params.action;
    var apiKey = params.apiKey;

    if (!validateApiKey(apiKey)) {
      return createJsonResponse({ success: false, message: "Unauthorized: Invalid API key" }, 401);
    }

    if (action === "ping") {
      return createJsonResponse({ success: true, message: "PQC Auth Apps Script API is operational" }, 200);
    } else if (action === "userExists") {
      return handleUserExists(params.userId);
    } else if (action === "getUser") {
      return handleGetUser(params.userId);
    } else {
      return createJsonResponse({ success: false, message: "Invalid or missing action parameter" }, 400);
    }
  } catch (err) {
    return createJsonResponse({ success: false, message: "Server error: " + err.toString() }, 500);
  }
}

/**
 * POST Endpoint handler
 */
function doPost(e) {
  var lock = LockService.getScriptLock();
  
  try {
    // Acquire lock for up to 10 seconds to ensure safe concurrent writes
    var acquired = lock.tryLock(10000);
    if (!acquired) {
      return createJsonResponse({ success: false, message: "Server busy, please try again" }, 503);
    }

    if (!e || !e.postData || !e.postData.contents) {
      return createJsonResponse({ success: false, message: "Missing request payload" }, 400);
    }

    var payload;
    try {
      payload = JSON.parse(e.postData.contents);
    } catch (parseErr) {
      return createJsonResponse({ success: false, message: "Malformed JSON payload" }, 400);
    }

    // Security checks: Reject dangerous fields
    if (payload.privateKey || payload.private_key || payload.secretKey) {
      return createJsonResponse({ success: false, message: "Security violation: Private key must never be sent to storage" }, 400);
    }

    if (payload.password && !payload.hashedPassword) {
      return createJsonResponse({ success: false, message: "Security violation: Plaintext password must never be sent to storage" }, 400);
    }

    // Validate API key
    if (!validateApiKey(payload.apiKey)) {
      return createJsonResponse({ success: false, message: "Unauthorized: Invalid API key" }, 401);
    }

    var action = payload.action;

    if (action === "createUser") {
      return handleCreateUser(payload);
    } else if (action === "getUser") {
      return handleGetUser(payload.userId);
    } else if (action === "userExists") {
      return handleUserExists(payload.userId);
    } else if (action === "updateUser") {
      return handleUpdateUser(payload);
    } else {
      return createJsonResponse({ success: false, message: "Unsupported action: " + action }, 400);
    }

  } catch (err) {
    return createJsonResponse({ success: false, message: "Execution error: " + err.toString() }, 500);
  } finally {
    try {
      lock.releaseLock();
    } catch (releaseErr) {
      // Lock already released or expired
    }
  }
}

/**
 * Helper: Find user row index by userId (1-indexed)
 */
function findUserRow(sheet, userId) {
  if (!userId) return -1;
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return -1; // No data rows
  
  var userIds = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
  for (var i = 0; i < userIds.length; i++) {
    if (String(userIds[i][0]).trim() === String(userId).trim()) {
      return i + 2; // Row number in spreadsheet
    }
  }
  return -1;
}

/**
 * Check if a user exists
 */
function handleUserExists(userId) {
  if (!userId) {
    return createJsonResponse({ success: false, message: "userId parameter required" }, 400);
  }
  
  var sheet = getOrCreateUsersSheet();
  var row = findUserRow(sheet, userId);
  return createJsonResponse({
    success: true,
    exists: row !== -1,
    userId: userId
  }, 200);
}

/**
 * Retrieve user by userId
 */
function handleGetUser(userId) {
  if (!userId) {
    return createJsonResponse({ success: false, message: "userId required" }, 400);
  }

  var sheet = getOrCreateUsersSheet();
  var rowIndex = findUserRow(sheet, userId);
  if (rowIndex === -1) {
    return createJsonResponse({ success: false, message: "User not found" }, 404);
  }

  var rowData = sheet.getRange(rowIndex, 1, 1, 3).getValues()[0];
  return createJsonResponse({
    success: true,
    user: {
      userId: String(rowData[0]),
      hashedPassword: String(rowData[1]),
      publicKey: String(rowData[2])
    }
  }, 200);
}

/**
 * Create a new user record
 */
function handleCreateUser(payload) {
  var userId = payload.userId;
  var hashedPassword = payload.hashedPassword;
  var publicKey = payload.publicKey || "";

  if (!userId || !hashedPassword) {
    return createJsonResponse({ success: false, message: "userId and hashedPassword are required" }, 400);
  }

  var sheet = getOrCreateUsersSheet();
  var existingRow = findUserRow(sheet, userId);
  if (existingRow !== -1) {
    return createJsonResponse({ success: false, message: "User already exists" }, 409);
  }

  sheet.appendRow([userId, hashedPassword, publicKey]);
  return createJsonResponse({
    success: true,
    message: "User created successfully",
    userId: userId
  }, 201);
}

/**
 * Update an existing user record
 */
function handleUpdateUser(payload) {
  var userId = payload.userId;
  if (!userId) {
    return createJsonResponse({ success: false, message: "userId required for update" }, 400);
  }

  var sheet = getOrCreateUsersSheet();
  var rowIndex = findUserRow(sheet, userId);
  if (rowIndex === -1) {
    return createJsonResponse({ success: false, message: "User not found" }, 404);
  }

  if (payload.hashedPassword) {
    sheet.getRange(rowIndex, 2).setValue(payload.hashedPassword);
  }
  if (payload.publicKey !== undefined) {
    sheet.getRange(rowIndex, 3).setValue(payload.publicKey);
  }

  return createJsonResponse({
    success: true,
    message: "User updated successfully",
    userId: userId
  }, 200);
}
