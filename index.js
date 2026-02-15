const crypto = require("crypto");
const {
  DynamoDBClient
} = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand
} = require("@aws-sdk/lib-dynamodb");

// ==============================
// AWS DynamoDB
// ==============================
const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({})
);

// ==============================
// ENV VARIABLES
// ==============================
const {
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  SHOPIFY_SCOPES,
  REDIRECT_URI,
  TABLE_NAME
} = process.env;

// ==============================
// MAIN HANDLER
// ==============================
exports.handler = async (event) => {
  try {
    const path = event.rawPath || event.requestContext?.http?.path;
    const query = event.queryStringParameters || {};

    console.log("PATH:", path);
    console.log("QUERY:", query);

    // ==========================
    // 0️⃣ CHECK CONFIG & STATUS
    // ==========================
    if (!SHOPIFY_CLIENT_ID || !SHOPIFY_CLIENT_SECRET || !TABLE_NAME || !REDIRECT_URI) {
      console.error("Missing environment variables");
      return htmlResponse(500, `
        <h1>Configuration Error</h1>
        <p>Missing required environment variables on server.</p>
        <pre>
Client ID: ${SHOPIFY_CLIENT_ID ? 'OK' : 'MISSING'}
Client Secret: ${SHOPIFY_CLIENT_SECRET ? 'OK' : 'MISSING'}
Table Name: ${TABLE_NAME ? 'OK' : 'MISSING'}
Redirect URI: ${REDIRECT_URI ? 'OK' : 'MISSING'}
        </pre>
      `);
    }

    if (REDIRECT_URI.includes("example.com")) {
      return htmlResponse(500, `
            <h1>Configuration Warning</h1>
            <p>The <code>REDIRECT_URI</code> environment variable is set to <strong>${REDIRECT_URI}</strong>, which appears to be a placeholder.</p>
            <p>Please update it to your actual API Gateway URL + <code>/callback</code>.</p>
        `);
    }

    if (path === "/" || path === "") {
      const { shop, hmac } = query;

      if (!shop) {
        return htmlResponse(200, `
          <html>
            <body style="font-family: system-ui; padding: 2rem; text-align: center;">
              <h1>Shopify App Status</h1>
              <p>Please open this app from the Shopify Admin.</p>
            </body>
          </html>
        `);
      }

      // If HMAC is present, validate it.
      if (hmac && !validateHmac(query)) {
        return htmlResponse(400, "<h1>Security Error</h1><p>Invalid HMAC signature.</p>");
      }

      // Check installation status in DynamoDB
      let session = null;
      try {
        session = await getSession(shop);
      } catch (err) {
        console.error("DynamoDB Error:", err);
        return htmlResponse(500, "<h1>Database Error</h1><p>Could not verify installation status.</p>");
      }

      const isInstalled = !!session && !!session.accessToken;

      if (!isInstalled) {
        // Not installed: Redirect to Auth
        return redirect(`/auth?shop=${shop}`);
      }

      // APP IS INSTALLED & RUNNING
      return htmlResponse(200, `
        <!DOCTYPE html>
        <html>
        <head>
          <title>App Status</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Segoe UI", Roboto, "Helvetica Neue", sans-serif; padding: 20px; background: #f6f6f7; color: #202223; }
            .card { background: white; border: 1px solid #e1e3e5; border-radius: 8px; padding: 20px; max-width: 600px; margin: 40px auto; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
            h1 { font-size: 24px; font-weight: 600; margin-bottom: 8px; }
            p { color: #6d7175; margin-bottom: 24px; }
            .status-badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
            .status-badge.active { background: #E4F7EB; color: #007D44; border: 1px solid #B7EBCE; }
            .status-badge.inactive { background: #FFEAEE; color: #B51818; border: 1px solid #FFC9D1; }
            table { width: 100%; border-collapse: collapse; margin-top: 24px; }
            td { padding: 12px 0; border-bottom: 1px solid #f1f2f3; font-size: 14px; }
            td:first-child { font-weight: 500; color: #6d7175; width: 40%; }
            td:last-child { text-align: right; font-family: monospace; color: #202223; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>App Status</h1>
            <p>The application is installed and communicating with Shopify APIs.</p>
            
            <div style="margin-bottom: 20px;">
                <span class="status-badge active">● &nbsp; System Operational</span>
            </div>

            <table>
                <tr><td>Shop Domain</td><td>${shop}</td></tr>
                <tr><td>Installed At</td><td>${new Date(session.installedAt).toLocaleString()}</td></tr>
                <tr><td>Scopes</td><td>${session.scope}</td></tr>
                <tr><td>Status</td><td>Active</td></tr>
            </table>
          </div>
        </body>
        </html>
      `);
    }

    // ==========================
    // 1️⃣ AUTH
    // ==========================
    if (path === "/auth") {
      const shop = query.shop;

      if (!shop || !shop.endsWith(".myshopify.com")) {
        return response(400, "Invalid shop parameter");
      }

      const state = crypto.randomBytes(16).toString("hex");

      const installUrl =
        `https://${shop}/admin/oauth/authorize` +
        `?client_id=${SHOPIFY_CLIENT_ID}` +
        `&scope=${SHOPIFY_SCOPES}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&state=${state}`;

      return redirect(installUrl);
    }

    // ==========================
    // 2️⃣ CALLBACK
    // ==========================
    if (path === "/callback") {
      const { shop, code, hmac } = query;

      if (!shop || !code || !hmac) {
        return response(400, "Missing required parameters");
      }

      if (!validateHmac(query)) {
        return response(400, "HMAC validation failed");
      }

      const tokenResponse = await fetch(
        `https://${shop}/admin/oauth/access_token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client_id: SHOPIFY_CLIENT_ID,
            client_secret: SHOPIFY_CLIENT_SECRET,
            code
          })
        }
      );

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        console.error("Token exchange error:", errorText);
        return response(500, errorText);
      }

      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) {
        return response(500, "No access token returned");
      }

      await ddb.send(
        new PutCommand({
          TableName: TABLE_NAME,
          Item: {
            id: `offline_${shop}`,
            shop,
            accessToken,
            scope: SHOPIFY_SCOPES,
            installedAt: Date.now()
          }
        })
      );

      return response(200, "App instalada correctamente");
    }

    // ==========================
    // 3️⃣ PRODUCTS
    // ==========================
    if (path === "/products") {
      const shop = query.shop;

      if (!shop) {
        return response(400, "Missing shop parameter");
      }

      const session = await getSession(shop);

      if (!session) {
        return response(404, "Shop not installed");
      }

      const shopifyResponse = await fetch(
        `https://${shop}/admin/api/2024-10/products.json`,
        {
          headers: {
            "X-Shopify-Access-Token": session.accessToken,
            "Content-Type": "application/json"
          }
        }
      );

      if (!shopifyResponse.ok) {
        const errorText = await shopifyResponse.text();
        console.error("Shopify API error:", errorText);
        return response(500, errorText);
      }

      const data = await shopifyResponse.json();
      return jsonResponse(200, data);
    }

    return response(404, "Not Found");

  } catch (error) {
    console.error("Unhandled error:", error);
    return response(500, "Internal Server Error");
  }
};

// ==============================
// HELPERS
// ==============================

function validateHmac(params) {
  const { hmac, ...rest } = params;

  const message = Object.keys(rest)
    .sort()
    .map(key => `${key}=${rest[key]}`)
    .join("&");

  const generatedHash = crypto
    .createHmac("sha256", SHOPIFY_CLIENT_SECRET)
    .update(message)
    .digest("hex");

  const hashBuffer = Buffer.from(generatedHash, "utf8");
  const hmacBuffer = Buffer.from(hmac, "utf8");

  if (hashBuffer.length !== hmacBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(hashBuffer, hmacBuffer);
}

async function getSession(shop) {
  const result = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { id: `offline_${shop}` }
    })
  );

  return result.Item;
}

function response(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "text/plain"
    },
    body
  };
}

function jsonResponse(statusCode, data) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(data)
  };
}

function redirect(location) {
  return {
    statusCode: 302,
    headers: {
      Location: location
    }
  };
}

function htmlResponse(statusCode, html) {
  return {
    statusCode,
    headers: {
      "Content-Type": "text/html"
    },
    body: html
  };
}
