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
    const path = event.rawPath;
    const query = event.queryStringParameters || {};

    console.log("PATH:", path);
    console.log("QUERY:", query);

    // ==========================
    // 1️⃣ AUTH
    // ==========================
    if (path === "/auth") {
      const shop = query.shop;

      if (!shop) {
        return response(400, "Missing shop parameter");
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

      // 🔐 Validate HMAC
      if (!validateHmac(query)) {
        return response(400, "HMAC validation failed");
      }

      // 🔄 Exchange code for token
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

      const rawText = await tokenResponse.text();

      if (!tokenResponse.ok) {
        console.error("Token exchange error:", rawText);
        return response(500, rawText);
      }

      let tokenData;
      try {
        tokenData = JSON.parse(rawText);
      } catch (err) {
        console.error("Invalid JSON:", rawText);
        return response(500, "Invalid JSON from Shopify");
      }

      const accessToken = tokenData.access_token;

      if (!accessToken) {
        return response(500, "No access token returned");
      }

      // 💾 Save in DynamoDB
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
    // 3️⃣ PRODUCTS ENDPOINT
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

      const rawText = await shopifyResponse.text();

      if (!shopifyResponse.ok) {
        console.error("Shopify API error:", rawText);
        return response(500, rawText);
      }

      return jsonResponse(200, JSON.parse(rawText));
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

  return crypto.timingSafeEqual(
    Buffer.from(generatedHash),
    Buffer.from(hmac)
  );
}

async function getSession(shop) {
  const result = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        id: `offline_${shop}`
      }
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
