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
