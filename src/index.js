import crypto from "crypto";
import fetch from "node-fetch";
import {
  DynamoDBClient
} from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const {
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  SHOPIFY_SCOPES,
  REDIRECT_URI,
  TABLE_NAME
} = process.env;

// =============================
// 🔒 Utils
// =============================

function validateShop(shop) {
  return /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop);
}

function validateHmac(query, secret) {
  const { hmac, ...rest } = query;

  const message = Object.keys(rest)
    .sort()
    .map(key => `${key}=${rest[key]}`)
    .join("&");

  const generatedHash = crypto
    .createHmac("sha256", secret)
    .update(message)
    .digest();

  const providedHash = Buffer.from(hmac, "hex");

  return (
    providedHash.length === generatedHash.length &&
    crypto.timingSafeEqual(generatedHash, providedHash)
  );
}

function jsonResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  };
}

// =============================
// 🚀 Handler
// =============================

export const handler = async (event) => {
  try {
    const path = event.rawPath;
    const query = event.queryStringParameters || {};

    // =============================
    // 🟢 HEALTH CHECK
    // =============================
    if (path === "/") {
      return jsonResponse(200, { status: "ok" });
    }

    // =============================
    // 1️⃣ AUTH
    // =============================
    if (path === "/auth") {
      const { shop } = query;

      if (!shop || !validateShop(shop)) {
        return jsonResponse(400, { error: "Invalid shop parameter" });
      }

      const state = crypto.randomBytes(16).toString("hex");

      const installUrl =
        `https://${shop}/admin/oauth/authorize` +
        `?client_id=${SHOPIFY_CLIENT_ID}` +
        `&scope=${SHOPIFY_SCOPES}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&state=${state}`;

      return {
        statusCode: 302,
        headers: {
          Location: installUrl
        }
      };
    }

    // =============================
    // 2️⃣ CALLBACK
    // =============================
    if (path === "/callback") {
      const { shop, code } = query;

      if (!shop || !code || !validateShop(shop)) {
        return jsonResponse(400, { error: "Invalid callback parameters" });
      }

      if (!validateHmac(query, SHOPIFY_CLIENT_SECRET)) {
        return jsonResponse(400, { error: "HMAC validation failed" });
      }

      // 🔄 Intercambiar code por token
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
        return jsonResponse(500, {
          error: "Failed to fetch access token"
        });
      }

      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;

      // 💾 Guardar sesión offline
      await ddb.send(
        new PutCommand({
          TableName: TABLE_NAME,
          Item: {
            id: `offline_${shop}`,
            shop,
            accessToken,
            scope: SHOPIFY_SCOPES,
            isOnline: false,
            processed_count: 0,
            installedAt: new Date().toISOString()
          }
        })
      );

      return jsonResponse(200, {
        success: true,
        message: "App instalada correctamente"
      });
    }

    // =============================
    // 3️⃣ PRODUCTS (para OpenClaw)
    // =============================
    if (path === "/products") {
      const { shop } = query;

      if (!shop || !validateShop(shop)) {
        return jsonResponse(400, { error: "Invalid shop parameter" });
      }

      // 🔍 Obtener token
      const session = await ddb.send(
        new GetCommand({
          TableName: TABLE_NAME,
          Key: { id: `offline_${shop}` }
        })
      );

      if (!session.Item) {
        return jsonResponse(404, { error: "Shop not installed" });
      }

      const token = session.Item.accessToken;

      // 📡 Llamar Shopify Admin API
      const response = await fetch(
        `https://${shop}/admin/api/2026-01/products.json`,
        {
          headers: {
            "X-Shopify-Access-Token": token,
            "Content-Type": "application/json"
          }
        }
      );

      if (!response.ok) {
        return jsonResponse(response.status, {
          error: "Shopify API error"
        });
      }

      const data = await response.json();

      return jsonResponse(200, data);
    }

    // =============================
    // ❌ NOT FOUND
    // =============================
    return jsonResponse(404, { error: "Route not found" });

  } catch (err) {
    console.error("Unhandled error:", err);
    return jsonResponse(500, { error: "Internal server error" });
  }
};
