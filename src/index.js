import crypto from "crypto";
import fetch from "node-fetch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, GetCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const {
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  SHOPIFY_SCOPES,
  REDIRECT_URI,
  TABLE_NAME
} = process.env;

export const handler = async (event) => {
  try {
    const path = event.rawPath;

    // =============================
    // 1️⃣ AUTH
    // =============================
    if (path === "/auth") {
      const shop = event.queryStringParameters?.shop;

      if (!shop) {
        return response(400, "Missing shop param");
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
        headers: { Location: installUrl }
      };
    }

    // =============================
    // 2️⃣ CALLBACK
    // =============================
    if (path === "/callback") {
      const { shop, code, hmac } = event.queryStringParameters;

      if (!shop || !code || !hmac) {
        return response(400, "Missing required parameters");
      }

      // 🔐 Validar HMAC
      const map = { ...event.queryStringParameters };
      delete map.hmac;

      const message = Object.keys(map)
        .sort()
        .map(key => `${key}=${map[key]}`)
        .join("&");

      const generatedHash = crypto
        .createHmac("sha256", SHOPIFY_CLIENT_SECRET)
        .update(message)
        .digest("hex");

      if (generatedHash !== hmac) {
        return response(400, "HMAC validation failed");
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

      const rawText = await tokenResponse.text();

      if (!tokenResponse.ok) {
        console.error("Shopify token error:", rawText);
        return response(500, `Token exchange failed: ${rawText}`);
      }

      let tokenData;
      try {
        tokenData = JSON.parse(rawText);
      } catch (err) {
        console.error("Invalid JSON from Shopify:", rawText);
        return response(500, "Invalid JSON returned from Shopify");
      }

      const accessToken = tokenData.access_token;

      if (!accessToken) {
        return response(500, "No access_token returned");
      }

      // 💾 Guardar en DynamoDB
      await ddb.send(
        new PutCommand({
          TableName: TABLE_NAME,
          Item: {
            id: `offline_${shop}`,
            accessToken,
            shop,
            scope: SHOPIFY_SCOPES,
            isOnline: false,
            installedAt: Date.now()
          }
        })
      );

      return response(200, "App instalada correctamente");
    }

    return response(404, "Not found");

  } catch (error) {
    console.error("Lambda error:", error);
    return response(500, "Internal Server Error");
  }
};

// Helper
function response(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "text/plain" },
    body
  };
}
