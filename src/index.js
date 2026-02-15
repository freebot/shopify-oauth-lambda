import crypto from "crypto";
import fetch from "node-fetch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const {
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  SHOPIFY_SCOPES,
  REDIRECT_URI,
  TABLE_NAME
} = process.env;

export const handler = async (event) => {
  const path = event.rawPath;

  // =============================
  // 1️⃣ AUTH
  // =============================
  if (path === "/auth") {
    const shop = event.queryStringParameters?.shop;

    if (!shop) {
      return { statusCode: 400, body: "Missing shop param" };
    }

    const state = crypto.randomBytes(16).toString("hex");

    const installUrl =
      `https://${shop}/admin/oauth/authorize` +
      `?client_id=${SHOPIFY_CLIENT_ID}` +
      `&scope=${SHOPIFY_SCOPES}` +
      `&redirect_uri=${REDIRECT_URI}` +
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
    const { shop, code, hmac, state } = event.queryStringParameters;

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
      return { statusCode: 400, body: "HMAC validation failed" };
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

    const tokenData = await tokenResponse.json();

    const accessToken = tokenData.access_token;

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
          processed_count: 0,
          state
        }
      })
    );

    return {
      statusCode: 200,
      body: "App instalada correctamente"
    };
  }

  return { statusCode: 404 };
};
