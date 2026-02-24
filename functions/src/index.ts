import { onRequest } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import { defineSecret } from "firebase-functions/params";
import { google } from "googleapis";
import { OAuth2Client } from "google-auth-library";

import * as admin from "firebase-admin";
admin.initializeApp();
const db = admin.firestore();

/**
 * ============================
 *  Secret Manager
 * ============================
 */
const GP_JSON = defineSecret("GP_SERVICE_ACCOUNT_JSON");

/**
 * ============================
 *  Google Login Audience
 * ============================
 */
const WEB_CLIENT_ID =
    "788294993689-oqhpc6hpcj6utskqe9k45jk8illfp0i6.apps.googleusercontent.com";

const ANDROID_CLIENT_ID_1 =
    "788294993689-5egq6j9j2dk5ahovvnjc1lsf5v0kl6q8.apps.googleusercontent.com";

const ANDROID_CLIENT_ID_2 =
    "788294993689-dndcr4urbm4244ke9hluvulsfkmuo510.apps.googleusercontent.com";

const ALLOWED_AUDIENCES = [WEB_CLIENT_ID, ANDROID_CLIENT_ID_1, ANDROID_CLIENT_ID_2];

// ----------------------
// Google Login 검증 (DTO 호환)
// ----------------------
export const verifyGoogleIdToken = onRequest(async (req, res) => {
    try {
        if (req.method !== "POST") {
            res.status(405).json({ ok: false, error: "Method Not Allowed" });
            return;
        }

        const token = req.body?.idToken;
        if (!token) {
            res.status(400).json({ ok: false, error: "Missing idToken" });
            return;
        }

        const client = new OAuth2Client();
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: ALLOWED_AUDIENCES,
        });

        const payload = ticket.getPayload();
        if (!payload) {
            res.status(401).json({ ok: false, error: "Invalid token" });
            return;
        }

        // ✅ Unity DTO(VerifyGoogleIdTokenResult)와 구조 맞춤
        res.json({
            ok: true,
            googleUser: {
                uid: payload.sub,
                email: payload.email ?? null,
                name: payload.name ?? null,
                picture: payload.picture ?? null,
            },
            firebaseCustomToken: null, // (옵션) 원하면 여기서 admin.auth().createCustomToken(...) 가능
            error: null,
            details: null,
        });
    } catch (error: any) {
        logger.error("verifyGoogleIdToken error:", error);
        res.status(500).json({ ok: false, error: error?.message ?? "Server error" });
    }
});

// ----------------------
// Google Play 결제 검증 + 로그 저장 (원본 유지)
// ----------------------
export const verifyPurchase = onRequest({ secrets: [GP_JSON] }, async (req, res) => {
    try {
        const { packageName, productId, purchaseToken, accountId } = req.body ?? {};

        if (!packageName || !productId || !purchaseToken) {
            res.status(400).json({ error: "Missing parameters" });
            return;
        }

        const safeAccountId =
            typeof accountId === "string" && accountId.length > 0 ? accountId : "unknown";

        const svcJson = GP_JSON.value();
        if (!svcJson) {
            res.status(500).json({ error: "Missing GP_SERVICE_ACCOUNT_JSON" });
            return;
        }

        const serviceAccount = JSON.parse(svcJson);

        const auth = new google.auth.GoogleAuth({
            credentials: serviceAccount,
            scopes: ["https://www.googleapis.com/auth/androidpublisher"],
        });

        const androidpublisher = google.androidpublisher({
            version: "v3",
            auth,
        });

        const result = await androidpublisher.purchases.products.get({
            packageName,
            productId,
            token: purchaseToken,
        });

        const p = result.data;

        const purchaseState = typeof p.purchaseState === "number" ? p.purchaseState : -1;
        const orderId = (p.orderId ?? "") as string;

        const purchaseTimeMillisRaw = (p.purchaseTimeMillis ?? "") as string;
        const purchaseTimeMillis =
            typeof purchaseTimeMillisRaw === "string" && purchaseTimeMillisRaw.length > 0
                ? Number(purchaseTimeMillisRaw)
                : null;

        const docId = purchaseToken;
        const logRef = db.collection("iap_purchases").doc(docId);
        const now = admin.firestore.FieldValue.serverTimestamp();

        await logRef.set(
            {
                accountId: safeAccountId,
                packageName,
                productId,
                purchaseToken,
                orderId,
                purchaseState,
                acknowledgementState: (p as any).acknowledgementState ?? null,
                consumptionState: (p as any).consumptionState ?? null,
                kind: (p as any).kind ?? null,
                purchaseTimeMillis,
                verifiedAt: now,
                purchaseRaw: p,
            },
            { merge: true }
        );

        res.json({
            ok: true,
            status: "ok",
            purchase: p,
            logged: true,
            logDocId: docId,
        });
    } catch (error: any) {
        logger.error("verifyPurchase error:", error);
        res.status(500).json({ error: "Server error", details: error?.message });
    }
});