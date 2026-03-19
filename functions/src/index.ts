import { onRequest } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import { defineSecret } from "firebase-functions/params";
import { google } from "googleapis";
import { OAuth2Client } from "google-auth-library";
import jwksClient from "jwks-rsa";
import jwt from "jsonwebtoken";

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

/**
 * ============================
 *  Apple Login
 * ============================
 * Google과 달리 별도 Client ID/Secret 없음. iOS는 Bundle ID만으로 식별.
 * Web 로그인 사용 시 Apple Service ID 추가 가능.
 */
const APPLE_CLIENT_IDS = [
    "com.justthislab.justonematch",
] as [string, ...string[]];

const appleJwksClient = jwksClient({
    jwksUri: "https://appleid.apple.com/auth/keys",
    timeout: 30000,
});

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
// Apple Login 검증 (DTO 호환)
// ----------------------
export const verifyAppleIdToken = onRequest(async (req, res) => {
    try {
        if (req.method !== "POST") {
            res.status(405).json({ ok: false, error: "Method Not Allowed" });
            return;
        }

        const token = req.body?.idToken ?? req.body?.identityToken;
        if (!token) {
            res.status(400).json({ ok: false, error: "Missing idToken or identityToken" });
            return;
        }

        const decoded = jwt.decode(token, { complete: true }) as jwt.JwtPayload | null;
        if (!decoded?.header?.kid) {
            res.status(401).json({ ok: false, error: "Invalid token format" });
            return;
        }

        const key = await appleJwksClient.getSigningKey(decoded.header.kid);
        const publicKey = key.getPublicKey();

        const payload = jwt.verify(token, publicKey, {
            algorithms: ["RS256"],
            issuer: "https://appleid.apple.com",
            audience: APPLE_CLIENT_IDS,
        }) as jwt.JwtPayload;

        // Apple은 sub가 사용자 고유 ID, email은 선택(최초 1회만 올 수 있음)
        res.json({
            ok: true,
            appleUser: {
                uid: payload.sub,
                email: (payload.email as string) ?? null,
                name: null,  // Apple 토큰에는 없음. 클라이언트에서 최초 인증 시 따로 전달 가능
                picture: null,
            },
            firebaseCustomToken: null,
            error: null,
            details: null,
        });
    } catch (error: any) {
        logger.error("verifyAppleIdToken error:", error);
        res.status(500).json({ ok: false, error: error?.message ?? "Server error" });
    }
});

// ----------------------
// Apple App Store 결제 검증 + 로그 저장
// ----------------------
const APPLE_VERIFY_PROD = "https://buy.itunes.apple.com/verifyReceipt";
const APPLE_VERIFY_SANDBOX = "https://sandbox.itunes.apple.com/verifyReceipt";

async function appleVerifyReceipt(
    receiptData: string,
    useSandbox: boolean
): Promise<{ status: number; receipt?: any; latest_receipt_info?: any[]; in_app?: any[] }> {
    const url = useSandbox ? APPLE_VERIFY_SANDBOX : APPLE_VERIFY_PROD;
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ "receipt-data": receiptData }),
    });
    return (await res.json()) as { status: number; receipt?: any; latest_receipt_info?: any[]; in_app?: any[] };
}

// 일회성 구매만 검증 (구독 미사용 → 공유 시크릿 불필요)
export const verifyApplePurchase = onRequest(async (req, res) => {
    try {
        const { receiptData, productId, accountId } = req.body ?? {};

        if (!receiptData || typeof receiptData !== "string") {
            res.status(400).json({ error: "Missing receiptData (base64)" });
            return;
        }

        const safeAccountId =
            typeof accountId === "string" && accountId.length > 0 ? accountId : "unknown";

        let result = await appleVerifyReceipt(receiptData, false);
        if (result.status === 21007) {
            result = await appleVerifyReceipt(receiptData, true);
        }

        if (result.status !== 0) {
            res.status(400).json({
                ok: false,
                error: "Invalid receipt",
                status: result.status,
                details: result,
            });
            return;
        }

        const receipt = result.receipt ?? {};
        const inApp = receipt.in_app ?? result.latest_receipt_info ?? [];
        const firstTx = Array.isArray(inApp) && inApp.length > 0 ? inApp[0] : null;
        const transactionId = firstTx?.transaction_id ?? firstTx?.original_transaction_id ?? `rev_${Date.now()}`;
        const docId = `apple_${transactionId}`;

        const logRef = db.collection("iap_purchases").doc(docId);
        const now = admin.firestore.FieldValue.serverTimestamp();

        await logRef.set(
            {
                platform: "apple",
                accountId: safeAccountId,
                bundleId: receipt.bundle_id ?? null,
                productId: productId ?? (firstTx?.product_id ?? null),
                transactionId,
                receiptData: receiptData.substring(0, 100) + "...",
                inAppCount: Array.isArray(inApp) ? inApp.length : 0,
                receipt,
                latest_receipt_info: result.latest_receipt_info ?? null,
                verifiedAt: now,
            },
            { merge: true }
        );

        res.json({
            ok: true,
            status: "ok",
            purchase: {
                receipt: result.receipt,
                latest_receipt_info: result.latest_receipt_info,
            },
            logged: true,
            logDocId: docId,
        });
    } catch (error: any) {
        logger.error("verifyApplePurchase error:", error);
        res.status(500).json({ error: "Server error", details: error?.message });
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
                platform: "google",
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