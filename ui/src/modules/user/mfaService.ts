import { apiDelete, apiGet, apiPost } from "@/modules/api/apiWrapper";
import { ApiResponse } from "@/modules/api/types";

// MFA Status and Methods
export interface MfaMethod {
  id: string;
  type: "TOTP" | "WEBAUTHN";
  name: string;
  createdAt: string;
}

export interface MfaStatus {
  mfaEnabled: boolean;
  methods: MfaMethod[];
  backupCodesRemaining: number;
}

// TOTP Interfaces
export interface TotpSetupResponse {
  secretUri: string;
}

export interface TotpVerifyRequest {
  code: string;
}

// WebAuthn Interfaces
export interface WebAuthnRegisterOptions {
  challenge: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{
    type: string;
    alg: number;
  }>;
  timeout: number;
  attestation: string;
}

export interface WebAuthnCredential {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface WebAuthnAuthOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  userVerification: string;
  allowCredentials: Array<{
    type: string;
    id: string;
  }>;
}

export interface BackupCode {
  code: string;
  used: boolean;
}

export interface BackupCodesResponse {
  codes: string[];
}

export interface BackupCodesCountResponse {
  count: number;
}

// Service Methods
async function getMfaStatus(): Promise<ApiResponse<MfaStatus>> {
  return await apiGet("/mfa/v1/status");
}

async function setupTotp(): Promise<ApiResponse<TotpSetupResponse>> {
  return await apiPost("/mfa/v1/totp/setup", {});
}

async function verifyTotp(code: string): Promise<ApiResponse<void>> {
  return await apiPost("/mfa/v1/totp/verify", { code });
}

async function deleteTotp(): Promise<ApiResponse<void>> {
  return await apiDelete("/mfa/v1/totp");
}

async function getWebAuthnRegisterOptions(): Promise<ApiResponse<WebAuthnRegisterOptions>> {
  return await apiPost("/mfa/v1/webauthn/register/options", {});
}

async function verifyWebAuthnRegistration(credential: object): Promise<ApiResponse<void>> {
  return await apiPost("/mfa/v1/webauthn/register/verify", credential);
}

async function listWebAuthnCredentials(): Promise<ApiResponse<WebAuthnCredential[]>> {
  return await apiGet("/mfa/v1/webauthn/credentials");
}

async function deleteWebAuthnCredential(id: string): Promise<ApiResponse<void>> {
  return await apiDelete(`/mfa/v1/webauthn/credentials/${id}`);
}

async function getWebAuthnAuthOptions(): Promise<ApiResponse<WebAuthnAuthOptions>> {
  return await apiPost("/mfa/v1/webauthn/authenticate/options", {});
}

async function verifyWebAuthnAuth(assertion: object): Promise<ApiResponse<void>> {
  return await apiPost("/mfa/v1/webauthn/authenticate/verify", assertion);
}

async function generateBackupCodes(): Promise<ApiResponse<BackupCodesResponse>> {
  return await apiPost("/mfa/v1/backup-codes/generate", {});
}

async function verifyBackupCode(code: string): Promise<ApiResponse<void>> {
  return await apiPost("/mfa/v1/backup-codes/verify", { code });
}

async function getBackupCodesCount(): Promise<ApiResponse<BackupCodesCountResponse>> {
  return await apiGet("/mfa/v1/backup-codes/count");
}
async function getBackupCodes(): Promise<ApiResponse<BackupCode[]>> {
  return await apiGet("/mfa/v1/backup-codes");
}

const methods = {
  getMfaStatus,
  setupTotp,
  verifyTotp,
  deleteTotp,
  getWebAuthnRegisterOptions,
  verifyWebAuthnRegistration,
  listWebAuthnCredentials,
  deleteWebAuthnCredential,
  getWebAuthnAuthOptions,
  verifyWebAuthnAuth,
  generateBackupCodes,
  verifyBackupCode,
  getBackupCodesCount,
  getBackupCodes,
};

export default methods;
