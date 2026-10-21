import { exec, spawn } from 'kernelsu-alt'
import { normalizeScoopTargets, parseScoopTarget } from './package_name'
import {
  ANDROID_SECURITY_BULLETIN_MIRROR_URL,
  ANDROID_SECURITY_BULLETIN_URL,
  isSecurityPatchDate,
} from './security_patch'

const MODULE_ROOT = '/data/adb/modules/oh_my_keymint'
const HOT_UPDATE_ROOT = '/data/adb/omk'
const SUPPORTED_ABIS = ['arm64-v8a', 'x86_64'] as const
type SupportedAbi = typeof SUPPORTED_ABIS[number]
type HelperPaths = { abi: SupportedAbi, inject: string, keymint: string }
const KEYBOX_BASE64_CHUNK_BYTES = 48 * 1024
const MAX_BULLETIN_BYTES = 2 * 1024 * 1024
const MAX_PIF_CATALOG_BYTES = 64 * 1024
const MAX_PIF_STATE_BYTES = 2 * 1024
const MAX_SOTER_HAL_JSON_BYTES = 16 * 1024
const MAX_DIAGNOSTICS_JSON_BYTES = 8 * 1024
const MAX_CLOUD_JSON_BYTES = 8 * 1024
const MAX_KEYBOX_INSPECTOR_JSON_BYTES = 32 * 1024
const MAX_APP_PATCH_LEVELS_JSON_BYTES = 64 * 1024
const MAX_ROOT_OF_TRUST_JSON_BYTES = 4 * 1024
const MAX_WALLPAPER_JSON_BYTES = 4 * 1024
const WALLPAPER_CHUNK_BYTES = 48 * 1024
const WALLPAPER_TOKEN_RE = /^[0-9a-f]{32}$/
const WALLPAPER_URL_RE = /^assets\/wallpaper\/(default\.jpg|custom\.(jpg|png|webp))$/
const WALLPAPER_STORAGE_ROOT = '/storage/emulated/0/'
const MAX_PIF_DEVICES = 64
const MAX_PIF_MODEL_LENGTH = 128
const MAX_PIF_PRODUCT_LENGTH = 128
const MAX_PIF_FINGERPRINT_LENGTH = 1024
const PIF_PRODUCT_RE = /^[a-z0-9][a-z0-9_]*$/

export const MAX_KEYBOX_XML_BYTES = 64 * 1024
export const MAX_WALLPAPER_BYTES = 10 * 1024 * 1024
export const WALLPAPER_EXTENSIONS = ['jpg', 'jpeg', 'png', 'webp'] as const

export interface WallpaperState {
  custom: boolean
  url: string
  bytes: number
  updated_at: number
  max_bytes: number
}

/** Cloud connection state: the mirror keybox feed and the online heartbeat. */
export interface MirrorStatus {
  installed_sha256: string
  installed_source: string
  last_fetch_unix: number
  last_sha256: string
  last_source: string
  last_status: string
  last_error: string
}

export interface OnlineReportStatus {
  module_id: string
  last_report_unix: number
  last_status: string
  last_error: string
  interval_seconds: number
}

export interface CloudStatus {
  mirror: MirrorStatus
  online: OnlineReportStatus
}

export interface MirrorRefreshReport {
  ok: boolean
  applied: boolean
  source: string
  sha256: string
  size: number
  note: string
}

export interface PifDevice {
  model: string
  product: string
}

export interface EnabledPifFingerprintState {
  enabled: true
  model: string
  product: string
  fingerprint: string
  security_patch: string
  device_initial_sdk_int: number
  spoof_build: boolean
  spoof_props: boolean
  spoof_vending_build: boolean
}

export type PifFingerprintState = {
  enabled: false
} | EnabledPifFingerprintState

export type KeyboxSource = 'google_hardware' | 'google_remote' | 'unknown'
export type KeyboxLevel = 'tee' | 'strongbox' | 'unknown'
export interface SoterBetaState {
  enabled: boolean
}
/** Configuration for the Qualcomm Soter HAL relay. */
export interface SoterHalState {
  enabled: boolean
  remote_enabled: boolean
  url: string
  token: string
  device_id: string
  tls_insecure: boolean
  uid_map: string
}
export type PlayIntegrityStatus = 'not_checked'
export type KeyboxRevocationStatus =
  | 'not_checked'
  | 'checking'
  | 'not_listed'
  | 'suspended'
  | 'revoked'
  | 'unknown'

export interface KeyboxState {
  valid: boolean
  bundled: boolean
  source: KeyboxSource
  level: KeyboxLevel
  play_integrity: PlayIntegrityStatus
  revocation: KeyboxRevocationStatus
}

export interface KeyboxChainInspector {
  algorithm: 'RSA' | 'EC'
  chain_length: number
  serials: string[]
  leaf_subject: string
  leaf_issuer: string
  valid_from: string
  valid_until: string
  certificates: KeyboxCertificateInspector[]
}

export interface KeyboxCertificateInspector {
  serial: string
  subject: string
  issuer: string
  valid_from: string
  valid_until: string
}

export interface KeyboxInspector {
  valid: boolean
  bundled: boolean
  rsa: KeyboxChainInspector | null
  ec: KeyboxChainInspector | null
}

export interface AppPatchLevels {
  os_patchlevel: string | null
  vendor_patchlevel: string | null
  boot_patchlevel: string | null
}

export type AppPatchProfiles = Record<string, AppPatchLevels>

export function isAppPatchLevel(value: string | null, boot = false): boolean {
  return value === null || value === 'auto' || isSecurityPatchDate(value)
    || (boot && /^\d+$/.test(value) && Number(value) <= 0xffff_ffff)
}

function parseAppPatchProfiles(output: string): AppPatchProfiles {
  const parsed = parseCanonicalJson(output, 'app patch levels')
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ['app_patch_levels'])
      || !isRecord(parsed.app_patch_levels)) {
    throw new Error('OMK returned invalid app patch levels')
  }
  const profiles = Object.create(null) as AppPatchProfiles
  const fields = ['os_patchlevel', 'vendor_patchlevel', 'boot_patchlevel'] as const
  for (const [target, value] of Object.entries(parsed.app_patch_levels)) {
    const selector = parseScoopTarget(target)
    if (!selector || selector.kind === 'uid' || !isRecord(value)
        || Object.keys(value).some(field => !(fields as readonly string[]).includes(field))) {
      throw new Error('OMK returned an invalid app patch profile')
    }
    const profile: AppPatchLevels = { os_patchlevel: null, vendor_patchlevel: null, boot_patchlevel: null }
    for (const field of fields) {
      const level = value[field]
      if (level === undefined || level === null || level === 'auto') continue
      if (typeof level !== 'string' || !isAppPatchLevel(level, field === 'boot_patchlevel')) {
        throw new Error('OMK returned an invalid app patch level')
      }
      profile[field] = level
    }
    profiles[selector.target] = profile
  }
  return profiles
}

export type ServiceDiagnosticStatus = 'running' | 'stopped' | 'configured' | 'disabled' | 'unknown' | 'available' | 'unavailable' | 'error'

export interface ServiceDiagnostic {
  status: ServiceDiagnosticStatus
  pid: number | null
}

export interface DiagnosticsState {
  keymint: ServiceDiagnostic
  keystore2: ServiceDiagnostic
  injector: ServiceDiagnostic
  soter: ServiceDiagnostic
  tee: HardwareDiagnostic
  strongbox: HardwareDiagnostic
  rkp_tee: ServiceDiagnostic
  rkp_strongbox: ServiceDiagnostic
  selinux: 'enforcing' | 'permissive' | 'unknown'
  rot: RotDiagnostic
}

export interface HardwareDiagnostic {
  status: 'available' | 'unavailable' | 'error'
  version: number | null
  name: string | null
}

export interface RotDiagnostic {
  status: 'ok' | 'drift' | 'unknown'
  mode: string
  pinned: boolean
  drift: boolean
}

// Field order mirrors the Rust serializer so the strict key check stays valid.
export interface RootOfTrustStatus {
  mode: 'pinned' | 'auto'
  vb_key: string
  vb_hash: string
  vb_key_source: string
  vb_hash_source: string
  pinned_in_config: boolean
  drift: boolean
  stamp_present: boolean
  purged_keys: number | null
  restart_required: boolean
  note: string
}

function parseCanonicalJson(output: string, description: string): unknown {
  let parsed: unknown
  try {
    parsed = JSON.parse(output)
  } catch {
    throw new Error(`OMK returned invalid ${description}`)
  }
  if (JSON.stringify(parsed) !== output) {
    throw new Error(`OMK returned non-canonical ${description}`)
  }
  return parsed
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value)
  return keys.length === allowed.length && keys.every((key, index) => key === allowed[index])
}

function isSafeText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maxLength
    && value.trim() === value
    && !/[\u0000-\u001f\u007f]/.test(value)
}

function isPifProduct(value: unknown): value is string {
  return isSafeText(value, MAX_PIF_PRODUCT_LENGTH) && PIF_PRODUCT_RE.test(value)
}

function parsePifDevice(value: unknown): PifDevice {
  if (!isRecord(value)
      || !hasOnlyKeys(value, ['model', 'product'])
      || !isSafeText(value.model, MAX_PIF_MODEL_LENGTH)
      || !isPifProduct(value.product)) {
    throw new Error('OMK returned an invalid PIF device')
  }
  return { model: value.model, product: value.product }
}

function parsePifState(output: string): PifFingerprintState {
  const parsed = parseCanonicalJson(output, 'PIF fingerprint state')
  if (!isRecord(parsed) || typeof parsed.enabled !== 'boolean') {
    throw new Error('OMK returned an invalid PIF fingerprint state')
  }
  if (!parsed.enabled) {
    if (!hasOnlyKeys(parsed, ['enabled'])) {
      throw new Error('OMK returned an invalid disabled PIF fingerprint state')
    }
    return { enabled: false }
  }
  if (!hasOnlyKeys(parsed, [
        'enabled', 'model', 'product', 'fingerprint', 'security_patch',
        'device_initial_sdk_int', 'spoof_build', 'spoof_props', 'spoof_vending_build',
      ])
      || !isSafeText(parsed.model, MAX_PIF_MODEL_LENGTH)
      || !isPifProduct(parsed.product)
      || !isSafeText(parsed.fingerprint, MAX_PIF_FINGERPRINT_LENGTH)
      || !isSafeText(parsed.security_patch, 10)
      || !isSecurityPatchDate(parsed.security_patch)
      || typeof parsed.device_initial_sdk_int !== 'number'
      || !Number.isInteger(parsed.device_initial_sdk_int)
      || parsed.device_initial_sdk_int <= 0
      || parsed.device_initial_sdk_int > 2147483647
      || typeof parsed.spoof_build !== 'boolean'
      || typeof parsed.spoof_props !== 'boolean'
      || typeof parsed.spoof_vending_build !== 'boolean') {
    throw new Error('OMK returned an invalid enabled PIF fingerprint state')
  }
  return {
    enabled: true,
    model: parsed.model,
    product: parsed.product,
    fingerprint: parsed.fingerprint,
    security_patch: parsed.security_patch,
    device_initial_sdk_int: parsed.device_initial_sdk_int,
    spoof_build: parsed.spoof_build,
    spoof_props: parsed.spoof_props,
    spoof_vending_build: parsed.spoof_vending_build,
  }
}

function parseKeyboxState(output: string): KeyboxState {
  const parsed = parseCanonicalJson(output, 'Keybox state')
  if (!isRecord(parsed)
      || !hasOnlyKeys(
        parsed,
        ['valid', 'bundled', 'source', 'level', 'play_integrity', 'revocation'],
      )
      || typeof parsed.valid !== 'boolean'
      || typeof parsed.bundled !== 'boolean'
      || (parsed.source !== 'google_hardware'
        && parsed.source !== 'google_remote'
        && parsed.source !== 'unknown')
      || (parsed.level !== 'tee'
        && parsed.level !== 'strongbox'
        && parsed.level !== 'unknown')
      || parsed.play_integrity !== 'not_checked'
      || (parsed.revocation !== 'not_checked'
        && parsed.revocation !== 'not_listed'
        && parsed.revocation !== 'suspended'
        && parsed.revocation !== 'revoked'
        && parsed.revocation !== 'unknown')
      || (!parsed.valid && parsed.bundled)) {
    throw new Error('OMK returned an invalid Keybox state')
  }
  return {
    valid: parsed.valid,
    bundled: parsed.bundled,
    source: parsed.source,
    level: parsed.level,
    play_integrity: parsed.play_integrity,
    revocation: parsed.revocation,
  }
}

function parseKeyboxChainInspector(value: unknown, algorithm: KeyboxChainInspector['algorithm']): KeyboxChainInspector {
  if (!isRecord(value)
      || !hasOnlyKeys(
        value,
        ['algorithm', 'chain_length', 'serials', 'leaf_subject', 'leaf_issuer', 'valid_from', 'valid_until', 'certificates'],
      )
      || value.algorithm !== algorithm
      || typeof value.chain_length !== 'number'
      || !Number.isSafeInteger(value.chain_length)
      || value.chain_length < 1
      || value.chain_length > 16
      || !Array.isArray(value.serials)
      || value.serials.length !== value.chain_length
      || value.serials.some(serial => !isSafeText(serial, 256))
      || !isSafeText(value.leaf_subject, 2048)
      || !isSafeText(value.leaf_issuer, 2048)
      || !isSafeText(value.valid_from, 128)
      || !isSafeText(value.valid_until, 128)
      || !Array.isArray(value.certificates)
      || value.certificates.length !== value.chain_length
      || value.certificates.some(certificate => {
        if (!isRecord(certificate)
            || !hasOnlyKeys(certificate, ['serial', 'subject', 'issuer', 'valid_from', 'valid_until'])
            || !isSafeText(certificate.serial, 256)
            || !isSafeText(certificate.subject, 2048)
            || !isSafeText(certificate.issuer, 2048)
            || !isSafeText(certificate.valid_from, 128)
            || !isSafeText(certificate.valid_until, 128)) {
          return true
        }
        return false
      })) {
    throw new Error('OMK returned an invalid Keybox certificate chain')
  }
  return {
    algorithm,
    chain_length: value.chain_length,
    serials: value.serials,
    leaf_subject: value.leaf_subject,
    leaf_issuer: value.leaf_issuer,
    valid_from: value.valid_from,
    valid_until: value.valid_until,
    certificates: value.certificates.map(certificate => ({
      serial: certificate.serial as string,
      subject: certificate.subject as string,
      issuer: certificate.issuer as string,
      valid_from: certificate.valid_from as string,
      valid_until: certificate.valid_until as string,
    })),
  }
}

function parseKeyboxInspector(output: string): KeyboxInspector {
  const parsed = parseCanonicalJson(output, 'Keybox inspector')
  if (!isRecord(parsed)
      || !hasOnlyKeys(parsed, ['valid', 'bundled', 'rsa', 'ec'])
      || typeof parsed.valid !== 'boolean'
      || typeof parsed.bundled !== 'boolean'
      || (parsed.rsa !== null && parsed.rsa === undefined)
      || (parsed.ec !== null && parsed.ec === undefined)
      || (!parsed.valid && parsed.bundled)) {
    throw new Error('OMK returned an invalid Keybox inspector')
  }
  const rsa = parsed.rsa === null ? null : parseKeyboxChainInspector(parsed.rsa, 'RSA')
  const ec = parsed.ec === null ? null : parseKeyboxChainInspector(parsed.ec, 'EC')
  return { valid: parsed.valid, bundled: parsed.bundled, rsa, ec }
}

function parseServiceDiagnostic(value: unknown): ServiceDiagnostic {
  if (!isRecord(value)
      || !hasOnlyKeys(value, ['status', 'pid'])
      || (value.status !== 'running'
        && value.status !== 'stopped'
        && value.status !== 'configured'
        && value.status !== 'disabled'
        && value.status !== 'available'
        && value.status !== 'unavailable'
        && value.status !== 'error'
        && value.status !== 'unknown')
      || (value.pid !== null
        && (typeof value.pid !== 'number' || !Number.isSafeInteger(value.pid) || value.pid < 1))) {
    throw new Error('OMK returned an invalid service diagnostic')
  }
  return { status: value.status, pid: value.pid }
}

function parseHardwareDiagnostic(value: unknown): HardwareDiagnostic {
  if (!isRecord(value)
      || !hasOnlyKeys(value, ['status', 'version', 'name'])
      || (value.status !== 'available' && value.status !== 'unavailable' && value.status !== 'error')
      || (value.version !== null && (typeof value.version !== 'number' || !Number.isSafeInteger(value.version) || value.version < 0))
      || (value.name !== null && !isSafeText(value.name, 512))) {
    throw new Error('OMK returned an invalid hardware diagnostic')
  }
  return { status: value.status, version: value.version, name: value.name }
}

function parseDiagnostics(output: string): DiagnosticsState {
  const parsed = parseCanonicalJson(output, 'service diagnostics')
  if (!isRecord(parsed)
      || !hasOnlyKeys(parsed, ['keymint', 'keystore2', 'injector', 'soter', 'tee', 'strongbox', 'rkp_tee', 'rkp_strongbox', 'selinux', 'rot'])
      || (parsed.selinux !== 'enforcing' && parsed.selinux !== 'permissive' && parsed.selinux !== 'unknown')) {
    throw new Error('OMK returned invalid service diagnostics')
  }
  return {
    keymint: parseServiceDiagnostic(parsed.keymint),
    keystore2: parseServiceDiagnostic(parsed.keystore2),
    injector: parseServiceDiagnostic(parsed.injector),
    soter: parseServiceDiagnostic(parsed.soter),
    tee: parseHardwareDiagnostic(parsed.tee),
    strongbox: parseHardwareDiagnostic(parsed.strongbox),
    rkp_tee: parseServiceDiagnostic(parsed.rkp_tee),
    rkp_strongbox: parseServiceDiagnostic(parsed.rkp_strongbox),
    selinux: parsed.selinux,
    rot: parseRotDiagnostic(parsed.rot),
  }
}

function parseRotDiagnostic(value: unknown): RotDiagnostic {
  if (!isRecord(value)
      || !hasOnlyKeys(value, ['status', 'mode', 'pinned', 'drift'])
      || (value.status !== 'ok' && value.status !== 'drift' && value.status !== 'unknown')
      || !isSafeTextOrEmpty(value.mode, 32)
      || typeof value.pinned !== 'boolean'
      || typeof value.drift !== 'boolean') {
    throw new Error('OMK returned an invalid root of trust diagnostic')
  }
  return { status: value.status, mode: value.mode, pinned: value.pinned, drift: value.drift }
}

function parseCloudStatus(output: string): CloudStatus {
  const parsed = parseCanonicalJson(output, 'cloud status')
  if (!isRecord(parsed)
      || !hasOnlyKeys(parsed, ['mirror', 'online'])
      || !isRecord(parsed.mirror)
      || !hasOnlyKeys(parsed.mirror, [
        'installed_sha256', 'installed_source', 'last_fetch_unix', 'last_sha256',
        'last_source', 'last_status', 'last_error',
      ])
      || !isHexDigestOrEmpty(parsed.mirror.installed_sha256)
      || !isSafeTextOrEmpty(parsed.mirror.installed_source, 32)
      || typeof parsed.mirror.last_fetch_unix !== 'number'
      || !Number.isSafeInteger(parsed.mirror.last_fetch_unix)
      || parsed.mirror.last_fetch_unix < 0
      || !isHexDigestOrEmpty(parsed.mirror.last_sha256)
      || !isSafeTextOrEmpty(parsed.mirror.last_source, 32)
      || !isSafeTextOrEmpty(parsed.mirror.last_status, 32)
      || !isSafeTextOrEmpty(parsed.mirror.last_error, 512)
      || !isRecord(parsed.online)
      || !hasOnlyKeys(parsed.online, [
        'module_id', 'last_report_unix', 'last_status', 'last_error', 'interval_seconds',
      ])
      || !isSafeTextOrEmpty(parsed.online.module_id, 64)
      || typeof parsed.online.last_report_unix !== 'number'
      || !Number.isSafeInteger(parsed.online.last_report_unix)
      || parsed.online.last_report_unix < 0
      || !isSafeTextOrEmpty(parsed.online.last_status, 32)
      || !isSafeTextOrEmpty(parsed.online.last_error, 512)
      || typeof parsed.online.interval_seconds !== 'number'
      || !Number.isSafeInteger(parsed.online.interval_seconds)
      || parsed.online.interval_seconds < 0) {
    throw new Error('OMK returned an invalid cloud status')
  }
  return {
    mirror: {
      installed_sha256: parsed.mirror.installed_sha256 as string,
      installed_source: parsed.mirror.installed_source as string,
      last_fetch_unix: parsed.mirror.last_fetch_unix as number,
      last_sha256: parsed.mirror.last_sha256 as string,
      last_source: parsed.mirror.last_source as string,
      last_status: parsed.mirror.last_status as string,
      last_error: parsed.mirror.last_error as string,
    },
    online: {
      module_id: parsed.online.module_id as string,
      last_report_unix: parsed.online.last_report_unix as number,
      last_status: parsed.online.last_status as string,
      last_error: parsed.online.last_error as string,
      interval_seconds: parsed.online.interval_seconds as number,
    },
  }
}

function parseMirrorRefreshReport(output: string): MirrorRefreshReport {
  const parsed = parseCanonicalJson(output, 'mirror refresh report')
  if (!isRecord(parsed)
      || !hasOnlyKeys(parsed, ['ok', 'applied', 'source', 'sha256', 'size', 'note'])
      || typeof parsed.ok !== 'boolean'
      || typeof parsed.applied !== 'boolean'
      || !isSafeTextOrEmpty(parsed.source, 32)
      || !isHexDigestOrEmpty(parsed.sha256)
      || typeof parsed.size !== 'number'
      || !Number.isSafeInteger(parsed.size)
      || parsed.size < 0
      || !isSafeTextOrEmpty(parsed.note, 512)) {
    throw new Error('OMK returned an invalid mirror refresh report')
  }
  return {
    ok: parsed.ok,
    applied: parsed.applied,
    source: parsed.source as string,
    sha256: parsed.sha256 as string,
    size: parsed.size as number,
    note: parsed.note as string,
  }
}

function isHexDigestOrEmpty(value: unknown): boolean {
  return value === '' || isHexDigest(value, 64)
}

function isHexDigest(value: unknown, length: number): value is string {
  return typeof value === 'string'
    && value.length === length
    && /^[0-9a-f]+$/.test(value)
}

function parseRootOfTrust(output: string, description: string): RootOfTrustStatus {
  const parsed = parseCanonicalJson(output, description)
  if (!isRecord(parsed)
      || !hasOnlyKeys(parsed, [
        'mode', 'vb_key', 'vb_hash', 'vb_key_source', 'vb_hash_source',
        'pinned_in_config', 'drift', 'stamp_present', 'purged_keys', 'restart_required', 'note',
      ])
      || (parsed.mode !== 'pinned' && parsed.mode !== 'auto')
      || !isHexDigest(parsed.vb_key, 64)
      || !isHexDigest(parsed.vb_hash, 64)
      || !isSafeTextOrEmpty(parsed.vb_key_source, 64)
      || !isSafeTextOrEmpty(parsed.vb_hash_source, 64)
      || typeof parsed.pinned_in_config !== 'boolean'
      || typeof parsed.drift !== 'boolean'
      || typeof parsed.stamp_present !== 'boolean'
      || (parsed.purged_keys !== null
        && (typeof parsed.purged_keys !== 'number' || !Number.isSafeInteger(parsed.purged_keys) || parsed.purged_keys < 0))
      || typeof parsed.restart_required !== 'boolean'
      || typeof parsed.note !== 'string'
      || parsed.note.length > 512
      || /[\u0000-\u001f\u007f]/.test(parsed.note)) {
    throw new Error(`OMK returned an invalid ${description}`)
  }
  return {
    mode: parsed.mode,
    vb_key: parsed.vb_key,
    vb_hash: parsed.vb_hash,
    vb_key_source: parsed.vb_key_source,
    vb_hash_source: parsed.vb_hash_source,
    pinned_in_config: parsed.pinned_in_config,
    drift: parsed.drift,
    stamp_present: parsed.stamp_present,
    purged_keys: parsed.purged_keys,
    restart_required: parsed.restart_required,
    note: parsed.note,
  }
}

function parseWallpaperState(output: string, description: string): WallpaperState {
  const parsed = parseCanonicalJson(output, description)
  if (!isRecord(parsed)
      || !hasOnlyKeys(parsed, ['custom', 'url', 'bytes', 'updated_at', 'max_bytes'])
      || typeof parsed.custom !== 'boolean'
      || typeof parsed.url !== 'string'
      || !WALLPAPER_URL_RE.test(parsed.url)
      || typeof parsed.bytes !== 'number'
      || !Number.isSafeInteger(parsed.bytes)
      || parsed.bytes < 0
      || parsed.bytes > MAX_WALLPAPER_BYTES
      || typeof parsed.updated_at !== 'number'
      || !Number.isSafeInteger(parsed.updated_at)
      || parsed.updated_at < 0
      || parsed.max_bytes !== MAX_WALLPAPER_BYTES) {
    throw new Error(`OMK returned invalid ${description}`)
  }
  if (parsed.custom !== (parsed.url !== 'assets/wallpaper/default.jpg')) {
    throw new Error(`OMK returned inconsistent ${description}`)
  }
  return parsed as unknown as WallpaperState
}

function validateWallpaperStoragePath(path: string): string {
  if (!path.startsWith(WALLPAPER_STORAGE_ROOT)
      || path.length > 4096
      || /[\u0000-\u001f\u007f]/.test(path)
      || path.includes('//')
      || path.split('/').some(part => part === '.' || part === '..')) {
    throw new Error('The wallpaper must be chosen from shared storage')
  }
  const extension = path.slice(path.lastIndexOf('.') + 1).toLowerCase()
  if (!(WALLPAPER_EXTENSIONS as readonly string[]).includes(extension)) {
    throw new Error('The wallpaper must be a JPG, PNG or WebP image')
  }
  return path
}

function isSafeTextOrEmpty(value: unknown, maxLength: number): value is string {
  return typeof value === 'string'
    && value.length <= maxLength
    && value.trim() === value
    && !/[\u0000-\u001f\u007f]/.test(value)
}

function encodeBase64Bytes(bytes: Uint8Array): string {
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return btoa(binary)
}

function encodeBase64Utf8(value: string): string {
  return encodeBase64Bytes(new TextEncoder().encode(value))
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function normalizeAbiToken(value: string): SupportedAbi | null {
  switch (value.trim()) {
    case 'arm64-v8a':
    case 'aarch64':
      return 'arm64-v8a'
    case 'x86_64':
    case 'amd64':
      return 'x86_64'
    default:
      return null
  }
}

function parseSupportedAbi(output: string): SupportedAbi | null {
  const tokens = output.split(/[\s,]+/).filter(Boolean)
  for (const token of tokens) {
    const abi = normalizeAbiToken(token)
    if (abi !== null) return abi
  }
  return null
}

export class Cli {
  #helperPaths: Promise<HelperPaths> | null = null

  async getAppPatchLevels(): Promise<AppPatchProfiles> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-app-patch-levels'], MAX_APP_PATCH_LEVELS_JSON_BYTES)
    return parseAppPatchProfiles(output)
  }

  async setAppPatchLevels(target: string, levels: AppPatchLevels): Promise<void> {
    const selector = parseScoopTarget(target)
    if (!selector || selector.kind === 'uid'
        || !isAppPatchLevel(levels.os_patchlevel)
        || !isAppPatchLevel(levels.vendor_patchlevel)
        || !isAppPatchLevel(levels.boot_patchlevel, true)) {
      throw new Error('Invalid app patch-level configuration')
    }
    const effective: AppPatchLevels = {
      os_patchlevel: levels.os_patchlevel === 'auto' ? null : levels.os_patchlevel,
      vendor_patchlevel: levels.vendor_patchlevel === 'auto' ? null : levels.vendor_patchlevel,
      boot_patchlevel: levels.boot_patchlevel === 'auto' ? null : levels.boot_patchlevel,
    }
    const payload = encodeBase64Utf8(JSON.stringify({ target: selector.target, ...effective }))
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-set-app-patch-levels-base64', payload], 256)
    if (output !== 'app_patch_levels_saved') throw new Error('OMK returned an unexpected app patch result')
    const profiles = await this.getAppPatchLevels()
    if (JSON.stringify(profiles[selector.target]) !== JSON.stringify(effective)) {
      throw new Error('App patch-level configuration read-back did not match the saved values')
    }
  }

  async getScoop(): Promise<string[]> {
    const output = await this.#runInject(['--webui-get-scoop'])
    let parsed: unknown
    try {
      parsed = JSON.parse(output)
    } catch {
      throw new Error('OMK returned an invalid package list')
    }
    return normalizeScoopTargets(parsed)
  }

  async setScoop(packages: string[]): Promise<void> {
    const normalized = normalizeScoopTargets(packages)
    const payload = encodeBase64Utf8(JSON.stringify(normalized))
    await this.#runInject(['--webui-set-scoop', payload])
  }

  async installKeybox(contents: Uint8Array): Promise<void> {
    if (contents.byteLength > MAX_KEYBOX_XML_BYTES) {
      throw new Error(`keybox.xml exceeds the ${MAX_KEYBOX_XML_BYTES} byte limit`)
    }

    const payload = encodeBase64Bytes(contents)
    const chunks: string[] = []
    for (let offset = 0; offset < payload.length; offset += KEYBOX_BASE64_CHUNK_BYTES) {
      chunks.push(payload.slice(offset, offset + KEYBOX_BASE64_CHUNK_BYTES))
    }
    const { keymint } = await this.#getHelperPaths()
    await this.#run(keymint, ['--webui-install-keybox', ...chunks])
  }

  async getKeyboxState(): Promise<KeyboxState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-keybox-state'], 256)
    return parseKeyboxState(output)
  }

  async getKeyboxInspector(): Promise<KeyboxInspector> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-get-keybox-inspector'],
      MAX_KEYBOX_INSPECTOR_JSON_BYTES,
    )
    return parseKeyboxInspector(output)
  }

  async getDiagnostics(): Promise<DiagnosticsState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-diagnostics'], MAX_DIAGNOSTICS_JSON_BYTES)
    return parseDiagnostics(output)
  }

  async getCloudStatus(): Promise<CloudStatus> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-cloud-status'], MAX_CLOUD_JSON_BYTES)
    return parseCloudStatus(output)
  }

  async refreshMirrorKeybox(): Promise<MirrorRefreshReport> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-refresh-mirror-keybox'],
      MAX_CLOUD_JSON_BYTES,
    )
    return parseMirrorRefreshReport(output)
  }

  async checkKeyboxRevocation(): Promise<KeyboxRevocationStatus> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-check-keybox-revocation'], 256)
    if (output !== 'not_listed' && output !== 'suspended' && output !== 'revoked') {
      throw new Error('OMK returned an invalid Keybox revocation status')
    }
    return output
  }

  async getSoterBeta(): Promise<SoterBetaState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-soter-beta'], 256)
    const parsed = parseCanonicalJson(output, 'Soter Beta state')
    if (!isRecord(parsed)
        || !hasOnlyKeys(parsed, ['enabled'])
        || typeof parsed.enabled !== 'boolean') {
      throw new Error('OMK returned invalid Soter Beta state')
    }
    return { enabled: parsed.enabled }
  }

  async setSoterBeta(enabled: boolean): Promise<void> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-set-soter-beta', enabled ? '1' : '0'], 256)
    if (output !== 'soter_beta_saved') {
      throw new Error('OMK returned an unexpected Soter Beta result')
    }
  }

  async getSoterHal(): Promise<SoterHalState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-soter-hal'], MAX_SOTER_HAL_JSON_BYTES + 1)
    const parsed = parseCanonicalJson(output, 'Soter HAL state')
    if (!isRecord(parsed)
        || !hasOnlyKeys(parsed, ['enabled', 'remote_enabled', 'url', 'token', 'device_id', 'tls_insecure', 'uid_map'])
        || typeof parsed.enabled !== 'boolean'
        || typeof parsed.remote_enabled !== 'boolean'
        || typeof parsed.url !== 'string'
        || typeof parsed.token !== 'string'
        || typeof parsed.device_id !== 'string'
        || typeof parsed.tls_insecure !== 'boolean'
        || typeof parsed.uid_map !== 'string') {
      throw new Error('OMK returned invalid Soter HAL state')
    }
    return parsed as unknown as SoterHalState
  }

  async setSoterHal(state: SoterHalState): Promise<void> {
    const { keymint } = await this.#getHelperPaths()
    // Relay identity is only what the user configured; the native save
    // validates and stores it verbatim, so the mandatory read-back check
    // compares the saved values directly.
    const json = JSON.stringify(state)
    if (new TextEncoder().encode(json).byteLength > MAX_SOTER_HAL_JSON_BYTES) {
      throw new Error('Soter HAL configuration exceeds the byte limit')
    }
    // KernelSU runs spawn arguments through a shell. Encode structured data
    // just like the package-list and activity helpers so JSON stays one arg.
    const payload = encodeBase64Utf8(json)
    const output = await this.#run(keymint, ['--webui-set-soter-hal-base64', payload], 256)
    if (output !== 'soter_hal_saved') {
      throw new Error('OMK returned an unexpected Soter HAL result')
    }
    const persisted = await this.getSoterHal()
    if (JSON.stringify(persisted) !== json) {
      throw new Error('Soter HAL configuration read-back did not match the saved values')
    }
  }

  async getWallpaper(): Promise<WallpaperState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-wallpaper'], MAX_WALLPAPER_JSON_BYTES)
    return parseWallpaperState(output, 'wallpaper state')
  }

  async resetWallpaper(): Promise<WallpaperState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-reset-wallpaper'], MAX_WALLPAPER_JSON_BYTES)
    return parseWallpaperState(output, 'wallpaper reset result')
  }

  async installWallpaperFromStorage(path: string): Promise<WallpaperState> {
    const source = validateWallpaperStoragePath(path)
    const { keymint } = await this.#getHelperPaths()
    // KernelSU runs spawn arguments through a shell, so the storage path
    // travels as one base64 argument instead of a raw pathname.
    const output = await this.#run(
      keymint,
      ['--webui-install-wallpaper-base64', encodeBase64Utf8(source)],
      MAX_WALLPAPER_JSON_BYTES,
    )
    return parseWallpaperState(output, 'wallpaper install result')
  }

  async installWallpaper(contents: Uint8Array): Promise<WallpaperState> {
    if (contents.byteLength < 1 || contents.byteLength > MAX_WALLPAPER_BYTES) {
      throw new Error(`The wallpaper must be between 1 byte and ${MAX_WALLPAPER_BYTES} bytes`)
    }
    const { keymint } = await this.#getHelperPaths()
    const token = await this.#run(keymint, ['--webui-stage-wallpaper'], 64)
    if (!WALLPAPER_TOKEN_RE.test(token)) {
      throw new Error('OMK returned an invalid wallpaper upload token')
    }
    // One command argument cannot carry a picture, so the base64 stream travels as
    // sequential chunks bound to the single-use token.
    const payload = encodeBase64Bytes(contents)
    for (let offset = 0; offset < payload.length; offset += WALLPAPER_CHUNK_BYTES) {
      const chunk = payload.slice(offset, offset + WALLPAPER_CHUNK_BYTES)
      const accepted = await this.#run(
        keymint,
        ['--webui-stage-wallpaper-append', token, chunk],
        64,
      )
      if (accepted !== 'wallpaper_chunk_accepted') {
        throw new Error('OMK did not accept the wallpaper upload chunk')
      }
    }
    const output = await this.#run(
      keymint,
      ['--webui-install-staged-wallpaper', token],
      MAX_WALLPAPER_JSON_BYTES,
    )
    return parseWallpaperState(output, 'wallpaper install result')
  }

  async syncSecurityPatch(date: string): Promise<string> {
    if (!isSecurityPatchDate(date)) {
      throw new Error('Invalid security-patch date')
    }

    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-sync-security-patch', date])
    const firstDayFallback = date.endsWith('-05') ? `${date.slice(0, 8)}01` : null
    if (output !== date && output !== firstDayFallback) {
      throw new Error('OMK returned an unexpected security-patch date')
    }
    return output
  }

  async restoreDefaultSecurityPatch(): Promise<void> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-sync-security-patch', 'auto'])
    if (output !== 'auto') {
      throw new Error('OMK returned an unexpected security-patch mode')
    }
  }

  async getSystemSecurityPatch(): Promise<string> {
    let probe: Awaited<ReturnType<typeof exec>>
    try {
      probe = await exec(
        `/system/bin/sh -c ${shellQuote('/system/bin/getprop ro.build.version.security_patch')}`,
      )
    } catch (error) {
      throw new Error(`Unable to read the system security patch: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (probe.errno !== 0) {
      throw new Error(
        `Unable to read the system security patch: ${probe.stderr.trim() || `shell exited with code ${probe.errno}`}`,
      )
    }

    const patch = probe.stdout.trim()
    if (!isSecurityPatchDate(patch)) {
      throw new Error('Android returned an invalid system security-patch date')
    }
    return patch
  }

  async getModuleName(): Promise<string> {
    let probe: Awaited<ReturnType<typeof exec>>
    try {
      probe = await exec(
        `/system/bin/sh -c ${shellQuote(`/system/bin/cat ${shellQuote(`${MODULE_ROOT}/module.prop`)}`)}`,
      )
    } catch (error) {
      throw new Error(`Unable to read module.prop: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (probe.errno !== 0) {
      throw new Error(
        `Unable to read module.prop: ${probe.stderr.trim() || `shell exited with code ${probe.errno}`}`,
      )
    }

    const name = probe.stdout
      .split('\n')
      .find((line) => line.startsWith('name='))
      ?.slice('name='.length)
      .trim()
    if (!name) {
      throw new Error('module.prop has no module name')
    }
    return name
  }

  async getTeeStatus(): Promise<void> {
    const output = await this.#runInject(['--webui-get-tee-status'])
    if (output !== 'normal') {
      throw new Error('OMK returned an unexpected TEE status')
    }
  }

  async fetchSecurityBulletin(): Promise<string> {
    let lastError: Error | null = null
    for (const url of [ANDROID_SECURITY_BULLETIN_URL, ANDROID_SECURITY_BULLETIN_MIRROR_URL]) {
      try {
        const { keymint } = await this.#getHelperPaths()
        return await this.#run(
          keymint,
          ['--webui-fetch-security-bulletin', url],
          MAX_BULLETIN_BYTES + 1024,
        )
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))
      }
    }
    throw new Error(`Unable to download the Android Security Bulletin: ${lastError?.message ?? 'network request failed'}`)
  }

  async getPifFingerprintState(): Promise<PifFingerprintState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-get-pif-fingerprint-state'],
      MAX_PIF_STATE_BYTES,
    )
    return parsePifState(output)
  }

  async listPifDevices(): Promise<PifDevice[]> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-list-pif-devices'],
      MAX_PIF_CATALOG_BYTES,
    )
    const parsed = parseCanonicalJson(output, 'PIF device catalog')
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > MAX_PIF_DEVICES) {
      throw new Error('OMK returned an invalid PIF device catalog')
    }

    const devices = parsed.map(parsePifDevice)
    if (new Set(devices.map(device => device.product)).size !== devices.length) {
      throw new Error('OMK returned duplicate PIF products')
    }
    return devices
  }

  async applyPifFingerprint(
    product: string,
    spoofBuild = true,
    spoofProps = true,
    spoofVendingBuild = false,
  ): Promise<EnabledPifFingerprintState> {
    if (!isPifProduct(product)) throw new Error('Invalid PIF product')
    if (typeof spoofBuild !== 'boolean' || typeof spoofProps !== 'boolean'
        || typeof spoofVendingBuild !== 'boolean') {
      throw new Error('Invalid PIF spoofing options')
    }
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      [
        '--webui-apply-pif-fingerprint', product,
        spoofBuild ? '1' : '0', spoofProps ? '1' : '0', spoofVendingBuild ? '1' : '0',
      ],
      MAX_PIF_STATE_BYTES,
    )
    const state = parsePifState(output)
    if (!state.enabled || state.product !== product
        || state.spoof_build !== spoofBuild || state.spoof_props !== spoofProps
        || state.spoof_vending_build !== spoofVendingBuild) {
      throw new Error('OMK returned an unexpected PIF fingerprint state')
    }
    return state
  }

  async disablePifFingerprint(): Promise<PifFingerprintState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-disable-pif-fingerprint'],
      MAX_PIF_STATE_BYTES,
    )
    const state = parsePifState(output)
    if (state.enabled) throw new Error('OMK did not disable PIF fingerprint spoofing')
    return state
  }

  async getRootOfTrust(): Promise<RootOfTrustStatus> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-get-rot-status'], MAX_ROOT_OF_TRUST_JSON_BYTES)
    return parseRootOfTrust(output, 'root of trust status')
  }

  async repinRootOfTrust(purge: boolean): Promise<RootOfTrustStatus> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-repin-rot', purge ? '1' : '0'],
      MAX_ROOT_OF_TRUST_JSON_BYTES,
    )
    return parseRootOfTrust(output, 'root of trust result')
  }

  async #runInject(args: string[]): Promise<string> {
    const { inject } = await this.#getHelperPaths()
    return this.#run(inject, args)
  }

  async #getHelperPaths(): Promise<HelperPaths> {
    if (this.#helperPaths !== null) return this.#helperPaths

    const pending = this.#detectHelperPaths()
    this.#helperPaths = pending.catch(error => {
      this.#helperPaths = null
      throw error
    })
    return this.#helperPaths
  }

  async #detectHelperPaths(): Promise<HelperPaths> {
    let abiProbe: Awaited<ReturnType<typeof exec>>
    try {
      abiProbe = await exec(
        `/system/bin/sh -c ${shellQuote('/system/bin/getprop ro.product.cpu.abilist; /system/bin/getprop ro.product.cpu.abi; /system/bin/uname -m 2>/dev/null || :')}`,
      )
    } catch (error) {
      throw new Error(`Unable to detect the Android ABI: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (abiProbe.errno !== 0) {
      throw new Error(
        `Unable to detect the Android ABI: ${abiProbe.stderr.trim() || `shell exited with code ${abiProbe.errno}`}`,
      )
    }

    const abi = parseSupportedAbi(abiProbe.stdout)
    if (abi === null) {
      throw new Error('Unsupported Android ABI: OMK provides arm64-v8a and x86_64 binaries')
    }

    const roots = [`${MODULE_ROOT}/libs/${abi}`, HOT_UPDATE_ROOT]
    for (const root of roots) {
      const inject = `${root}/inject`
      const keymint = `${root}/keymint`
      const check = await exec(
        `/system/bin/sh -c ${shellQuote(`[ -x ${shellQuote(inject)} ] && [ -x ${shellQuote(keymint)} ]`)}`,
      )
      if (check.errno === 0) return { abi, inject, keymint }
    }

    throw new Error(`OMK ${abi} helper binaries are not installed`)
  }

  #run(binary: string, args: string[], maxOutputBytes = Number.POSITIVE_INFINITY): Promise<string> {
    return new Promise((resolve, reject) => {
      let stdout = ''
      let stderr = ''
      let stdoutBytes = 0
      let stderrBytes = 0
      let outputTooLarge = false
      let settled = false
      const process = spawn(binary, args)

      process.stdout.on('data', (chunk: string) => {
        if (outputTooLarge) return
        stdoutBytes += new TextEncoder().encode(chunk).byteLength
        if (stdoutBytes > maxOutputBytes) {
          outputTooLarge = true
          return
        }
        stdout += chunk
      })
      process.stderr.on('data', (chunk: string) => {
        if (stderrBytes >= 8192) return
        const remaining = 8192 - stderrBytes
        const encoded = new TextEncoder().encode(chunk)
        stderrBytes += encoded.byteLength
        stderr += new TextDecoder().decode(encoded.subarray(0, remaining))
      })
      process.on('exit', (code: number | null) => {
        if (settled) return
        settled = true
        if (outputTooLarge) {
          reject(new Error('command output exceeds the configured limit'))
        } else if (code === 0) {
          resolve(stdout.trim())
        } else {
          reject(new Error(stderr.trim() || `OMK helper exited with code ${code ?? 'unknown'}`))
        }
      })
      process.on('error', (error: Error) => {
        if (settled) return
        settled = true
        reject(new Error(`Unable to run the OMK helper: ${error.message}`))
      })
    })
  }
}
