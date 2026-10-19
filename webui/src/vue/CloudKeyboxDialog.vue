<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  MiuixButton,
  MiuixCard,
  MiuixDialog,
  MiuixInput,
  MiuixProgressIndicator,
  MiuixSmallTitle,
  MiuixSwitchPreference,
} from 'miuix-vue'
import {
  Cli,
  type CloudKeyboxStatus,
  type RootOfTrustStatus,
} from '../cli'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

const props = defineProps<{ modelValue: boolean, cli: Cli }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  notify: [message: string, error?: boolean]
  changed: []
}>()

const preview = isDev()
const PREVIEW_STATUS: CloudKeyboxStatus = {
  enabled: false,
  base_url: 'https://omk.5ijxa.com/api/omk',
  auto_fetch: false,
  fetch_interval_hours: 24,
  verify_signature: true,
  require_valid: true,
  min_days_remaining: 7,
  trusted_pubkey: 'builtin',
  last_fetch_unix: 0,
  last_sha256: '',
  last_source: '',
  last_status: '',
  last_error: '',
  installed_sha256: '',
  cloud: 'disabled',
  cloud_error: '',
  server_version: '',
  next_source: '',
  next_sha256: '',
  next_size: 0,
  next_level: '',
  next_ok: false,
  next_days_remaining: -1,
  next_min_not_after: '',
  rotation_enabled: false,
  rotation_pool_size: 0,
  rotation_current_index: 0,
  is_current: false,
  notice: [],
}
const PREVIEW_ROT: RootOfTrustStatus = {
  mode: 'auto',
  vb_key: '0'.repeat(64),
  vb_hash: '0'.repeat(64),
  vb_key_source: 'live',
  vb_hash_source: 'live',
  pinned_in_config: false,
  drift: false,
  stamp_present: false,
  purged_keys: null,
  restart_required: false,
  note: '',
}

const status = ref<'loading' | 'ready' | 'error'>('loading')
const errorMessage = ref('')
const busy = ref<'load' | 'settings' | 'fetch' | 'repin' | null>(null)
const cloud = ref<CloudKeyboxStatus | null>(null)
const rot = ref<RootOfTrustStatus | null>(null)
const enabled = ref(false)
const autoFetch = ref(false)
const verifySignature = ref(true)
const baseUrl = ref('')
const pubkey = ref('')
const purgeKeys = ref(true)
// Single-point trigger: every time the dialog opens the cycle starts at step 1.
// Step 1 fetches and replaces the Keybox, step 2 checks for a cloud update and
// applies it when one exists, step 3 fetches the second Keybox. Not persisted.
const step = ref<1 | 2 | 3>(1)
const operationMessage = ref('')
let generation = 0

function tr(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const settingsDirty = computed(() => {
  const current = cloud.value
  if (current === null) return false
  return current.enabled !== enabled.value
    || current.auto_fetch !== autoFetch.value
    || current.verify_signature !== verifySignature.value
    || current.base_url !== baseUrl.value.trim()
    || pubkey.value.trim() !== ''
})

const canSaveSettings = computed(() => !preview
  && busy.value === null
  && status.value === 'ready'
  && settingsDirty.value
  && /^https:\/\/[^\s]+$/.test(baseUrl.value.trim()))

const canFetch = computed(() => !preview
  && busy.value === null
  && status.value === 'ready'
  && cloud.value?.enabled === true)

const canRepin = computed(() => !preview && busy.value === null && status.value === 'ready')

const cloudBadge = computed(() => {
  const value = cloud.value
  if (value === null) return { key: '', text: '' }
  if (!value.enabled) return { key: 'off', text: tr('cloud_keybox_state_off', 'Disabled') }
  if (value.cloud === 'connected') return { key: 'ok', text: tr('cloud_keybox_state_connected', 'Connected') }
  if (value.cloud === 'unreachable') {
    return { key: 'bad', text: tr('cloud_keybox_state_unreachable', 'Unreachable') }
  }
  return { key: 'off', text: tr('cloud_keybox_state_off', 'Disabled') }
})

const rotBadge = computed(() => {
  const value = rot.value
  if (value === null) return { key: '', text: '' }
  if (value.mode === 'pinned' && !value.drift) {
    return { key: 'ok', text: tr('rot_state_pinned', 'Pinned') }
  }
  if (value.drift) return { key: 'bad', text: tr('rot_state_drift', 'Root of trust drifted') }
  return { key: 'warn', text: tr('rot_state_auto', 'Live values (not pinned)') }
})

function formatTime(unix: number): string {
  if (unix <= 0) return tr('cloud_keybox_never', 'never')
  const date = new Date(unix * 1000)
  return Number.isNaN(date.getTime()) ? tr('cloud_keybox_never', 'never') : date.toLocaleString()
}

function shortDigest(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value
}

function applyLoaded(value: CloudKeyboxStatus): void {
  cloud.value = value
  enabled.value = value.enabled
  autoFetch.value = value.auto_fetch
  verifySignature.value = value.verify_signature
  baseUrl.value = value.base_url
  pubkey.value = ''
}

async function load(): Promise<void> {
  if (!props.modelValue || busy.value === 'load') return
  const currentGeneration = ++generation
  status.value = 'loading'
  errorMessage.value = ''
  busy.value = 'load'
  try {
    if (preview) {
      applyLoaded(PREVIEW_STATUS)
      rot.value = PREVIEW_ROT
      status.value = 'ready'
      return
    }
    const [cloudResult, rotResult] = await Promise.allSettled([
      props.cli.getCloudKeybox(),
      props.cli.getRootOfTrust(),
    ])
    if (currentGeneration !== generation || !props.modelValue) return
    if (cloudResult.status === 'fulfilled') applyLoaded(cloudResult.value)
    if (rotResult.status === 'fulfilled') rot.value = rotResult.value
    const failure = cloudResult.status === 'rejected'
      ? cloudResult.reason
      : (rotResult.status === 'rejected' ? rotResult.reason : null)
    if (cloudResult.status === 'rejected' && rotResult.status === 'rejected') {
      status.value = 'error'
      errorMessage.value = failure instanceof Error ? failure.message : String(failure)
    } else {
      status.value = 'ready'
      if (failure !== null) {
        errorMessage.value = failure instanceof Error ? failure.message : String(failure)
      }
    }
  } catch (error) {
    if (currentGeneration !== generation || !props.modelValue) return
    status.value = 'error'
    errorMessage.value = error instanceof Error ? error.message : String(error)
  } finally {
    if (currentGeneration === generation) busy.value = null
  }
}

watch(() => props.modelValue, open => {
  if (open) {
    step.value = 1
    operationMessage.value = ''
    void load()
  } else {
    generation++
  }
})

function requestClose(): boolean {
  if (busy.value !== null) return false
  emit('update:modelValue', false)
  return true
}

defineExpose({ requestClose, busy })

async function saveSettings(): Promise<void> {
  if (!canSaveSettings.value || cloud.value === null) return
  const current = cloud.value
  const nextUrl = baseUrl.value.trim()
  const nextPubkey = pubkey.value.trim()
  busy.value = 'settings'
  errorMessage.value = ''
  try {
    if (nextUrl !== current.base_url) await props.cli.setCloudKeyboxBaseUrl(nextUrl)
    if (nextPubkey !== '') await props.cli.setCloudKeyboxPubkey(nextPubkey)
    if (verifySignature.value !== current.verify_signature) {
      await props.cli.setCloudKeyboxVerify(verifySignature.value)
    }
    if (enabled.value !== current.enabled) await props.cli.setCloudKeyboxEnabled(enabled.value)
    if (autoFetch.value !== current.auto_fetch) await props.cli.setCloudKeyboxAuto(autoFetch.value)
    emit('notify', tr('cloud_keybox_settings_saved', 'Cloud Keybox settings saved'))
    await load()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
    emit('notify', errorMessage.value, true)
  } finally {
    busy.value = null
  }
}

const stepLabel = computed(() => {
  if (step.value === 1) return tr('cloud_keybox_step1_button', 'Fetch and replace Keybox')
  if (step.value === 2) return tr('cloud_keybox_step2_button', 'Check for cloud updates')
  return tr('cloud_keybox_step3_button', 'Fetch the second Keybox')
})

const stepHint = computed(() => {
  if (step.value === 1) return tr('cloud_keybox_step1_hint', '1st round: fetch a Keybox from the cloud and replace the installed one')
  if (step.value === 2) return tr('cloud_keybox_step2_hint', '2nd round: check whether the cloud has a newer Keybox')
  return tr('cloud_keybox_step3_hint', '3rd round: fetch the second Keybox from the cloud')
})

async function runCloudAction(): Promise<void> {
  if (!canFetch.value) return
  busy.value = 'fetch'
  errorMessage.value = ''
  operationMessage.value = tr('cloud_keybox_working', 'Fetching the Keybox from the cloud…')
  try {
    if (!preview) {
      const result = await (step.value === 1
        ? props.cli.applyCloudKeybox()
        : step.value === 2
          ? props.cli.checkCloudKeyboxUpdate()
          : props.cli.getSecondCloudKeybox())
      const changed = result.applied
      if (step.value === 2 && !changed) {
        emit('notify', tr('cloud_keybox_latest', 'Your Keybox is already the newest one.'), false)
      } else {
        emit('notify', tr('cloud_keybox_success', 'Keybox fetched successfully'), false)
        if (changed) emit('changed')
      }
      // Cloud notices: server-configured prompts shown without touching existing texts.
      for (const line of result.notice) {
        emit('notify', line, false)
      }
    } else {
      await new Promise(resolve => setTimeout(resolve, 600))
      const changed = step.value !== 2
      emit('notify', step.value === 2
        ? tr('cloud_keybox_latest', 'Your Keybox is already the newest one.')
        : tr('cloud_keybox_success', 'Keybox fetched successfully'), false)
      if (changed) emit('changed')
    }
    step.value = step.value === 3 ? 1 : ((step.value + 1) as 1 | 2 | 3)
    await load()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
    emit('notify', tr('cloud_keybox_cloud_problem', 'Something is wrong with the cloud. Please try again later.'), true)
  } finally {
    busy.value = null
    operationMessage.value = ''
  }
}

async function repin(): Promise<void> {
  if (!canRepin.value) return
  busy.value = 'repin'
  errorMessage.value = ''
  try {
    const report = await props.cli.repinRootOfTrust(purgeKeys.value)
    rot.value = report
    emit('notify', tr('rot_repinned', 'Root of trust pinned to the current vbmeta values.'), false)
    emit('changed')
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
    emit('notify', errorMessage.value, true)
  } finally {
    busy.value = null
  }
}
</script>

<template>
  <MiuixDialog
    :model-value="modelValue"
    :title="tr('cloud_keybox_title', 'Cloud Keybox')"
    :close-on-click-modal="busy === null"
    @update:model-value="value => { if (!value) requestClose() }"
  >
    <div class="cloud-dialog" :aria-busy="busy !== null || status === 'loading'">
      <p class="cloud-dialog__hint">
        {{ tr('cloud_keybox_desc', 'Fetch a signed Keybox from your own server. Every download is verified with an Ed25519 signature and the published SHA-256 before it is installed.') }}
      </p>

      <template v-if="cloud !== null && cloud.notice.length > 0">
        <div class="cloud-dialog__notice" role="note">
          <p v-for="line in cloud.notice" :key="line" class="cloud-dialog__notice-line">
            {{ line }}
          </p>
        </div>
      </template>

      <div v-if="status === 'loading'" class="cloud-dialog__loading" role="status">
        <MiuixProgressIndicator type="circular" :size="28" />
        <span>{{ tr('home_status_loading', 'Checking') }}</span>
      </div>

      <template v-else-if="cloud !== null">
        <MiuixSmallTitle :text="tr('cloud_keybox_connection', 'Connection')" />
        <MiuixCard class="cloud-dialog__card" press-feedback="none">
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_state', 'Server') }}</span>
            <span class="cloud-dialog__value" :data-badge="cloudBadge.key">{{ cloudBadge.text }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_base_url', 'Base URL') }}</span>
            <span class="cloud-dialog__value cloud-dialog__value--wrap">{{ cloud.base_url }}</span>
          </div>
          <div v-if="cloud.server_version" class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_server_version', 'Server version') }}</span>
            <span class="cloud-dialog__value">{{ cloud.server_version }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_pubkey', 'Signing key') }}</span>
            <span class="cloud-dialog__value">{{ cloud.trusted_pubkey === 'builtin' ? tr('cloud_keybox_pubkey_builtin', 'Built-in anchor') : tr('cloud_keybox_pubkey_configured', 'Configured') }}</span>
          </div>
          <p v-if="cloud.cloud_error" class="cloud-dialog__error" role="alert">{{ cloud.cloud_error }}</p>
        </MiuixCard>

        <MiuixSmallTitle :text="tr('cloud_keybox_next', 'Next Keybox')" />
        <MiuixCard class="cloud-dialog__card" press-feedback="none">
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_source', 'Source') }}</span>
            <span class="cloud-dialog__value cloud-dialog__value--wrap">{{ cloud.next_source || tr('cloud_keybox_none', 'none') }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_digest', 'SHA-256') }}</span>
            <span class="cloud-dialog__value">{{ cloud.next_sha256 ? shortDigest(cloud.next_sha256) : tr('cloud_keybox_none', 'none') }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('keybox_level', 'Level') }}</span>
            <span class="cloud-dialog__value">{{ cloud.next_level || '-' }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_validity', 'Validity') }}</span>
            <span class="cloud-dialog__value" :data-badge="cloud.next_ok ? 'ok' : 'bad'">
              {{ cloud.next_days_remaining >= 0
                ? `${cloud.next_days_remaining} d`
                : tr('cloud_keybox_days_unknown', 'unknown') }}
              <template v-if="cloud.next_min_not_after"> · {{ cloud.next_min_not_after }}</template>
            </span>
          </div>
          <div v-if="cloud.rotation_enabled" class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_rotation', 'Rotation') }}</span>
            <span class="cloud-dialog__value">{{ cloud.rotation_current_index + 1 }} / {{ cloud.rotation_pool_size }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_installed', 'Installed Keybox') }}</span>
            <span class="cloud-dialog__value" :data-badge="cloud.is_current ? 'ok' : 'warn'">
              {{ cloud.installed_sha256 ? shortDigest(cloud.installed_sha256) : tr('cloud_keybox_none', 'none') }}
              <template v-if="cloud.is_current"> · {{ tr('cloud_keybox_current', 'up to date') }}</template>
            </span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_last_fetch', 'Last fetch') }}</span>
            <span class="cloud-dialog__value">{{ formatTime(cloud.last_fetch_unix) }}</span>
          </div>
          <div v-if="cloud.last_status" class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('cloud_keybox_last_result', 'Last result') }}</span>
            <span class="cloud-dialog__value">{{ cloud.last_status }}{{ cloud.last_source ? ` · ${shortDigest(cloud.last_sha256)}` : '' }}</span>
          </div>
          <p v-if="cloud.last_error" class="cloud-dialog__error" role="alert">{{ cloud.last_error }}</p>
        </MiuixCard>

        <MiuixSmallTitle :text="tr('cloud_keybox_preferences', 'Preferences')" />
        <MiuixCard class="cloud-dialog__card" press-feedback="none">
          <MiuixSwitchPreference
            v-model="enabled"
            :title="tr('cloud_keybox_enable', 'Enable cloud Keybox')"
            :summary="tr('cloud_keybox_enable_desc', 'When off, no request is sent to the server.')"
            :disabled="busy !== null"
          />
          <MiuixSwitchPreference
            v-model="autoFetch"
            :title="tr('cloud_keybox_auto', 'Automatic refresh')"
            :summary="tr('cloud_keybox_auto_desc', 'Checked once per interval, no background polling. A new Keybox restarts KeyMint.')"
            :disabled="busy !== null || !enabled"
          />
          <MiuixSwitchPreference
            v-model="verifySignature"
            :title="tr('cloud_keybox_verify', 'Verify the Ed25519 signature')"
            :summary="tr('cloud_keybox_verify_desc', 'Only disable it if your own server publishes unsigned Keyboxes.')"
            :disabled="busy !== null"
          />
        </MiuixCard>

        <MiuixInput
          v-model="baseUrl"
          :label="tr('cloud_keybox_base_url', 'Base URL')"
          :disabled="busy !== null"
        />
        <MiuixInput
          v-model="pubkey"
          :label="tr('cloud_keybox_pubkey_input', 'Replacement signing key (optional)')"
          :disabled="busy !== null"
        />
        <p class="cloud-dialog__hint">
          {{ tr('cloud_keybox_pubkey_hint', 'Leave empty to keep the built-in anchor. Accepts base64 or 64-character hex Ed25519 public keys.') }}
        </p>

        <MiuixSmallTitle :text="tr('rot_title', 'Root of trust')" />
        <p class="cloud-dialog__hint">
          {{ tr('rot_desc', 'KeyBlobs are encrypted with a key derived from vb_key and vb_hash. OMK pins both values whenever the Keybox changes, so a changed vbmeta no longer invalidates the stored keys.') }}
        </p>
        <MiuixCard class="cloud-dialog__card" press-feedback="none">
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('rot_state', 'State') }}</span>
            <span class="cloud-dialog__value" :data-badge="rotBadge.key">{{ rotBadge.text }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">vb_key</span>
            <span class="cloud-dialog__value">{{ rot ? shortDigest(rot.vb_key) : '-' }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">vb_hash</span>
            <span class="cloud-dialog__value">{{ rot ? shortDigest(rot.vb_hash) : '-' }}</span>
          </div>
          <div class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('rot_sources', 'Source') }}</span>
            <span class="cloud-dialog__value">{{ rot ? `${rot.vb_key_source} / ${rot.vb_hash_source}` : '-' }}</span>
          </div>
          <div v-if="rot && rot.purged_keys !== null" class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('rot_purged_keys', 'Retired keys') }}</span>
            <span class="cloud-dialog__value">{{ rot.purged_keys }}</span>
          </div>
          <div v-if="rot && rot.restart_required" class="cloud-dialog__row">
            <span class="cloud-dialog__label">{{ tr('rot_restart', 'Restart') }}</span>
            <span class="cloud-dialog__value" data-badge="warn">{{ tr('rot_restart_needed', 'KeyMint restart requested') }}</span>
          </div>
          <p v-if="rot && rot.note" class="cloud-dialog__hint">{{ rot.note }}</p>
        </MiuixCard>
        <MiuixSwitchPreference
          v-model="purgeKeys"
          :title="tr('rot_purge_switch', 'Delete KeyBlobs that no longer decrypt')"
          :summary="tr('rot_purge_switch_desc', 'Only clears Oh My Keymint-R1 key records under /data/misc/keystore/omk. Apps recreate their keys after a reboot.')"
          :disabled="busy !== null"
        />
      </template>

      <p v-if="errorMessage" class="cloud-dialog__error" role="alert">{{ errorMessage }}</p>
      <p v-if="preview" class="cloud-dialog__hint" role="status">
        {{ tr('cloud_keybox_preview', 'Preview only. Device settings cannot be saved here.') }}
      </p>

      <div class="cloud-dialog__actions">
        <MiuixButton :disabled="busy !== null" @click="requestClose">
          {{ tr('functional_button_cancel', 'Cancel') }}
        </MiuixButton>
        <MiuixButton v-if="status === 'error'" type="primary" @click="load">
          {{ tr('functional_button_retry', 'Retry') }}
        </MiuixButton>
        <template v-else>
          <MiuixButton type="primary" :disabled="!canSaveSettings" @click="saveSettings">
            <MiuixProgressIndicator v-if="busy === 'settings'" type="circular" :size="18" />
            {{ tr('functional_button_save', 'Save') }}
          </MiuixButton>
          <MiuixButton type="primary" :disabled="!canFetch" @click="runCloudAction">
            <MiuixProgressIndicator v-if="busy === 'fetch'" type="circular" :size="18" />
            {{ stepLabel }}
          </MiuixButton>
          <MiuixButton :disabled="!canRepin" @click="repin">
            <MiuixProgressIndicator v-if="busy === 'repin'" type="circular" :size="18" />
            {{ tr('rot_repin_button', 'Pin now') }}
          </MiuixButton>
        </template>
      </div>
      <p class="cloud-dialog__hint" role="status">
        {{ operationMessage || stepHint }}
      </p>
    </div>
  </MiuixDialog>
</template>

<style scoped>
.cloud-dialog { display: flex; flex-direction: column; gap: 12px; }
.cloud-dialog__hint { margin: 0; color: var(--m-color-on-surface-variant-summary); font-size: 13px; line-height: 1.5; overflow-wrap: anywhere; }
.cloud-dialog__notice { display: flex; flex-direction: column; gap: 4px; padding: 10px 12px; border-radius: 12px; background: color-mix(in srgb, var(--m-color-warning, #b26a00) 12%, transparent); }
.cloud-dialog__notice-line { margin: 0; color: var(--m-color-on-surface); font-size: 13px; line-height: 1.5; overflow-wrap: anywhere; }
.cloud-dialog__error { margin: 0; color: var(--m-color-error); font-size: 13px; line-height: 1.5; overflow-wrap: anywhere; }
.cloud-dialog__loading { display: flex; min-height: 64px; align-items: center; justify-content: center; gap: 12px; color: var(--m-color-on-surface-variant-summary); }
.cloud-dialog__card { padding: 4px 14px; }
.cloud-dialog__row { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; padding: 6px 0; font-size: 14px; }
.cloud-dialog__label { color: var(--m-color-on-surface-variant-summary); }
.cloud-dialog__value { font-weight: 500; text-align: end; }
.cloud-dialog__value--wrap { overflow-wrap: anywhere; }
.cloud-dialog__value[data-badge='ok'] { color: var(--m-color-success, #2e7d32); }
.cloud-dialog__value[data-badge='bad'] { color: var(--m-color-error); }
.cloud-dialog__value[data-badge='warn'] { color: var(--m-color-warning, #b26a00); }
.cloud-dialog__actions { display: flex; flex-wrap: wrap; gap: 10px; }
.cloud-dialog__actions > * { flex: 1 1 40%; min-width: 0; }
.cloud-dialog :deep(.m-basic-component) { padding: 6px 0; }
.cloud-dialog :deep(.m-basic-component__center > .m-text--headline1) { font-size: 16px; line-height: 1.35; }
.cloud-dialog :deep(.m-basic-component__center > .m-text--body2) { font-size: 13px; line-height: 1.4; }
</style>
