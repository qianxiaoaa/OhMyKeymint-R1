<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import {
  MiuixDialog,
  MiuixIcon,
  MiuixButton,
  MiuixNavigationBar,
  MiuixProgressIndicator,
  MiuixSnackbarHost,
  showSnackbar,
  setThemeMode,
} from 'miuix-vue'
import { All, Settings, Tune } from 'miuix-vue/icons'
import { AppList, type AppListSnapshot } from '../app_list/app_list'
import { appearance } from '../appearance'
import {
  Cli,
  MAX_WALLPAPER_BYTES,
  WALLPAPER_EXTENSIONS,
  type CloudStatus,
  type DiagnosticsState,
  type KeyboxInspector,
  type KeyboxRevocationStatus,
} from '../cli'
import { ConfigOhMyKeyMint } from '../config_ohmykeymint'
import { FileSelector, type SelectedContents } from '../file_selector/file_selector'
import { History } from '../history'
import { i18n } from '../i18n'
import { fetchLatestSecurityPatch } from '../security_patch'
import { wallpaper } from '../wallpaper'
import { isDev } from '../utils/dev'
import HomeView, { type KeyboxStatus, type ModuleStatus, type TeeStatus } from './HomeView.vue'
import PifFingerprintDialog from './PifFingerprintDialog.vue'
import SettingsView from './SettingsView.vue'
import SoterDialog from './SoterDialog.vue'
import SoterHalDialog from './SoterHalDialog.vue'
import TargetsView from './TargetsView.vue'
import ToolsView, { type ToolEvent } from './ToolsView.vue'
import FileBrowserSheet from './FileBrowserSheet.vue'
import './app.scss'

const cli = new Cli()
const config = new ConfigOhMyKeyMint(cli)
const appList = new AppList(config)
const fileSelector = new FileSelector()
const history = new History()

const DEV_CLOUD_STATUS: CloudStatus = {
  mirror: {
    installed_sha256: 'a'.repeat(64),
    installed_source: 'mirror',
    last_fetch_unix: Math.floor(Date.now() / 1000),
    last_sha256: 'a'.repeat(64),
    last_source: 'yurikey',
    last_status: 'applied',
    last_error: '',
  },
  online: {
    module_id: `omk-${'b'.repeat(32)}`,
    last_report_unix: Math.floor(Date.now() / 1000),
    last_status: 'ok',
    last_error: '',
    interval_seconds: 1800,
  },
}

const pageIndex = ref(0)
const pageDirection = ref(1)
const pageScrollPositions = [0, 0, 0]
const targetsOpen = ref(false)
const targetsLoading = ref(false)
const snapshot = ref<AppListSnapshot>(appList.getSnapshot())
const moduleStatus = ref<ModuleStatus>('loading')
const keyboxStatus = ref<KeyboxStatus>('loading')
const keyboxSource = ref<'google_hardware' | 'google_remote' | 'unknown'>('unknown')
const keyboxLevel = ref<'tee' | 'strongbox' | 'unknown'>('unknown')
const keyboxRevocation = ref<KeyboxRevocationStatus>('not_checked')
const keyboxInspector = ref<KeyboxInspector | null>(null)
const diagnostics = ref<DiagnosticsState | null>(null)
const diagnosticsStatus = ref<'loading' | 'ready' | 'error'>('loading')
const cloudStatus = ref<CloudStatus | null>(null)
const teeStatus = ref<TeeStatus>('loading')
const securityPatch = ref<string | null>(null)
const spoofedDevice = ref<string | null | undefined>(undefined)
const moduleName = ref('Oh My Keymint-R1')
const securityPatchBusy = ref<'sync' | 'restore' | null>(null)
const keyboxBusy = ref<'install' | 'mirror' | null>(null)
const soterOpen = ref(false)
const soterHalOpen = ref(false)
const pifOpen = ref(false)
const keyboxOpen = ref(false)
const selectedKeybox = ref<SelectedContents | null>(null)
const targetsView = ref<InstanceType<typeof TargetsView> | null>(null)
const settingsView = ref<InstanceType<typeof SettingsView> | null>(null)
const pifDialog = ref<InstanceType<typeof PifFingerprintDialog> | null>(null)
const soterDialog = ref<InstanceType<typeof SoterDialog> | null>(null)
const soterHalDialog = ref<InstanceType<typeof SoterHalDialog> | null>(null)

const pageIds = ['home', 'tools', 'settings'] as const
const navItems = computed(() => [
  { label: i18n.t('nav_home') === 'nav_home' ? 'Home' : i18n.t('nav_home') },
  { label: i18n.t('nav_tools') === 'nav_tools' ? 'Tools' : i18n.t('nav_tools') },
  { label: i18n.t('nav_settings') === 'nav_settings' ? 'Settings' : i18n.t('nav_settings') },
])

let unsubscribeAppList: (() => void) | null = null
let unsubscribeFileSelector: (() => void) | null = null
let unsubscribeAppearance: (() => void) | null = null
let keydownListener: ((event: KeyboardEvent) => void) | null = null
let pageHistoryActive = false
const overlayHistory = new Set<string>()
let targetsRefreshTimer: number | null = null
let navigationElement: HTMLElement | null = null
let navigationPointerId: number | null = null
let navigationPointerStartX = 0
let navigationPointerStartIndex = 0
let navigationPointerSlotWidth = 1
let navigationWasDragged = false
let navigationSuppressClick = false

// KernelSU's floating bar keeps its drag/spring interaction independent from
// the optional liquid-glass surface treatment.  The same gesture therefore
// remains available when the bar is rendered as a regular floating surface.
function floatingNavigationEnabled(): boolean {
  const root = document.documentElement
  return root.dataset.floatingBottomBar === 'true'
}

function clampNavigationIndex(index: number): number {
  return Math.max(0, Math.min(pageIds.length - 1, index))
}

function navigationPosition(clientX: number): number {
  if (!navigationElement) return pageIndex.value
  const bounds = navigationElement.getBoundingClientRect()
  const slot = Math.max(1, (bounds.width - 8) / pageIds.length)
  return clampNavigationIndex((clientX - bounds.left - 4) / slot)
}

function onNavigationPointerDown(event: PointerEvent): void {
  if (!navigationElement || !floatingNavigationEnabled() || !event.isPrimary || event.button !== 0
      || navigationPointerId !== null) return
  const bounds = navigationElement.getBoundingClientRect()
  navigationPointerSlotWidth = Math.max(
    1,
    (bounds.width - 8) / pageIds.length,
  )
  navigationPointerId = event.pointerId
  navigationPointerStartX = event.clientX
  navigationPointerStartIndex = Math.floor(navigationPosition(event.clientX))
  navigationWasDragged = false
  navigationElement.classList.add('is-pressing')
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(navigationPointerStartIndex))
  navigationElement.style.setProperty('--omk-liquid-nav-scale', '1.392857')
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', '0px')
  navigationElement.style.setProperty(
    '--omk-liquid-nav-highlight-x',
    `${event.clientX - bounds.left}px`,
  )
  try { navigationElement.setPointerCapture(event.pointerId) } catch { /* WebView may reject capture. */ }
  event.preventDefault()
}

function onNavigationPointerMove(event: PointerEvent): void {
  if (!navigationElement || navigationPointerId !== event.pointerId) return
  if (Math.abs(event.clientX - navigationPointerStartX) > 1) {
    navigationElement.classList.add('is-dragging')
    navigationWasDragged = true
  }
  const position = navigationPointerStartIndex
    + (event.clientX - navigationPointerStartX) / navigationPointerSlotWidth
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(clampNavigationIndex(position)))
  const bounds = navigationElement.getBoundingClientRect()
  const distance = event.clientX - navigationPointerStartX
  const fraction = Math.min(1, Math.abs(distance) / Math.max(1, bounds.width))
  const rubberBand = Math.sign(distance) * 4 * (1 - (1 - fraction) ** 2)
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', `${rubberBand}px`)
  navigationElement.style.setProperty(
    '--omk-liquid-nav-highlight-x',
    `${event.clientX - bounds.left}px`,
  )
  event.preventDefault()
}

function onNavigationPointerUp(event: PointerEvent): void {
  if (!navigationElement || navigationPointerId !== event.pointerId) return
  const target = navigationWasDragged
    ? Math.round(clampNavigationIndex(navigationPointerStartIndex
      + (event.clientX - navigationPointerStartX) / navigationPointerSlotWidth))
    : navigationPointerStartIndex
  navigationSuppressClick = navigationWasDragged
  navigationPointerId = null
  navigationWasDragged = false
  navigationElement.classList.remove('is-pressing', 'is-dragging')
  navigationElement.style.setProperty('--omk-liquid-nav-scale', '1')
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', '0px')
  navigationElement.style.setProperty('--omk-liquid-nav-highlight-x', '50%')
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(target))
  try { navigationElement.releasePointerCapture(event.pointerId) } catch { /* Already released. */ }
  if (target !== pageIndex.value) setPage(target)
  window.setTimeout(() => { navigationSuppressClick = false }, 120)
  event.preventDefault()
}

function onNavigationClickCapture(event: Event): void {
  if (!navigationSuppressClick) return
  navigationSuppressClick = false
  event.preventDefault()
  event.stopImmediatePropagation()
}

function onNavigationPointerCancel(event: PointerEvent): void {
  if (!navigationElement || navigationPointerId !== event.pointerId) return
  navigationPointerId = null
  navigationWasDragged = false
  navigationSuppressClick = false
  navigationElement.classList.remove('is-pressing', 'is-dragging')
  navigationElement.style.setProperty('--omk-liquid-nav-scale', '1')
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', '0px')
  navigationElement.style.setProperty('--omk-liquid-nav-highlight-x', '50%')
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(pageIndex.value))
}

function notify(message: string, error = false): void {
  void showSnackbar({ message, duration: error ? 6000 : 'long', withDismissAction: true })
}

function setPage(index: number): void {
  if (index < 0 || index >= pageIds.length || index === pageIndex.value) return
  pageIndex.value = index
  if (index !== 0 && !pageHistoryActive) {
    pageHistoryActive = true
    history.push('main-page', () => {
      pageHistoryActive = false
      pageIndex.value = 0
    })
  } else if (index === 0 && pageHistoryActive) {
    pageHistoryActive = false
    history.consume('main-page')
  }
}

function openTargets(): void {
  if (targetsOpen.value) return
  targetsOpen.value = true
  history.push('app-targets', () => { targetsOpen.value = false })
  window.setTimeout(() => { if (targetsOpen.value) void reloadApps(false) }, 220)
}

function closeTargets(): void {
  if (!targetsOpen.value) return
  targetsOpen.value = false
  if (targetsRefreshTimer !== null) {
    window.clearTimeout(targetsRefreshTimer)
    targetsRefreshTimer = null
  }
  history.consume('app-targets')
}

// Package installation happens outside the WebUI.  Refresh when Android
// brings the WebView back to the foreground so a newly installed app appears
// without requiring the user to close and reopen the selector.  The short
// debounce lets the overlay/focus animation paint before crossing the
// synchronous KernelSU package bridge.
function scheduleTargetsRefresh(): void {
  if (!targetsOpen.value
      || document.visibilityState !== 'visible'
      || targetsLoading.value
      || targetsRefreshTimer !== null) return
  targetsRefreshTimer = window.setTimeout(() => {
    targetsRefreshTimer = null
    if (targetsOpen.value && document.visibilityState === 'visible' && !targetsLoading.value) {
      void reloadApps(false)
    }
  }, 180)
}

function refreshTargetsWhenForegrounded(): void {
  if (document.visibilityState === 'visible') scheduleTargetsRefresh()
}

function onTargetsOverlayOpen(): void {
  const key = 'targets-overlay'
  if (overlayHistory.has(key)) return
  overlayHistory.add(key)
  history.push(key, () => { targetsView.value?.dismissOverlay() })
}

function onSettingsOverlayOpen(): void {
  const key = 'settings-overlay'
  if (overlayHistory.has(key)) return
  overlayHistory.add(key)
  history.push(key, () => {
    overlayHistory.delete(key)
    settingsView.value?.dismissOverlay()
  })
}

function onSettingsOverlayClose(): void {
  const key = 'settings-overlay'
  if (overlayHistory.delete(key)) history.consume(key)
}

function onTargetsOverlayClose(): void {
  const key = 'targets-overlay'
  if (overlayHistory.delete(key)) history.consume(key)
}

function handleEscape(): void {
  if (soterOpen.value && soterDialog.value?.busy) return
  if (soterHalOpen.value && soterHalDialog.value?.busy) return
  if (targetsOpen.value && targetsView.value?.dismissOverlay()) return
  if (history.size > 0) history.back()
}

async function reloadApps(readConfig: boolean): Promise<void> {
  targetsLoading.value = true
  try {
    if (readConfig) await config.read()
    await appList.fetch()
    snapshot.value = appList.getSnapshot()
    moduleStatus.value = config.isWritable ? 'ready' : 'error'
  } catch (error) {
    moduleStatus.value = 'error'
    console.error('Unable to load OMK configuration:', error)
    notify(i18n.t('prompt_load_error'), true)
  } finally {
    targetsLoading.value = false
  }
}

async function saveTargets(): Promise<void> {
  targetsLoading.value = true
  try {
    await appList.save()
    snapshot.value = appList.getSnapshot()
    notify(i18n.t('prompt_saved_target'))
  } catch (error) {
    console.error('Unable to save OMK targets:', error)
    notify(i18n.t('prompt_save_error'), true)
  } finally {
    targetsLoading.value = false
  }
}

// The version and commit hash exist only in the installed module.prop: the
// committed webroot has to stay byte-identical to a fresh WebUI build.
async function refreshModuleName(): Promise<void> {
  if (isDev()) {
    moduleName.value = 'Oh My Keymint-R1 (dev)'
  } else {
    try {
      moduleName.value = await cli.getModuleName()
    } catch (error) {
      console.error('Unable to load the OMK module name:', error)
    }
  }
  document.title = moduleName.value
}

async function refreshIdentity(force = false): Promise<void> {
  // The refresh path always queries the current backend state; keep the
  // parameter for callers that request an explicit refresh after a mutation.
  void force
  if (isDev()) {
    keyboxStatus.value = 'custom'
    keyboxSource.value = 'google_remote'
    keyboxLevel.value = 'tee'
    keyboxRevocation.value = 'not_listed'
    keyboxInspector.value = {
      valid: true,
      bundled: false,
      rsa: null,
      ec: {
        algorithm: 'EC',
        chain_length: 3,
        serials: ['01', '02', '03'],
        leaf_subject: 'CN=Demo keybox',
        leaf_issuer: 'CN=Demo issuer',
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2036-01-01T00:00:00Z',
        certificates: [
          { serial: '01', subject: 'CN=Demo keybox', issuer: 'CN=Demo issuer', valid_from: '2026-01-01T00:00:00Z', valid_until: '2036-01-01T00:00:00Z' },
          { serial: '02', subject: 'CN=Demo issuer', issuer: 'CN=Demo root', valid_from: '2025-01-01T00:00:00Z', valid_until: '2040-01-01T00:00:00Z' },
          { serial: '03', subject: 'CN=Demo root', issuer: 'CN=Demo root', valid_from: '2024-01-01T00:00:00Z', valid_until: '2044-01-01T00:00:00Z' },
        ],
      },
    }
    teeStatus.value = 'normal'
    securityPatch.value = '2026-08-01'
    spoofedDevice.value = 'Google Pixel 9 Pro'
    return
  }
  try {
    const [keybox, patch, tee, pif] = await Promise.allSettled([
      cli.getKeyboxState(),
      cli.getSystemSecurityPatch(),
      cli.getTeeStatus(),
      cli.getPifFingerprintState(),
    ])
    if (keybox.status === 'fulfilled') {
      const value = keybox.value
      keyboxStatus.value = value.valid ? (value.bundled ? 'bundled' : 'custom') : 'invalid'
      keyboxSource.value = value.source
      keyboxLevel.value = value.level
      keyboxRevocation.value = value.valid ? 'checking' : value.revocation
      if (value.valid) {
        try { keyboxRevocation.value = await cli.checkKeyboxRevocation() }
        catch { keyboxRevocation.value = 'unknown' }
      }
    } else keyboxStatus.value = 'error'
    if (patch.status === 'fulfilled') securityPatch.value = patch.value
    if (tee.status === 'fulfilled') teeStatus.value = 'normal'
    else teeStatus.value = 'error'
    if (pif.status === 'fulfilled') {
      spoofedDevice.value = pif.value.enabled
        ? (/^google\s/i.test(pif.value.model) ? pif.value.model : `Google ${pif.value.model}`)
        : null
    }
  } catch (error) {
    console.error('Unable to load OMK identity:', error)
  }
}

async function refreshDiagnostics(): Promise<void> {
  diagnosticsStatus.value = 'loading'
  if (isDev()) {
    diagnostics.value = {
      keymint: { status: 'running', pid: 1234 },
      keystore2: { status: 'running', pid: 1240 },
      injector: { status: 'running', pid: 1250 },
      soter: { status: 'configured', pid: null },
      tee: { status: 'available', version: 300, name: 'TEE KeyMint' },
      strongbox: { status: 'unavailable', version: null, name: null },
      rkp_tee: { status: 'available', pid: null },
      rkp_strongbox: { status: 'unavailable', pid: null },
      selinux: 'enforcing',
      rot: { status: 'ok', mode: 'pinned', pinned: true, drift: false },
    }
    diagnosticsStatus.value = 'ready'
    return
  }

  const [inspector, state] = await Promise.allSettled([
    cli.getKeyboxInspector(),
    cli.getDiagnostics(),
  ])
  if (inspector.status === 'fulfilled') keyboxInspector.value = inspector.value
  if (state.status === 'fulfilled') {
    diagnostics.value = state.value
    diagnosticsStatus.value = 'ready'
  } else {
    diagnosticsStatus.value = 'error'
    console.error('Unable to load OMK service diagnostics:', state.reason)
  }
}

async function chooseKeybox(): Promise<void> {
  try {
    const selected = await fileSelector.getSystemFileContent({ extensions: ['xml'] })
    if (selected?.kind === 'contents') {
      selectedKeybox.value = selected
      keyboxOpen.value = true
    }
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  }
}

async function installKeybox(): Promise<void> {
  const selected = selectedKeybox.value
  if (!selected || keyboxBusy.value) return
  keyboxBusy.value = 'install'
  try {
    if (!isDev()) await cli.installKeybox(selected.contents)
    notify(i18n.t('prompt_keybox_replaced'))
    keyboxOpen.value = false
    selectedKeybox.value = null
    await Promise.all([refreshIdentity(true), refreshDiagnostics()])
  } catch (error) {
    notify(i18n.t('prompt_keybox_replace_error', error instanceof Error ? error.message : String(error)), true)
  } finally {
    keyboxBusy.value = null
  }
}

async function refreshMirrorKeybox(): Promise<void> {
  if (keyboxBusy.value !== null) return
  keyboxBusy.value = 'mirror'
  try {
    const report = isDev()
      ? { ok: true, applied: true, source: 'yurikey', sha256: 'a'.repeat(64), size: 4096, note: 'mirror keybox installed' }
      : await cli.refreshMirrorKeybox()
    notify(
      i18n.t(
        report.ok && report.applied
          ? 'prompt_mirror_keybox_applied'
          : report.ok
            ? 'prompt_mirror_keybox_unchanged'
            : 'prompt_mirror_keybox_failed',
      ),
      !report.ok,
    )
    await Promise.all([refreshIdentity(true), refreshCloud()])
  } catch (error) {
    console.error('Unable to refresh the mirror Keybox:', error)
    notify(i18n.t('prompt_mirror_keybox_failed'), true)
  } finally {
    keyboxBusy.value = null
  }
}

async function refreshCloud(): Promise<void> {
  try {
    cloudStatus.value = isDev() ? DEV_CLOUD_STATUS : await cli.getCloudStatus()
  } catch (error) {
    console.error('Unable to load OMK cloud status:', error)
    cloudStatus.value = null
  }
}

async function chooseWallpaper(): Promise<void> {
  try {
    // The system image picker is preferred; the in-app browser is only used as
    // a fallback when the WebView cannot launch the native picker.
    const selected = await fileSelector.getSystemFileContent({
      extensions: WALLPAPER_EXTENSIONS,
      maxBytes: MAX_WALLPAPER_BYTES,
      wrongTypeKey: 'prompt_wallpaper_image_required',
      tooLargeKey: 'prompt_wallpaper_too_large',
      emptyKey: 'replace_wallpaper_storage_empty',
    })
    if (!selected) return
    const installed = selected.kind === 'contents'
      ? await wallpaper.installBytes(cli, selected.contents)
      : await wallpaper.installFromStorage(cli, selected.path)
    if (installed) notify(i18n.t('prompt_wallpaper_applied'))
    else notify(wallpaper.status, true)
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  }
}

async function resetWallpaper(): Promise<void> {
  if (await wallpaper.reset(cli)) notify(i18n.t('prompt_wallpaper_reset'))
  else notify(wallpaper.status, true)
}

async function syncPatch(restore: boolean): Promise<void> {
  if (securityPatchBusy.value !== null) return
  securityPatchBusy.value = restore ? 'restore' : 'sync'
  try {
    if (restore) {
      if (!isDev()) await cli.restoreDefaultSecurityPatch()
      await refreshIdentity(true)
      notify(i18n.t('prompt_security_patch_restored_default'))
    } else {
      const date = await fetchLatestSecurityPatch(() => cli.fetchSecurityBulletin())
      const applied = isDev() ? date : await cli.syncSecurityPatch(date)
      securityPatch.value = applied
      notify(i18n.t('prompt_security_patch_sync_complete', applied))
    }
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  } finally {
    securityPatchBusy.value = null
  }
}

function onTool(event: ToolEvent): void {
  switch (event) {
    case 'openAppTargets': openTargets(); break
    case 'installKeybox': void chooseKeybox(); break
    case 'refreshMirrorKeybox': void refreshMirrorKeybox(); break
    case 'syncSecurityPatch': void syncPatch(false); break
    case 'restoreSecurityPatch': void syncPatch(true); break
    case 'openSoterBeta': soterOpen.value = true; break
    case 'openSoterHal': soterHalOpen.value = true; break
    case 'spoofPif': pifOpen.value = true; break
  }
}

onMounted(async () => {
  const applyMiuixTheme = (): void => {
    const mode = appearance.mode === 'auto' ? 'system' : appearance.mode === 'amoled' ? 'dark' : appearance.mode
    setThemeMode(mode)
  }
  applyMiuixTheme()
  navigationElement = document.querySelector<HTMLElement>('.main-navigation')
  navigationElement?.style.setProperty('--omk-liquid-nav-index', String(pageIndex.value))
  navigationElement?.style.setProperty('--omk-liquid-nav-scale', '1')
  navigationElement?.addEventListener('pointerdown', onNavigationPointerDown)
  navigationElement?.addEventListener('pointermove', onNavigationPointerMove)
  navigationElement?.addEventListener('pointerup', onNavigationPointerUp)
  navigationElement?.addEventListener('pointercancel', onNavigationPointerCancel)
  navigationElement?.addEventListener('click', onNavigationClickCapture, true)
  unsubscribeAppearance = appearance.onChange(applyMiuixTheme)
  keydownListener = event => {
    if (event.key === 'Escape') {
      event.preventDefault()
      handleEscape()
    }
  }
  window.addEventListener('keydown', keydownListener)
  document.addEventListener('visibilitychange', refreshTargetsWhenForegrounded)
  window.addEventListener('focus', refreshTargetsWhenForegrounded)
  unsubscribeAppList = appList.subscribe(value => { snapshot.value = value })
  unsubscribeFileSelector = fileSelector.subscribe(() => {
    if (fileSelector.open && !overlayHistory.has('file-selector')) {
      overlayHistory.add('file-selector')
      history.push('file-selector', () => fileSelector.cancel())
    } else if (!fileSelector.open && overlayHistory.delete('file-selector')) {
      history.consume('file-selector')
    }
  })
  await Promise.all([
    reloadApps(true),
    refreshModuleName(),
    refreshIdentity(),
    refreshDiagnostics(),
    refreshCloud(),
    wallpaper.load(cli),
  ])
})

onBeforeUnmount(() => {
  if (targetsRefreshTimer !== null) {
    window.clearTimeout(targetsRefreshTimer)
    targetsRefreshTimer = null
  }
  document.removeEventListener('visibilitychange', refreshTargetsWhenForegrounded)
  window.removeEventListener('focus', refreshTargetsWhenForegrounded)
  if (keydownListener !== null) window.removeEventListener('keydown', keydownListener)
  navigationElement?.removeEventListener('pointerdown', onNavigationPointerDown)
  navigationElement?.removeEventListener('pointermove', onNavigationPointerMove)
  navigationElement?.removeEventListener('pointerup', onNavigationPointerUp)
  navigationElement?.removeEventListener('pointercancel', onNavigationPointerCancel)
  navigationElement?.removeEventListener('click', onNavigationClickCapture, true)
  navigationElement = null
  unsubscribeAppList?.()
  unsubscribeFileSelector?.()
  unsubscribeAppearance?.()
  history.destroy()
})

watch(pageIndex, (index, previousIndex) => {
  pageScrollPositions[previousIndex] = window.scrollY
  pageDirection.value = index > previousIndex ? 1 : -1
  void nextTick(() => {
    if (pageIndex.value === index && !targetsOpen.value) {
      window.scrollTo(0, pageScrollPositions[index] ?? 0)
    }
  })
  if (navigationPointerId === null) {
    navigationElement?.style.setProperty('--omk-liquid-nav-index', String(index))
  }
})

watch(targetsOpen, open => {
  if (open) pageScrollPositions[pageIndex.value] = window.scrollY
  void nextTick(() => {
    if (targetsOpen.value === open) {
      window.scrollTo(0, open ? 0 : pageScrollPositions[pageIndex.value] ?? 0)
    }
  })
})

// Pages stay mounted behind v-show; root-level chrome reads the visible page here.
watch([pageIndex, targetsOpen], ([index, targets]) => {
  document.documentElement.dataset.page = targets ? 'targets' : pageIds[index]
}, { immediate: true })

watch(pifOpen, open => {
  if (open && !overlayHistory.has('pif-fingerprint')) {
    overlayHistory.add('pif-fingerprint')
    history.push('pif-fingerprint', () => {
      overlayHistory.delete('pif-fingerprint')
      pifDialog.value?.requestClose()
    })
  } else if (!open && overlayHistory.delete('pif-fingerprint')) history.consume('pif-fingerprint')
})
function trackSoterOverlay(): void {
  const key = 'soter-beta'
  if (!soterOpen.value || overlayHistory.has(key)) return
  overlayHistory.add(key)
  history.push(key, () => {
    overlayHistory.delete(key)
    if (soterDialog.value?.requestClose() === false) {
      // Re-arm after the current popstate handler finishes so a busy dialog
      // does not lose its back entry or close the page beneath it.
      void nextTick(trackSoterOverlay)
    }
  })
}
watch(soterOpen, open => {
  if (open) trackSoterOverlay()
  else if (overlayHistory.delete('soter-beta')) history.consume('soter-beta')
})
function trackSoterHalOverlay(): void {
  const key = 'soter-hal'
  if (!soterHalOpen.value || overlayHistory.has(key)) return
  overlayHistory.add(key)
  history.push(key, () => {
    overlayHistory.delete(key)
    if (soterHalDialog.value?.requestClose() === false) void nextTick(trackSoterHalOverlay)
  })
}
watch(soterHalOpen, open => {
  if (open) trackSoterHalOverlay()
  else if (overlayHistory.delete('soter-hal')) history.consume('soter-hal')
})
watch(keyboxOpen, open => {
  if (open && !overlayHistory.has('keybox')) {
    overlayHistory.add('keybox')
    history.push('keybox', () => { if (!keyboxBusy.value) keyboxOpen.value = false })
  } else if (!open && overlayHistory.delete('keybox')) history.consume('keybox')
})
</script>

<template>
  <Teleport to="body">
    <div class="omk-wallpaper" aria-hidden="true" />
  </Teleport>
  <div class="omk-app">
    <main v-show="!targetsOpen" class="page-host" :style="{ '--omk-page-direction': pageDirection }">
      <Transition name="page-switch">
        <HomeView
          v-show="pageIndex === 0"
          :keybox-status="keyboxStatus"
          :keybox-source="keyboxSource"
          :keybox-level="keyboxLevel"
          :keybox-revocation="keyboxRevocation"
          :keybox-inspector="keyboxInspector"
          :diagnostics="diagnostics"
          :diagnostics-status="diagnosticsStatus"
          :cloud-status="cloudStatus"
          :tee-status="teeStatus"
          :security-patch="securityPatch"
          :spoofed-device="spoofedDevice"
          :module-name="moduleName"
          @refresh-diagnostics="refreshDiagnostics"
          @refresh-cloud="refreshCloud"
        />
      </Transition>
      <Transition name="page-switch">
        <ToolsView
          v-show="pageIndex === 1"
          :security-patch-busy="securityPatchBusy"
          :keybox-busy="keyboxBusy"
          @open-app-targets="onTool('openAppTargets')"
          @install-keybox="onTool('installKeybox')"
          @refresh-mirror-keybox="onTool('refreshMirrorKeybox')"
          @sync-security-patch="onTool('syncSecurityPatch')"
          @restore-security-patch="onTool('restoreSecurityPatch')"
          @open-soter-beta="onTool('openSoterBeta')"
          @open-soter-hal="onTool('openSoterHal')"
          @spoof-pif="onTool('spoofPif')"
        />
      </Transition>
      <Transition name="page-switch">
        <SettingsView
          v-show="pageIndex === 2"
          ref="settingsView"
          @overlay-open="onSettingsOverlayOpen"
          @overlay-close="onSettingsOverlayClose"
          @choose-wallpaper="chooseWallpaper"
          @reset-wallpaper="resetWallpaper"
        />
      </Transition>
    </main>

    <Teleport to="body">
      <div v-show="!targetsOpen" class="navigation-dock">
        <MiuixNavigationBar
          :model-value="pageIndex"
          :items="navItems"
          :data-active-index="pageIndex"
          class="main-navigation"
          @update:model-value="setPage"
        >
          <template #icon="{ index }">
            <MiuixIcon :icon="index === 0 ? All : index === 1 ? Tune : Settings" :size="24" />
          </template>
        </MiuixNavigationBar>
      </div>
    </Teleport>

    <Transition name="targets-page">
      <TargetsView
        v-if="targetsOpen"
        ref="targetsView"
        :app-list="appList"
        :cli="cli"
        :loading="targetsLoading"
        :apply-enabled="snapshot.isWritable"
        @close="closeTargets"
        @refresh="reloadApps(false)"
        @apply="saveTargets"
        @overlay-open="onTargetsOverlayOpen"
        @overlay-close="onTargetsOverlayClose"
      />
    </Transition>

    <FileBrowserSheet :selector="fileSelector" />

    <MiuixDialog
      v-model="keyboxOpen"
      :title="i18n.t('replace_keybox_title')"
      :close-on-click-modal="!keyboxBusy"
    >
      <template #default="{ close }">
        <div class="confirm-sheet">
          <p>{{ selectedKeybox ? i18n.t('replace_keybox_selected_file', selectedKeybox.name) : '' }}</p>
          <div class="confirm-actions">
            <MiuixButton :disabled="keyboxBusy !== null" @click="close">
              {{ i18n.t('functional_button_cancel') }}
            </MiuixButton>
            <MiuixButton type="primary" :disabled="keyboxBusy !== null" @click="installKeybox">
              <MiuixProgressIndicator v-if="keyboxBusy !== null" type="circular" :size="18" />
              {{ i18n.t('functional_button_replace') }}
            </MiuixButton>
          </div>
        </div>
      </template>
    </MiuixDialog>

    <PifFingerprintDialog
      ref="pifDialog"
      v-model="pifOpen"
      :cli="cli"
      @notify="notify"
      @changed="refreshIdentity(true)"
    />
    <SoterDialog ref="soterDialog" v-model="soterOpen" :cli="cli" @notify="notify" />
    <SoterHalDialog ref="soterHalDialog" v-model="soterHalOpen" :cli="cli" @notify="notify" />
    <MiuixSnackbarHost />
  </div>
</template>
