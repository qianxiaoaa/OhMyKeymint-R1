<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { ComponentPublicInstance, ComputedRef } from 'vue'
import {
  MiuixBottomSheet,
  MiuixButton,
  MiuixCard,
  MiuixCheckboxPreference,
  MiuixFloatingActionButton,
  MiuixIcon,
  MiuixIconButton,
  MiuixInput,
  MiuixProgressIndicator,
  MiuixSearchBar,
  MiuixTabRow,
  MiuixTopAppBar,
  showSnackbar,
} from 'miuix-vue'
import {
  AddCircle,
  All,
  Back,
  Clear,
  Close,
  More,
  Ok,
  Refresh,
  SelectAll,
  Tune,
} from 'miuix-vue/icons'
import {
  parsePackageUserTarget,
  type AppList,
  type SelectableAppEntry,
  type SelectionFilter,
} from '../app_list/app_list'
import { type AppPatchLevels, type AppPatchProfiles, type Cli, isAppPatchLevel } from '../cli'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

interface Props {
  appList: AppList
  cli: Cli
  loading?: boolean
  applyEnabled?: boolean
}

interface SearchBarInstance extends ComponentPublicInstance {
  $el: HTMLElement
}

type IconState = 'loading' | 'loaded' | 'error'

const props = withDefaults(defineProps<Props>(), {
  loading: false,
  applyEnabled: true,
})

const emit = defineEmits<{
  close: []
  apply: []
  refresh: []
  'overlay-open': []
  'overlay-close': []
}>()

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const FILTERS: readonly SelectionFilter[] = ['all', 'selected', 'unselected']
const filterLabels = [
  translate('filter_all', 'All'),
  translate('filter_selected', 'Selected'),
  translate('filter_unselected', 'Not selected'),
]

const revision = ref(props.appList.revision)
const searchQuery = ref('')
const searchExpanded = ref(false)
const filterIndex = ref(0)
const menuOpen = ref(false)
const selectingRecommended = ref(false)
const systemSheetOpen = ref(false)
const systemSearchQuery = ref('')
const systemSelection = ref(new Set<string>())
const iconStates = ref<Record<string, IconState>>({})
const searchBar = ref<SearchBarInstance | null>(null)
const patchTarget = ref<SelectableAppEntry | null>(null)
const patchSheetOpen = ref(false)
const patchStatus = ref<'loading' | 'ready' | 'error'>('loading')
const patchBusy = ref(false)
const patchError = ref('')
const patchOs = ref('')
const patchVendor = ref('')
const patchBoot = ref('')
const patchSaved = ref<AppPatchLevels | null>(null)
let patchGeneration = 0

function patchInput(value: string): string | null {
  const trimmed = value.trim()
  return trimmed === '' || trimmed === 'auto' ? null : trimmed
}

const patchCurrent = computed<AppPatchLevels>(() => ({
  os_patchlevel: patchInput(patchOs.value),
  vendor_patchlevel: patchInput(patchVendor.value),
  boot_patchlevel: patchInput(patchBoot.value),
}))

const patchValid = computed(() => (
  isAppPatchLevel(patchCurrent.value.os_patchlevel)
  && isAppPatchLevel(patchCurrent.value.vendor_patchlevel)
  && isAppPatchLevel(patchCurrent.value.boot_patchlevel, true)
))

const patchCanSave = computed(() => (
  !isDev() && !patchBusy.value && patchStatus.value === 'ready' && patchValid.value
  && JSON.stringify(patchCurrent.value) !== JSON.stringify(patchSaved.value)
))

// A menu followed by the system sheet is one overlay in the parent's history.
// Watching the combined state also avoids closing a second layer on Android Back.
watch(() => menuOpen.value || systemSheetOpen.value || patchSheetOpen.value, open => {
  if (open) emit('overlay-open')
  else emit('overlay-close')
})

const unsubscribe = props.appList.subscribe(snapshot => {
  revision.value = snapshot.revision
})

const activeFilter = computed<SelectionFilter>(() => FILTERS[filterIndex.value] ?? 'all')
const targetEntries = computed(() => {
  void revision.value
  return props.appList.getTargetEntries(searchQuery.value, activeFilter.value)
})
const systemEntries = computed(() => {
  void revision.value
  return props.appList.getSystemEntries(systemSearchQuery.value)
})

// MIUIX preferences include animated controls. Mount a small batch per paint so
// hundreds of installed packages cannot block the sheet or navigation animation.
function batchedEntries(
  entries: ComputedRef<SelectableAppEntry[]>,
  enabled: ComputedRef<boolean>,
): ComputedRef<SelectableAppEntry[]> {
  const count = ref(0)
  let frame = 0
  let timer = 0
  let generation = 0
  const cancel = () => {
    generation++
    cancelAnimationFrame(frame)
    clearTimeout(timer)
  }
  watch([entries, enabled], ([items, active]) => {
    cancel()
    if (!active) {
      count.value = 0
      return
    }
    count.value = Math.min(Math.max(count.value, 16), items.length)
    const currentGeneration = generation
    const append = () => {
      if (currentGeneration !== generation || count.value >= items.length) return
      frame = requestAnimationFrame(() => {
        timer = window.setTimeout(() => {
          if (currentGeneration !== generation) return
          count.value = Math.min(count.value + 16, items.length)
          append()
        }, 0)
      })
    }
    append()
  }, { immediate: true })
  onBeforeUnmount(cancel)
  return computed(() => entries.value.slice(0, count.value))
}

const renderedTargetEntries = batchedEntries(targetEntries, computed(() => !props.loading))
const renderedSystemEntries = batchedEntries(
  systemEntries,
  computed(() => systemSheetOpen.value && !props.loading),
)

function iconState(packageName: string): IconState {
  return iconStates.value[packageName] ?? 'loading'
}

function setIconState(packageName: string, state: IconState): void {
  if (iconStates.value[packageName] === state) return
  iconStates.value[packageName] = state
}

function setSelected(entry: SelectableAppEntry, selected: boolean): void {
  if (props.loading || menuOpen.value || selectingRecommended.value) return
  props.appList.setTargetSelected(entry, selected)
}

function entrySummary(entry: SelectableAppEntry, allUsers = entry.selectedForAllUsers): string {
  const userLabel = translate('app_target_user', 'User')
  const currentLabel = entry.currentUser ? ` · ${translate('app_target_current_user', 'Current')}` : ''
  const scope = allUsers ? ` · ${translate('app_target_global', 'All users')}` : ''
  return `${userLabel} ${entry.userId}${currentLabel}${scope} · ${entry.packageName}`
}

async function loadPatchProfile(): Promise<void> {
  const target = patchTarget.value
  if (!target || patchBusy.value) return
  const generation = ++patchGeneration
  patchStatus.value = 'loading'
  patchError.value = ''
  patchSaved.value = null
  try {
    const profiles: AppPatchProfiles = isDev() ? {} : await props.cli.getAppPatchLevels()
    if (generation !== patchGeneration || !patchSheetOpen.value) return
    const saved = profiles[target.targetKey] ?? profiles[target.packageName]
      ?? { os_patchlevel: null, vendor_patchlevel: null, boot_patchlevel: null }
    patchOs.value = saved.os_patchlevel ?? ''
    patchVendor.value = saved.vendor_patchlevel ?? ''
    patchBoot.value = saved.boot_patchlevel ?? ''
    patchSaved.value = saved
    patchStatus.value = 'ready'
  } catch (error) {
    if (generation !== patchGeneration || !patchSheetOpen.value) return
    patchStatus.value = 'error'
    patchError.value = error instanceof Error ? error.message : String(error)
  }
}

function openPatchProfile(entry: SelectableAppEntry): void {
  if (props.loading || selectingRecommended.value || patchBusy.value) return
  menuOpen.value = false
  patchTarget.value = entry
  patchSheetOpen.value = true
  void loadPatchProfile()
}

function closePatchProfile(): void {
  if (patchBusy.value) return
  patchGeneration++
  patchSheetOpen.value = false
}

async function savePatchProfile(): Promise<void> {
  const target = patchTarget.value
  if (!target || !patchCanSave.value) return
  patchBusy.value = true
  patchError.value = ''
  try {
    const levels = { ...patchCurrent.value }
    await props.cli.setAppPatchLevels(target.targetKey, levels)
    patchSaved.value = levels
    void showSnackbar({ message: translate('app_patch_saved', 'App patch levels saved'), duration: 'long' })
  } catch (error) {
    patchError.value = error instanceof Error ? error.message : String(error)
  } finally {
    patchBusy.value = false
  }
}

async function selectRecommended(): Promise<void> {
  if (props.loading || selectingRecommended.value) return
  selectingRecommended.value = true
  try {
    await props.appList.selectRecommended()
    menuOpen.value = false
  } catch (error) {
    console.error('Unable to select recommended apps:', error)
    void showSnackbar({
      message: translate('prompt_load_error', 'Unable to load apps. Please refresh and try again.'),
      duration: 'long',
      withDismissAction: true,
    })
  } finally {
    selectingRecommended.value = false
  }
}

function deselectAll(): void {
  menuOpen.value = false
  props.appList.deselectAll()
}

function refresh(): void {
  menuOpen.value = false
  emit('refresh')
}

function apply(): void {
  if (!props.loading && !selectingRecommended.value && props.applyEnabled) emit('apply')
}

function focusSearch(): void {
  searchExpanded.value = true
  requestAnimationFrame(() => {
    searchBar.value?.$el.querySelector<HTMLInputElement>('input[type="search"]')?.focus()
  })
}

function openSystemApps(): void {
  menuOpen.value = false
  systemSearchQuery.value = ''
  // Retain bare all-user rules and unmapped selectors instead of converting
  // them to the currently visible profile list when the sheet is opened.
  systemSelection.value = new Set(props.appList.getSelectedPackages())
  systemSheetOpen.value = true
}

function setSystemSelected(targetKey: string, selected: boolean): void {
  const target = parsePackageUserTarget(targetKey)
  if (target === null) return
  const nextSelection = new Set(systemSelection.value)
  if (selected) {
    if (!nextSelection.has(target.packageName)) nextSelection.add(target.targetKey)
  } else {
    nextSelection.delete(target.targetKey)
    if (nextSelection.delete(target.packageName)) {
      for (const entry of props.appList.getSystemEntries()) {
        if (entry.packageName === target.packageName && entry.userId !== target.userId) {
          nextSelection.add(entry.targetKey)
        }
      }
    }
  }
  systemSelection.value = nextSelection
}

function saveSystemApps(): void {
  if (props.loading) return
  props.appList.applySystemAppSelection([...systemSelection.value])
  systemSheetOpen.value = false
}

function closeSystemApps(): void {
  systemSheetOpen.value = false
}

function dismissOverlay(): boolean {
  if (patchSheetOpen.value) {
    closePatchProfile()
    return true
  }
  if (systemSheetOpen.value) {
    closeSystemApps()
    return true
  }
  if (menuOpen.value) {
    menuOpen.value = false
    return true
  }
  return false
}

onBeforeUnmount(() => {
  unsubscribe()
})

defineExpose({
  focusSearch,
  selectRecommended,
  deselectAll,
  refresh,
  apply,
  openSystemApps,
  dismissOverlay,
})
</script>

<template>
  <section class="targets-view" aria-labelledby="targets-view-title">
    <div v-if="menuOpen" class="targets-menu-scrim" @click="menuOpen = false" />
    <div class="targets-top-bar">
      <MiuixTopAppBar
        id="targets-view-title"
        :title="translate('app_targets_title', 'Add package names')"
        color="transparent"
      >
        <template #navigation>
          <MiuixIconButton
            :aria-label="translate('functional_button_back', 'Back')"
            @click="emit('close')"
          >
            <MiuixIcon :icon="Back" />
          </MiuixIconButton>
        </template>

        <template #actions>
          <div class="targets-menu">
            <MiuixIconButton
              class="targets-menu-toggle"
              :hold-down="menuOpen"
              :aria-label="translate('menu_more_options', 'More options')"
              aria-haspopup="menu"
              :aria-expanded="menuOpen"
              @click.stop="menuOpen = !menuOpen"
            >
              <MiuixIcon :icon="More" />
            </MiuixIconButton>

            <Transition name="targets-menu">
              <MiuixCard v-if="menuOpen" class="targets-menu-popup" role="menu">
                <MiuixButton role="menuitem" :disabled="loading || selectingRecommended" @click="selectRecommended">
                  <MiuixProgressIndicator v-if="selectingRecommended" type="circular" :size="21" />
                  <MiuixIcon v-else :icon="SelectAll" :size="21" />
                  <span class="targets-menu-label">
                    <span>{{ translate('menu_select_all', 'Select recommended apps') }}</span>
                    <small>{{ translate('menu_select_recommended_desc', 'User apps and Google services; skip recognized Root, Shizuku and Xposed tools. Keep existing selections.') }}</small>
                  </span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="selectingRecommended" @click="deselectAll">
                  <MiuixIcon :icon="Clear" :size="21" />
                  <span>{{ translate('menu_deselect_all', 'Deselect all') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="loading || selectingRecommended" @click="refresh">
                  <MiuixIcon :icon="Refresh" :size="21" />
                  <span>{{ translate('menu_refresh', 'Refresh') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="loading || selectingRecommended" @click="openSystemApps">
                  <MiuixIcon :icon="AddCircle" :size="21" />
                  <span>{{ translate('menu_add_system_app', 'Add System App') }}</span>
                </MiuixButton>
              </MiuixCard>
            </Transition>
          </div>
        </template>
      </MiuixTopAppBar>

      <MiuixSearchBar
        ref="searchBar"
        v-model="searchQuery"
        v-model:expanded="searchExpanded"
        :label="translate('search_bar_search_placeholder', 'Search')"
        :cancel-text="translate('functional_button_cancel', 'Cancel')"
        @focusin="menuOpen = false"
      />

      <div class="targets-filter" :aria-label="translate('app_targets_filter_aria', 'Filter apps')">
        <MiuixTabRow
          contour
          :model-value="filterIndex"
          :tabs="filterLabels"
          @update:model-value="filterIndex = $event; menuOpen = false"
        />
      </div>
    </div>

    <main class="targets-content" :aria-busy="loading">
      <p v-if="!loading" class="targets-scope-note">
        {{ translate('app_target_all_users', 'Select apps per Android user. Existing all-user rules remain until edited. Apps sharing a UID share routing.') }}
      </p>
      <div v-if="loading" class="targets-loading" role="status">
        <MiuixProgressIndicator type="circular" :size="34" />
        <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
      </div>

      <MiuixCard v-else-if="targetEntries.length > 0" class="targets-list">
        <MiuixCheckboxPreference
          v-for="entry in renderedTargetEntries"
          v-memo="[entry.selected, entry.selectedForAllUsers, entry.appName, entry.targetKey, entry.currentUser, iconState(entry.packageName), selectingRecommended]"
          :key="entry.targetKey"
          :model-value="entry.selected"
          :disabled="selectingRecommended"
          :title="entry.appName"
          :summary="entrySummary(entry)"
          location="end"
          @update:model-value="setSelected(entry, $event)"
        >
          <template #end>
            <MiuixIconButton
              :aria-label="translate('app_patch_title', 'App patch levels')"
              :disabled="selectingRecommended"
              @click.stop="openPatchProfile(entry)"
            >
              <MiuixIcon :icon="Tune" :size="20" />
            </MiuixIconButton>
          </template>
          <template #start>
            <span class="app-icon-frame" :class="`app-icon-frame--${iconState(entry.packageName)}`">
              <img
                class="app-icon"
                :src="`ksu://icon/${entry.packageName}`"
                :alt="entry.appName"
                loading="lazy"
                decoding="async"
                draggable="false"
                @load="setIconState(entry.packageName, 'loaded')"
                @error="setIconState(entry.packageName, 'error')"
              >
              <MiuixIcon
                v-if="iconState(entry.packageName) !== 'loaded'"
                class="app-icon-fallback"
                :icon="All"
                :size="24"
              />
            </span>
          </template>
        </MiuixCheckboxPreference>
        <div v-if="renderedTargetEntries.length < targetEntries.length" class="app-list-batch-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="24" />
          <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
        </div>
      </MiuixCard>

      <div v-else class="targets-empty">
        <MiuixIcon :icon="All" :size="34" />
        <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
      </div>
    </main>

    <MiuixFloatingActionButton
      v-show="!systemSheetOpen && !patchSheetOpen"
      class="targets-apply"
      :disabled="loading || selectingRecommended || !applyEnabled"
      :aria-label="translate('functional_button_apply', 'Apply')"
      :title="translate('functional_button_apply', 'Apply')"
      @click="apply"
    >
      <MiuixProgressIndicator
        v-if="loading"
        type="circular"
        :size="27"
        :stroke-width="3"
      />
      <MiuixIcon v-else :icon="Ok" />
    </MiuixFloatingActionButton>

    <MiuixBottomSheet
      v-model="systemSheetOpen"
      :title="translate('add_system_app_title', 'Add System App')"
    >
      <template #start-action>
        <MiuixIconButton
          :aria-label="translate('functional_button_cancel', 'Cancel')"
          @click="closeSystemApps"
        >
          <MiuixIcon :icon="Close" />
        </MiuixIconButton>
      </template>
      <template #end-action>
        <MiuixButton type="primary" :disabled="loading" @click="saveSystemApps">
          {{ translate('functional_button_save', 'Save') }}
        </MiuixButton>
      </template>

      <div class="system-app-sheet">
        <p class="targets-scope-note">
          {{ translate('app_target_all_users', 'Select apps per Android user. Existing all-user rules remain until edited. Apps sharing a UID share routing.') }}
        </p>
        <MiuixSearchBar
          v-model="systemSearchQuery"
          :label="translate('search_bar_search_placeholder', 'Search')"
          :cancel-text="translate('functional_button_cancel', 'Cancel')"
        />

        <div v-if="loading" class="system-app-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="32" />
        </div>

        <MiuixCard v-else-if="systemEntries.length > 0" class="system-app-list">
          <MiuixCheckboxPreference
            v-for="entry in renderedSystemEntries"
            v-memo="[systemSelection.has(entry.targetKey), systemSelection.has(entry.packageName), entry.appName, entry.targetKey, entry.currentUser, iconState(entry.packageName)]"
            :key="entry.targetKey"
            :model-value="systemSelection.has(entry.targetKey) || systemSelection.has(entry.packageName)"
            :title="entry.appName"
            :summary="entrySummary(entry, systemSelection.has(entry.packageName))"
            location="end"
            @update:model-value="setSystemSelected(entry.targetKey, $event)"
          >
            <template #start>
              <span class="app-icon-frame" :class="`app-icon-frame--${iconState(entry.packageName)}`">
                <img
                  class="app-icon"
                  :src="`ksu://icon/${entry.packageName}`"
                  :alt="entry.appName"
                  loading="lazy"
                  decoding="async"
                  draggable="false"
                  @load="setIconState(entry.packageName, 'loaded')"
                  @error="setIconState(entry.packageName, 'error')"
                >
                <MiuixIcon
                  v-if="iconState(entry.packageName) !== 'loaded'"
                  class="app-icon-fallback"
                  :icon="All"
                  :size="24"
                />
              </span>
            </template>
          </MiuixCheckboxPreference>
          <div v-if="renderedSystemEntries.length < systemEntries.length" class="app-list-batch-loading" role="status">
            <MiuixProgressIndicator type="circular" :size="24" />
            <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
          </div>
        </MiuixCard>

        <div v-else class="targets-empty targets-empty--sheet">
          <MiuixIcon :icon="All" :size="32" />
          <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
        </div>
      </div>
    </MiuixBottomSheet>

    <MiuixBottomSheet
      :model-value="patchSheetOpen"
      :title="translate('app_patch_title', 'App patch levels')"
      :allow-dismiss="!patchBusy"
      :close-on-click-modal="!patchBusy"
      @update:model-value="value => { if (!value) closePatchProfile() }"
    >
      <template #start-action>
        <MiuixIconButton
          :disabled="patchBusy"
          :aria-label="translate('functional_button_close', 'Close')"
          @click="closePatchProfile"
        >
          <MiuixIcon :icon="Close" />
        </MiuixIconButton>
      </template>
      <template #end-action>
        <MiuixButton type="primary" :disabled="!patchCanSave" @click="savePatchProfile">
          <MiuixProgressIndicator v-if="patchBusy" type="circular" :size="18" />
          {{ translate('functional_button_save', 'Save') }}
        </MiuixButton>
      </template>
      <div v-if="patchTarget" class="app-patch-sheet" :aria-busy="patchBusy || patchStatus === 'loading'">
        <div class="app-patch-identity">
          <strong>{{ patchTarget.appName }}</strong>
          <span>{{ patchTarget.packageName }} · {{ translate('app_target_user', 'User') }} {{ patchTarget.userId }}</span>
        </div>
        <p class="app-patch-hint">
          {{ translate('app_patch_scope', 'This profile applies to this Android user. Leave a field empty or use auto to inherit the global patch level.') }}
        </p>
        <p class="app-patch-hint">
          {{ translate('app_patch_shared_uid', 'Apps sharing a UID must resolve to the same patch dates. Conflicting profiles are rejected.') }}
        </p>
        <div v-if="patchStatus === 'loading'" class="system-app-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="28" />
        </div>
        <template v-else-if="patchStatus === 'ready'">
          <MiuixInput
            v-model="patchOs"
            :disabled="patchBusy"
            :label="translate('app_patch_os', 'OS patch level')"
            placeholder="YYYY-MM-DD / auto"
          />
          <MiuixInput
            v-model="patchVendor"
            :disabled="patchBusy"
            :label="translate('app_patch_vendor', 'Vendor patch level')"
            placeholder="YYYY-MM-DD / auto"
          />
          <MiuixInput
            v-model="patchBoot"
            :disabled="patchBusy"
            :label="translate('app_patch_boot', 'Boot patch level')"
            placeholder="YYYY-MM-DD / auto"
          />
          <p v-if="!patchValid" class="app-patch-error" role="alert">
            {{ translate('app_patch_invalid', 'Use a valid YYYY-MM-DD date, auto, or an empty field. Boot also accepts a raw unsigned 32-bit value.') }}
          </p>
          <MiuixButton :disabled="patchBusy" @click="patchOs = ''; patchVendor = ''; patchBoot = ''">
            {{ translate('app_patch_inherit', 'Use global defaults') }}
          </MiuixButton>
        </template>
        <p v-if="patchError" class="app-patch-error" role="alert">{{ patchError }}</p>
        <MiuixButton v-if="patchStatus === 'error'" @click="loadPatchProfile">
          {{ translate('functional_button_retry', 'Retry') }}
        </MiuixButton>
        <p v-if="isDev()" class="app-patch-hint">
          {{ translate('app_patch_preview', 'Preview only. Device settings cannot be saved here.') }}
        </p>
      </div>
    </MiuixBottomSheet>
  </section>
</template>

<style scoped>
.app-patch-sheet { display: flex; flex-direction: column; gap: 14px; padding-bottom: 12px; }
.app-patch-identity { display: grid; gap: 4px; min-width: 0; }
.app-patch-identity strong { font-size: 17px; line-height: 1.4; color: var(--m-color-on-surface); }
.app-patch-identity span { overflow-wrap: anywhere; font-size: 13px; line-height: 1.5; color: var(--m-color-on-surface-variant-summary); }
.app-patch-hint { margin: 0; font-size: 14px; line-height: 1.5; color: var(--m-color-on-surface-variant-summary); }
.app-patch-error { margin: 0; font-size: 14px; line-height: 1.5; color: var(--m-color-error); overflow-wrap: anywhere; }

.targets-scope-note {
  margin: 0 0 12px;
  font-size: 14px;
  line-height: 1.5;
  color: var(--m-color-on-surface-variant-summary);
}

.targets-view {
  position: relative;
  box-sizing: border-box;
  min-height: 100%;
  color: var(--m-color-on-background);
  background: var(--m-color-surface);
}

.targets-top-bar {
  position: sticky;
  z-index: 40;
  top: 0;
  box-sizing: border-box;
  padding-top: calc(var(--omk-top-inset) / var(--omk-ui-scale));
  /* Keep a solid fallback for older Android WebViews that do not implement
     CSS color-mix; the translucent value is then layered on when supported. */
  background: var(--m-color-surface);
  background: color-mix(in srgb, var(--m-color-surface) 92%, transparent);
  backdrop-filter: blur(18px) saturate(1.25);
}

.targets-top-bar :deep(.m-top-app-bar__nav) {
  padding-inline-start: 8px;
  padding-inline-end: 0;
}

.targets-top-bar :deep(.m-top-app-bar__actions) {
  padding-inline-start: 0;
  padding-inline-end: 8px;
}

.targets-menu {
  position: relative;
}

.targets-menu-scrim {
  position: fixed;
  z-index: 35;
  inset: 0;
}

.targets-menu-toggle {
  position: relative;
  z-index: 41;
}

.targets-menu-popup {
  position: absolute;
  z-index: 50;
  top: calc(100% + 6px);
  inset-inline-end: 0;
  box-sizing: border-box;
  width: min(296px, calc(100vw - 24px));
  min-width: min(296px, calc(100vw - 24px));
  max-height: calc(100vh - 116px);
  max-height: calc(100dvh - 116px);
  overflow-y: auto;
  padding: 6px;
  border: 1px solid color-mix(in srgb, var(--m-color-on-surface) 7%, transparent);
  border-radius: 20px;
  background: var(--m-color-surface-container);
  background: color-mix(in srgb, var(--m-color-surface-container) 96%, transparent);
  box-shadow: 0 14px 36px rgb(0 0 0 / 18%), 0 3px 10px rgb(0 0 0 / 9%);
  backdrop-filter: blur(22px) saturate(1.15);
  scrollbar-width: none;
  -ms-overflow-style: none;
}

.targets-menu-popup::-webkit-scrollbar {
  display: none;
}

.targets-menu-popup :deep(.m-card) {
  gap: 0;
  padding: 0;
  border-radius: inherit;
  background: transparent;
}

.targets-menu-popup :deep(.m-button) {
  width: 100%;
  min-height: 48px;
  justify-content: flex-start;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 16px;
  background: transparent;
  color: var(--m-color-on-surface);
  font-size: 17px;
  font-weight: 400;
  line-height: 1.25;
  white-space: normal;
  text-align: start;
}

.targets-menu-label {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.targets-menu-label small {
  color: var(--m-color-on-surface-variant-summary);
  font-size: 13px;
  font-weight: 400;
  line-height: 1.4;
}

.targets-menu-popup :deep(.m-button:hover),
.targets-menu-popup :deep(.m-button:focus-visible) {
  background: color-mix(in srgb, var(--m-color-on-surface) 7%, transparent);
}

.targets-menu-popup :deep(.m-button::after) {
  display: none;
}

.targets-menu-popup :deep(.m-button:active) {
  background: color-mix(in srgb, var(--m-color-primary) 12%, transparent);
}

.targets-menu-popup :deep(.m-button .m-icon) {
  flex: none;
  color: var(--m-color-on-surface);
}

.targets-menu-enter-active,
.targets-menu-leave-active {
  transition: opacity 140ms ease, transform 180ms cubic-bezier(.2, .8, .2, 1);
  transform-origin: top right;
}

[dir='rtl'] .targets-menu-enter-active,
[dir='rtl'] .targets-menu-leave-active {
  transform-origin: top left;
}

.targets-menu-enter-from,
.targets-menu-leave-to {
  opacity: 0;
  transform: translateY(-5px) scale(.97);
}

.targets-filter {
  box-sizing: border-box;
  width: min(100%, 680px);
  margin: 7px auto 0;
  padding: 0 12px 10px;
}

.targets-filter :deep(.m-tab-row__scroll) {
  background: var(--m-color-surface-container-high);
}

.targets-content {
  box-sizing: border-box;
  width: min(100%, 680px);
  min-height: 240px;
  margin: 0 auto;
  padding: 8px 12px calc(96px + var(--omk-bottom-inset) / var(--omk-ui-scale));
}

.targets-list,
.system-app-list {
  width: 100%;
}

.targets-list :deep(.m-basic-component),
.system-app-list :deep(.m-basic-component) {
  min-height: 68px;
  padding: 10px 14px;
}

.targets-list :deep(.m-basic-component__row),
.system-app-list :deep(.m-basic-component__row) {
  gap: 12px;
}

.targets-list :deep(.m-basic-component__center),
.system-app-list :deep(.m-basic-component__center) {
  overflow: hidden;
}

.targets-list :deep(.m-basic-component__center > *),
.system-app-list :deep(.m-basic-component__center > *) {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.targets-list :deep(.m-basic-component + .m-basic-component),
.system-app-list :deep(.m-basic-component + .m-basic-component) {
  border-top: 1px solid var(--m-color-divider-line);
}

.app-icon-frame {
  position: relative;
  box-sizing: border-box;
  display: inline-flex;
  flex: none;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  overflow: hidden;
  border-radius: 10px;
  color: var(--m-color-on-tertiary-container);
  background: var(--m-color-tertiary-container);
}

.app-icon {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  opacity: 0;
}

.app-icon-frame--loaded .app-icon {
  opacity: 1;
}

.app-icon-fallback {
  opacity: .8;
}

.app-list-batch-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 64px;
}

.targets-loading,
.system-app-loading,
.targets-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 220px;
  color: var(--m-color-on-surface-variant-summary);
}

.targets-empty {
  flex-direction: column;
  gap: 10px;
  text-align: center;
}

.targets-empty p {
  margin: 0;
  font-size: 15px;
}

.targets-apply {
  position: fixed;
  z-index: 30;
  right: calc(20px + var(--omk-right-inset) / var(--omk-ui-scale));
  bottom: calc(14px + var(--omk-bottom-inset) / var(--omk-ui-scale));
}

[dir='rtl'] .targets-apply {
  right: auto;
  left: calc(20px + var(--omk-left-inset) / var(--omk-ui-scale));
}

.system-app-sheet {
  box-sizing: border-box;
  min-height: min(65vh, 520px);
  /* The teleported MIUIX sheet already reserves the system gesture area. */
  padding-bottom: 18px;
}

.system-app-sheet > :deep(.m-search-bar) {
  position: sticky;
  z-index: 2;
  top: 0;
  padding: 2px 0 12px;
  background: var(--m-color-background);
}

.targets-empty--sheet {
  min-height: 180px;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

@media (max-width: 420px) {
  .targets-filter,
  .targets-content {
    padding-inline: 10px;
  }

  .targets-list :deep(.m-basic-component),
  .system-app-list :deep(.m-basic-component) {
    padding-inline: 12px;
  }

  .system-app-sheet {
    min-height: 68vh;
  }
}

@media (prefers-reduced-motion: reduce) {
  .targets-menu-enter-active,
  .targets-menu-leave-active {
    transition: none;
  }
}
</style>
