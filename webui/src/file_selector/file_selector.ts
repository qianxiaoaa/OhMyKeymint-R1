import { exec } from 'kernelsu-alt'
import { afterPaint } from '../app_list/app_list'
import { MAX_KEYBOX_XML_BYTES, MAX_WALLPAPER_BYTES } from '../cli'
import { i18n } from '../i18n'

const STORAGE_ROOT = '/storage/emulated/0'
const INITIAL_PATH = `${STORAGE_ROOT}/Download`
const MAX_LIST_ENTRIES = 512
const MAX_LIST_OUTPUT_BYTES = 256 * 1024
const MAX_ERROR_LENGTH = 512
const SYSTEM_PICKER_RETURN_GRACE_MS = 2000

export interface FileEntry {
  name: string
  isDirectory: boolean
}

export interface SelectedContents {
  kind: 'contents'
  name: string
  contents: Uint8Array
}

export interface SelectedPath {
  kind: 'path'
  name: string
  path: string
}

export type SelectedFile = SelectedContents | SelectedPath

type Listener = () => void

export interface FileSelectorOptions {
  extensions: readonly string[]
  maxBytes?: number
  wrongTypeKey?: string
  tooLargeKey?: string
  emptyKey?: string
  /** Resolve the storage path instead of the bytes, for callers that copy the
   * file on the device (a large picture must not cross the command channel). */
  pathOnly?: boolean
}

interface Messages {
  wrongType: string
  tooLarge: string
  empty: string
}

const KEYBOX_MESSAGES: Messages = {
  wrongType: 'prompt_keybox_xml_required',
  tooLarge: 'prompt_keybox_too_large',
  empty: 'replace_keybox_storage_empty',
}

function resolveMessages(options: FileSelectorOptions): Messages {
  return {
    wrongType: options.wrongTypeKey ?? KEYBOX_MESSAGES.wrongType,
    tooLarge: options.tooLargeKey ?? KEYBOX_MESSAGES.tooLarge,
    empty: options.emptyKey ?? KEYBOX_MESSAGES.empty,
  }
}

interface PendingSelection {
  token: number
  resolve: (value: SelectedFile | null) => void
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function commandError(errno: number, stderr: string): Error {
  const detail = stderr.trim().replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, MAX_ERROR_LENGTH)
  return new Error(detail || `storage command exited with code ${errno}`)
}

function isSafeEntryName(name: string): boolean {
  return name.length > 0
    && name !== '.'
    && name !== '..'
    && !/[\\/\u0000-\u001f\u007f]/.test(name)
}

function hasFileExtension(name: string, extensions: readonly string[]): boolean {
  const lower = name.toLowerCase()
  return extensions.some(extension => lower.endsWith(`.${extension}`))
}

function joinStoragePath(parent: string, name: string): string | null {
  if (!isSafeEntryName(name)) return null
  if (parent !== STORAGE_ROOT && !parent.startsWith(`${STORAGE_ROOT}/`)) return null
  const path = `${parent}/${name}`
  return path.startsWith(`${STORAGE_ROOT}/`) ? path : null
}

function decodeBase64(value: string, maxBytes: number): Uint8Array {
  const normalized = value.replace(/[\t\n\r ]/g, '')
  const maxEncodedLength = Math.ceil(maxBytes / 3) * 4 + 16
  if (normalized.length > maxEncodedLength || normalized.length % 4 !== 0
      || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('storage command returned invalid data')
  }
  let binary: string
  try {
    binary = atob(normalized)
  } catch {
    throw new Error('storage command returned invalid data')
  }
  if (binary.length > maxBytes) throw new Error('selected file exceeds the size limit')
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function parseListing(value: string, extensions: readonly string[]): FileEntry[] {
  const bytes = decodeBase64(value, MAX_LIST_OUTPUT_BYTES)
  const entries: FileEntry[] = []
  let offset = 0
  let terminated = false
  while (offset < bytes.length) {
    const kind = bytes[offset++]
    if (offset >= bytes.length || bytes[offset++] !== 0) {
      throw new Error('storage command returned malformed entries')
    }
    if (kind === 0x78) throw new Error('folder contains too many entries')
    if (kind === 0x7a) {
      if (offset !== bytes.length) throw new Error('storage command returned malformed entries')
      terminated = true
      break
    }
    if (kind !== 0x64 && kind !== 0x66) {
      throw new Error('storage command returned malformed entries')
    }
    const end = bytes.indexOf(0, offset)
    if (end < 0) throw new Error('storage command returned malformed entries')
    let name: string
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(offset, end))
    } catch {
      throw new Error('storage command returned an invalid file name')
    }
    if (!isSafeEntryName(name)) throw new Error('storage command returned an invalid file name')
    if (kind === 0x66 && !hasFileExtension(name, extensions)) {
      throw new Error('storage command returned an invalid file')
    }
    entries.push({ name, isDirectory: kind === 0x64 })
    if (entries.length > MAX_LIST_ENTRIES) throw new Error('folder contains too many entries')
    offset = end + 1
  }
  if (!terminated) throw new Error('storage command returned an incomplete listing')
  return entries.sort((left, right) => {
    if (left.isDirectory !== right.isDirectory) return left.isDirectory ? -1 : 1
    return left.name.localeCompare(right.name, undefined, { sensitivity: 'base' })
  })
}

function shellExtensionPattern(extension: string): string {
  return extension.split('').map(character => {
    if (/[a-z]/.test(character)) return `[${character}${character.toUpperCase()}]`
    if (/[A-Z]/.test(character)) return `[${character.toLowerCase()}${character}]`
    return character
  }).join('')
}

function buildListCommand(path: string, extensions: readonly string[]): string {
  const extensionPattern = extensions
    .map(extension => `*.${shellExtensionPattern(extension)}`)
    .join('|')
  const script = [
    `root=${shellQuote(STORAGE_ROOT)}`,
    `target=${shellQuote(path)}`,
    'case "$target" in',
    '  "$root"|"$root"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    'if command -v realpath >/dev/null 2>&1; then',
    '  root_real=$(realpath "$root" 2>/dev/null) || exit 1',
    '  resolved=$(realpath "$target" 2>/dev/null) || exit 1',
    'else',
    '  root_real=$(readlink -f "$root" 2>/dev/null) || exit 1',
    '  resolved=$(readlink -f "$target" 2>/dev/null) || exit 1',
    'fi',
    'case "$resolved" in',
    '  "$root_real"|"$root_real"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    '[ -d "$resolved" ] || exit 1',
    'count=0',
    'for entry in "$resolved"/*; do',
    `  [ "$count" -le ${MAX_LIST_ENTRIES} ] || break`,
    '  [ -e "$entry" ] || continue',
    '  [ -L "$entry" ] && continue',
    '  name=${entry##*/}',
    '  if [ -d "$entry" ]; then',
    String.raw`    printf '%s\000%s\000' d "$name"`,
    '  elif [ -f "$entry" ]; then',
    '    case "$name" in',
    `      ${extensionPattern}) printf '%s\\000%s\\000' f "$name" ;;`,
    '      *) continue ;;',
    '    esac',
    '  else',
    '    continue',
    '  fi',
    '  count=$((count + 1))',
    'done',
    String.raw`if [ "$count" -gt ${MAX_LIST_ENTRIES} ]; then printf 'x\000'; else printf 'z\000'; fi`,
  ].join('\n')
  const command = `command -v base64 >/dev/null 2>&1 && command -v tr >/dev/null 2>&1 || exit 127\n{\n${script}\n} | base64 | tr -d '\\r\\n'`
  return `/system/bin/sh -c ${shellQuote(command)}`
}

function buildReadCommand(path: string, maxBytes: number): string {
  const script = [
    `root=${shellQuote(STORAGE_ROOT)}`,
    `target=${shellQuote(path)}`,
    `limit=${shellQuote(String(maxBytes))}`,
    'command -v head >/dev/null 2>&1 || exit 127',
    'command -v base64 >/dev/null 2>&1 || exit 127',
    'command -v tr >/dev/null 2>&1 || exit 127',
    'case "$target" in',
    '  "$root"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    '[ -L "$target" ] && exit 1',
    'if command -v realpath >/dev/null 2>&1; then',
    '  root_real=$(realpath "$root" 2>/dev/null) || exit 1',
    '  resolved=$(realpath "$target" 2>/dev/null) || exit 1',
    'else',
    '  root_real=$(readlink -f "$root" 2>/dev/null) || exit 1',
    '  resolved=$(readlink -f "$target" 2>/dev/null) || exit 1',
    'fi',
    'case "$resolved" in',
    '  "$root_real"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    '[ -f "$resolved" ] || exit 1',
    'bytes=$(wc -c < "$resolved") || exit 1',
    'bytes=${bytes##* }',
    'case "$bytes" in',
    '  ""|*[!0-9]*) exit 1 ;;',
    'esac',
    '[ "$bytes" -le "$limit" ] || exit 3',
    'limit_plus_one=$((limit + 1))',
    'head -c "$limit_plus_one" "$resolved" | base64 | tr -d \'\\r\\n\'',
  ].join('\n')
  return `/system/bin/sh -c ${shellQuote(script)}`
}

async function readBrowserFile(
  file: File,
  extensions: readonly string[],
  maxBytes: number,
  messages: Messages,
): Promise<SelectedContents> {
  if (!hasFileExtension(file.name, extensions)) throw new Error(i18n.t(messages.wrongType))
  if (file.size > maxBytes) throw new Error(i18n.t(messages.tooLarge))
  const contents = new Uint8Array(await file.slice(0, maxBytes + 1).arrayBuffer())
  if (contents.byteLength > maxBytes) throw new Error(i18n.t(messages.tooLarge))
  return { kind: 'contents', name: file.name, contents }
}

async function pickWithSystem(
  extensions: readonly string[],
  maxBytes: number,
  messages: Messages,
): Promise<{ supported: boolean, selected: SelectedFile | null }> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '*/*'
    input.setAttribute('aria-hidden', 'true')
    Object.assign(input.style, {
      position: 'fixed', width: '1px', height: '1px', opacity: '0', pointerEvents: 'none',
    })
    let pickerWasBackgrounded = false
    let cleanupTimer: number | null = null
    let settled = false
    const clearTimer = (): void => {
      if (cleanupTimer !== null) window.clearTimeout(cleanupTimer)
      cleanupTimer = null
    }
    const cleanup = (): void => {
      clearTimer()
      window.removeEventListener('blur', onBlur)
      window.removeEventListener('focus', onFocus)
      window.removeEventListener('pageshow', onFocus)
      window.removeEventListener('pagehide', onBlur)
      document.removeEventListener('visibilitychange', onVisibility)
      input.remove()
    }
    const finish = (value: SelectedFile | null): void => {
      if (settled) return
      settled = true
      cleanup()
      resolve({ supported: true, selected: value })
    }
    const fail = (error: unknown): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(error)
    }
    const handleFile = (): void => {
      const file = input.files?.[0]
      if (!file) return finish(null)
      clearTimer()
      void readBrowserFile(file, extensions, maxBytes, messages).then(finish, fail)
    }
    const scheduleCancel = (): void => {
      if (settled || !pickerWasBackgrounded) return
      clearTimer()
      cleanupTimer = window.setTimeout(() => {
        if (input.files?.[0]) handleFile()
        else finish(null)
      }, SYSTEM_PICKER_RETURN_GRACE_MS)
    }
    const onBlur = (): void => { pickerWasBackgrounded = true }
    const onFocus = (): void => { scheduleCancel() }
    const onVisibility = (): void => {
      if (document.visibilityState === 'hidden') pickerWasBackgrounded = true
      else scheduleCancel()
    }
    input.addEventListener('change', handleFile, { once: true })
    input.addEventListener('cancel', () => finish(null), { once: true })
    document.body.appendChild(input)
    window.addEventListener('blur', onBlur)
    window.addEventListener('focus', onFocus)
    window.addEventListener('pageshow', onFocus)
    window.addEventListener('pagehide', onBlur)
    document.addEventListener('visibilitychange', onVisibility)
    try {
      input.click()
    } catch (error) {
      settled = true
      cleanup()
      console.error('Unable to open the system file picker:', error)
      resolve({ supported: false, selected: null })
    }
  })
}

export class FileSelector {
  #listeners = new Set<Listener>()
  #pending: PendingSelection | null = null
  #token = 0
  #request = 0
  // Keep one native picker alive at a time. Android WebView providers (in
  // particular MT Manager) can leave a URI grant pending for a short while
  // after returning focus; opening a second input during that window loses
  // the first provider callback and can resolve the wrong request.
  #systemPickerActive = false
  #extensions: readonly string[] = ['xml']
  #maxBytes = MAX_KEYBOX_XML_BYTES
  #messages: Messages = KEYBOX_MESSAGES
  #pathOnly = false
  #pathStack: string[] = [STORAGE_ROOT]
  #open = false
  #loading = false
  #status = ''
  #entries: FileEntry[] = []
  #currentPath = STORAGE_ROOT

  get open(): boolean { return this.#open }
  get loading(): boolean { return this.#loading }
  get status(): string { return this.#status }
  get entries(): readonly FileEntry[] { return this.#entries }
  get currentPath(): string { return this.#currentPath }
  get canGoBack(): boolean { return this.#pathStack.length > 1 }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener)
    return () => this.#listeners.delete(listener)
  }

  async getSystemFileContent(options: FileSelectorOptions): Promise<SelectedFile | null> {
    const contentsOptions: FileSelectorOptions = { ...options, pathOnly: false }
    const maxBytes = this.#validate(contentsOptions)
    if (this.#systemPickerActive) return null
    this.#systemPickerActive = true
    let systemResult: { supported: boolean, selected: SelectedFile | null }
    try {
      systemResult = await pickWithSystem(this.#extensions, maxBytes, this.#messages)
    } finally {
      this.#systemPickerActive = false
    }
    if (systemResult.supported) return systemResult.selected
    // The native picker is unavailable, so fall back to the in-app browser and
    // keep whatever result mode the caller asked for.
    return this.getFileContent(options)
  }

  getFileContent(options: FileSelectorOptions): Promise<SelectedFile | null> {
    const maxBytes = this.#validate(options)
    this.cancel()
    this.#maxBytes = maxBytes
    this.#currentPath = INITIAL_PATH
    this.#pathStack = [STORAGE_ROOT, INITIAL_PATH]
    this.#entries = []
    this.#status = ''
    this.#open = true
    const token = ++this.#token
    const promise = new Promise<SelectedFile | null>(resolve => {
      this.#pending = { token, resolve }
    })
    this.#emit()
    void this.#loadInitialPath(token)
    return promise
  }

  async openWithAnotherApp(): Promise<void> {
    const pending = this.#pending
    if (!pending || this.#loading || this.#systemPickerActive) return
    this.#systemPickerActive = true
    this.#loading = true
    this.#status = i18n.t('replace_keybox_storage_loading')
    this.#emit()
    try {
      const result = await pickWithSystem(this.#extensions, this.#maxBytes, this.#messages)
      if (this.#pending?.token !== pending.token || !result.supported) return
      if (result.selected) this.#finish(result.selected)
    } catch (error) {
      if (this.#pending?.token !== pending.token) return
      this.#status = error instanceof Error ? error.message : String(error)
      this.#loading = false
      this.#emit()
    } finally {
      this.#systemPickerActive = false
      if (this.#pending?.token === pending.token && this.#loading) {
        this.#loading = false
        this.#emit()
      }
    }
  }

  activate(entry: FileEntry): void {
    const pending = this.#pending
    if (!pending || this.#loading) return
    const path = joinStoragePath(this.#currentPath, entry.name)
    if (!path) return
    if (entry.isDirectory) {
      this.#currentPath = path
      this.#pathStack.push(path)
      void this.#listDirectory(path, pending.token)
    } else if (this.#pathOnly) {
      this.#finish({ kind: 'path', name: entry.name, path })
    } else {
      void this.#readLocalFile(path, entry.name, pending.token)
    }
  }

  navigateBack(): void {
    const pending = this.#pending
    if (!pending || this.#loading || this.#pathStack.length <= 1) return
    this.#pathStack.pop()
    this.#currentPath = this.#pathStack[this.#pathStack.length - 1] ?? STORAGE_ROOT
    void this.#listDirectory(this.#currentPath, pending.token)
  }

  cancel(): void {
    if (this.#pending) this.#finish(null)
    else if (this.#open) {
      this.#open = false
      this.#emit()
    }
  }

  #validate(options: FileSelectorOptions): number {
    if (options.extensions.length === 0) throw new Error('Invalid file extension')
    const extensions = options.extensions.map(extension => {
      const normalized = extension.trim().replace(/^\./, '').toLowerCase()
      if (!/^[a-z0-9]{1,16}$/.test(normalized)) throw new Error('Invalid file extension')
      return normalized
    })
    const maxBytes = options.maxBytes ?? MAX_KEYBOX_XML_BYTES
    // The wallpaper limit is the largest asset any caller installs through here.
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_WALLPAPER_BYTES) {
      throw new Error('Invalid file size limit')
    }
    this.#extensions = extensions
    this.#messages = resolveMessages(options)
    this.#pathOnly = options.pathOnly === true
    return maxBytes
  }

  async #loadInitialPath(token: number): Promise<void> {
    if (await this.#listDirectory(INITIAL_PATH, token)) return
    if (this.#pending?.token !== token) return
    this.#currentPath = STORAGE_ROOT
    this.#pathStack = [STORAGE_ROOT]
    await this.#listDirectory(STORAGE_ROOT, token)
  }

  async #listDirectory(path: string, token: number): Promise<boolean> {
    if (this.#pending?.token !== token) return false
    const request = ++this.#request
    this.#loading = true
    this.#status = i18n.t('replace_keybox_storage_loading')
    this.#entries = []
    this.#emit()
    try {
      await afterPaint()
      if (this.#pending?.token !== token || request !== this.#request) return false
      const result = await exec(buildListCommand(path, this.#extensions))
      if (this.#pending?.token !== token || request !== this.#request) return false
      if (result.errno !== 0) throw commandError(result.errno, result.stderr)
      this.#entries = parseListing(result.stdout, this.#extensions)
      this.#status = this.#entries.length === 0 ? i18n.t(this.#messages.empty) : ''
      this.#loading = false
      this.#emit()
      return true
    } catch (error) {
      if (this.#pending?.token !== token || request !== this.#request) return false
      console.error('Unable to list shared-storage files:', error)
      this.#loading = false
      this.#status = i18n.t('replace_keybox_storage_error')
      this.#emit()
      return false
    }
  }

  async #readLocalFile(path: string, name: string, token: number): Promise<void> {
    if (this.#pending?.token !== token) return
    const request = ++this.#request
    this.#loading = true
    this.#status = i18n.t('replace_keybox_storage_loading')
    this.#emit()
    try {
      await afterPaint()
      if (this.#pending?.token !== token || request !== this.#request) return
      const result = await exec(buildReadCommand(path, this.#maxBytes))
      if (this.#pending?.token !== token || request !== this.#request) return
      if (result.errno !== 0) {
        if (result.errno === 3) throw new Error(i18n.t(this.#messages.tooLarge))
        throw commandError(result.errno, result.stderr)
      }
      this.#finish({ kind: 'contents', name, contents: decodeBase64(result.stdout, this.#maxBytes) })
    } catch (error) {
      if (this.#pending?.token !== token || request !== this.#request) return
      console.error('Unable to read shared-storage file:', error)
      this.#loading = false
      this.#status = error instanceof Error ? error.message : i18n.t('replace_keybox_storage_error')
      this.#emit()
    }
  }

  #finish(value: SelectedFile | null): void {
    const pending = this.#pending
    if (!pending) return
    this.#pending = null
    this.#token++
    this.#request++
    this.#open = false
    this.#loading = false
    this.#emit()
    pending.resolve(value)
  }

  #emit(): void {
    for (const listener of this.#listeners) listener()
  }
}
