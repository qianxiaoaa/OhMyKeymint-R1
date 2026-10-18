import { reactive } from 'vue'
import type { Cli, WallpaperState } from './cli'

const DEFAULT_URL = 'assets/wallpaper/default.jpg'

interface WallpaperStore {
  state: WallpaperState | null
  loading: boolean
  busy: boolean
  status: string
}

const store = reactive<WallpaperStore>({
  state: null,
  loading: false,
  busy: false,
  status: '',
})

function assetUrl(state: WallpaperState | null): string {
  // The state URL is whitelisted by the CLI parser, so it only ever points at a
  // module asset. The timestamp is a cache buster: the WebView keeps the old
  // picture under the same custom.* name otherwise.
  const name = state?.url ?? DEFAULT_URL
  const version = state && state.custom ? state.updated_at : 0
  return version > 0 ? `${name}?v=${version}` : name
}

function resolvedUrl(state: WallpaperState | null): string {
  return new URL(assetUrl(state), document.baseURI).href
}

function apply(): void {
  const root = document.documentElement
  root.style.setProperty('--omk-wallpaper-url', `url("${assetUrl(store.state)}")`)
  root.dataset.wallpaper = store.state?.custom ? 'custom' : 'default'
}

async function load(cli: Cli): Promise<void> {
  if (store.loading) return
  store.loading = true
  store.status = ''
  // Paint the packaged default before the state round-trip so the first frame
  // is already glass; a custom picture replaces it as soon as it decodes.
  apply()
  try {
    store.state = await cli.getWallpaper()
  } catch {
    // Unreadable state means the packaged default is showing; keep the normal row text.
    store.state = null
  } finally {
    store.loading = false
  }
  // Paint only once the picture is decodable, so a failed install cannot leave
  // the page with a background that renders nothing.
  const image = new Image()
  image.onload = apply
  image.onerror = apply
  image.src = resolvedUrl(store.state)
  if (image.complete) apply()
}

async function run(cli: Cli, action: (client: Cli) => Promise<WallpaperState>): Promise<boolean> {
  if (store.busy) return false
  store.busy = true
  store.status = ''
  try {
    store.state = await action(cli)
    store.busy = false
    await load(cli)
    return true
  } catch (error) {
    store.busy = false
    store.status = error instanceof Error ? error.message : String(error)
    return false
  }
}

export const wallpaper = {
  get state(): WallpaperState | null { return store.state },
  get loading(): boolean { return store.loading },
  get busy(): boolean { return store.busy },
  get status(): string { return store.status },
  get previewUrl(): string { return resolvedUrl(store.state) },

  load,

  async installFromStorage(cli: Cli, path: string): Promise<boolean> {
    return run(cli, client => client.installWallpaperFromStorage(path))
  },

  async installBytes(cli: Cli, contents: Uint8Array): Promise<boolean> {
    return run(cli, client => client.installWallpaper(contents))
  },

  async reset(cli: Cli): Promise<boolean> {
    return run(cli, client => client.resetWallpaper())
  },
}
