const PACKAGE_NAME = /^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$/

export function isValidPackageName(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 255
    && PACKAGE_NAME.test(value)
}

export function normalizePackageNames(values: unknown): string[] {
  if (!Array.isArray(values) || !values.every(isValidPackageName)) {
    throw new Error('Invalid package list returned by OMK')
  }
  return [...new Set(values)]
}

export type ScoopTarget =
  | { kind: 'package'; packageName: string; target: string }
  | { kind: 'package-user'; packageName: string; userId: number; target: string }
  | { kind: 'uid'; uid: number; target: string }

export function parseScoopTarget(value: unknown): ScoopTarget | null {
  if (typeof value !== 'string') return null
  const target = value.trim()
  if (isValidPackageName(target)) return { kind: 'package', packageName: target, target }
  const uidMatch = /^uid:(\d+)$/.exec(target)
  if (uidMatch) {
    const uid = Number(uidMatch[1])
    return Number.isInteger(uid) && uid <= 0xffff_ffff
      ? { kind: 'uid', uid, target: `uid:${uid}` }
      : null
  }
  const userMatch = /^(.+)@(\d+)$/.exec(target)
  if (!userMatch || !isValidPackageName(userMatch[1])) return null
  const userId = Number(userMatch[2])
  return Number.isInteger(userId) && userId <= Math.floor(0xffff_ffff / 100_000)
    ? { kind: 'package-user', packageName: userMatch[1], userId, target: `${userMatch[1]}@${userId}` }
    : null
}

export function normalizeScoopTargets(values: unknown): string[] {
  if (!Array.isArray(values)) throw new Error('Invalid caller target list returned by OMK')
  const normalized = values.map(parseScoopTarget)
  if (normalized.some(target => target === null)) {
    throw new Error('Invalid caller target list returned by OMK')
  }
  return [...new Set(normalized.map(target => target!.target))]
}
