import { readFile, readdir } from 'node:fs/promises'
import { extname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const frontendRoot = fileURLToPath(new URL('..', import.meta.url))
const sourceRoot = join(frontendRoot, 'src')
const allowedExtensions = new Set(['.css', '.ts', '.tsx'])
const failures = []

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const nested = await Promise.all(
    entries.map((entry) => {
      const path = join(directory, entry.name)
      return entry.isDirectory() ? collectFiles(path) : [path]
    }),
  )
  return nested.flat()
}

function report(path, line, message) {
  failures.push(`${relative(frontendRoot, path)}:${line}: ${message}`)
}

function lineNumber(text, index) {
  return text.slice(0, index).split('\n').length
}

function checkSource(path, text) {
  for (const match of text.matchAll(/\u2014/g)) {
    report(path, lineNumber(text, match.index), 'use plain punctuation instead of an em dash')
  }

  for (const match of text.matchAll(/description="([^"]+)"/g)) {
    if (match[1].length > 100) {
      report(
        path,
        lineNumber(text, match.index),
        `page description is ${match[1].length} characters; keep it at 100 or fewer`,
      )
    }
  }

  const templateEffects = [
    ['rounded-3xl', 'oversized generic card rounding'],
    ['backdrop-blur', 'decorative glass effect'],
    ['text-transparent', 'decorative gradient text'],
    ['bg-gradient-to-', 'decorative background gradient'],
    ['shadow-[0_0_', 'decorative glow shadow'],
  ]
  for (const [token, label] of templateEffects) {
    let start = 0
    while ((start = text.indexOf(token, start)) !== -1) {
      report(path, lineNumber(text, start), `${label} is not part of this product UI`)
      start += token.length
    }
  }
}

const sourceFiles = (await collectFiles(sourceRoot)).filter((path) =>
  allowedExtensions.has(extname(path)),
)
sourceFiles.push(join(frontendRoot, 'index.html'))

for (const path of sourceFiles) {
  checkSource(path, await readFile(path, 'utf8'))
}

const themePath = join(sourceRoot, 'styles', 'theme.css')
const theme = await readFile(themePath, 'utf8')
const rootContract = theme.match(/html,\s*\n?body,\s*\n?#root\s*\{([\s\S]*?)\}/)?.[1] ?? ''
if (!/overflow:\s*hidden;/.test(rootContract)) {
  report(themePath, 1, 'html, body, and #root must contain overflow with one app scroller')
}

const layoutPath = join(sourceRoot, 'components', 'Layout.tsx')
const layout = await readFile(layoutPath, 'utf8')
if (!layout.includes('overflow-x-hidden overflow-y-auto')) {
  report(layoutPath, 1, 'the app content region must own vertical scrolling and contain width')
}

const apiPath = join(sourceRoot, 'lib', 'api.ts')
const api = await readFile(apiPath, 'utf8')
if (!api.includes('normalizeUiCopy((await r.json()) as T)')) {
  report(apiPath, 1, 'API-fed copy must pass through the shared UI punctuation normalizer')
}

if (failures.length) {
  console.error('UI quality checks failed:\n')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log(`UI quality checks passed (${sourceFiles.length} files).`)
