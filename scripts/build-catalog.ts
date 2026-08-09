import { writeFileSync } from 'node:fs'
import type { CatalogEntry, ListType, LoadTier, Tier } from '../src/core/types'

const TREE_URL =
  'https://api.github.com/repos/MISP/misp-warninglists/git/trees/main?recursive=1'
const RAW = 'https://raw.githubusercontent.com/MISP/misp-warninglists/main'

/** Lists excluded entirely: file-hash lists, out of scope for v1. */
const EXCLUDED = new Set(['windows-binary-hashes', 'nioc-filehash'])

/** Only these two are large enough to defer behind an opt-in. */
const HEAVY = new Set(['tranco', 'google-chrome-crux-1million'])

const INFRASTRUCTURE = new Set([
  'akamai', 'amazon-aws', 'apple', 'cloudflare', 'fastly', 'github', 'google',
  'google-gcp', 'google-gmail-sending-ips', 'googlebot', 'microsoft',
  'microsoft-azure', 'microsoft-azure-appid', 'microsoft-azure-china',
  'microsoft-azure-germany', 'microsoft-azure-us-gov', 'microsoft-office365',
  'microsoft-office365-cn', 'microsoft-office365-ip',
  'microsoft-win10-connection-endpoints', 'mozilla-CA', 'mozilla-IntermediateCA',
  'ovh-cluster', 'public-dns-hostname', 'public-dns-v4', 'public-dns-v6',
  'smtp-receiving-ips', 'smtp-sending-ips', 'stackpath', 'telegram-ips',
  'tenable-cloud-ipv4', 'tenable-cloud-ipv6', 'wikimedia', 'zscaler',
  'crl-hostname', 'crl-ip', 'captive-portals', 'openai-gptbot',
])

const KNOWN_FP = new Set([
  'ti-falsepositives', 'common-ioc-false-positive', 'rfc1918', 'rfc3849',
  'rfc5735', 'rfc6598', 'rfc6761', 'ipv6-linklocal', 'multicast',
  'covid-19-cyber-threat-coalition-whitelist', 'covid-19-krassi-whitelist',
  'eicar.com', 'empty-hashes', 'second-level-tlds', 'tlds',
  'microsoft-attack-simulator', 'whats-my-ip', 'university_domains',
  'bank-website', 'dax30', 'sinkholes',
])

const POPULARITY = new Set([
  'alexa', 'cisco_top1000', 'cisco_top5k', 'cisco_top10k', 'cisco_top20k',
  'google-chrome-crux-1million', 'majestic_million', 'moz-top500', 'tranco',
  'tranco10k',
])

const CONTEXT = new Set([
  'dynamic-dns', 'vpn-ipv4', 'vpn-ipv6', 'url-shortener', 'link-in-bio',
  'parking-domain', 'parking-domain-ns', 'disposable-email', 'covid',
  'automated-malware-analysis', 'security-provider-blogpost', 'digitalside',
  'lots-project', 'public-ipfs-gateways', 'findip-host', 'check-host-net',
  'shadowserver', 'modat-scanner', 'onyphe-scanner', 'internetcleanup-scanner',
  'umbrella-blockpage-hostname', 'umbrella-blockpage-v4', 'umbrella-blockpage-v6',
  'umich-cse-connection-attempts', 'palo-alto-networks-cortex-xpanse',
  'common-contact-emails', 'phone_numbers',
])

/**
 * Presentation tier. Name-suffix rule for scanners comes first so that
 * scanner lists added upstream self-classify without a catalog edit.
 */
export function assignTier(name: string, _type: ListType, _attrs: string[]): Tier {
  if (name.endsWith('-scanning') || name.endsWith('-nt-scanning')) return 'context'
  if (INFRASTRUCTURE.has(name)) return 'infrastructure'
  if (KNOWN_FP.has(name)) return 'known-fp'
  if (POPULARITY.has(name)) return 'popularity'
  if (CONTEXT.has(name)) return 'context'
  return 'neutral'
}

export function assignLoadTier(name: string): LoadTier {
  return HEAVY.has(name) ? 'heavy' : 'core'
}

interface UpstreamList {
  description: string
  list: string[]
  matching_attributes: string[]
  name: string
  type: ListType
  version: number
}

async function main(): Promise<void> {
  const tree = (await (await fetch(TREE_URL)).json()) as {
    tree: Array<{ path: string; type: string; size?: number }>
  }

  const files = tree.tree.filter(
    (e) => e.type === 'blob' && e.path.endsWith('/list.json'),
  )

  const entries: CatalogEntry[] = []
  for (const f of files) {
    const name = f.path.split('/')[1]!
    if (EXCLUDED.has(name)) continue

    const res = await fetch(`${RAW}/${f.path}`)
    if (!res.ok) throw new Error(`fetch failed for ${name}: ${res.status}`)
    const body = (await res.json()) as UpstreamList

    entries.push({
      name,
      title: body.name,
      description: body.description,
      type: body.type,
      matchingAttributes: body.matching_attributes,
      tier: assignTier(name, body.type, body.matching_attributes),
      loadTier: assignLoadTier(name),
      bytes: f.size ?? 0,
    })
    console.log(`${name} ${body.type} ${assignTier(name, body.type, body.matching_attributes)}`)
  }

  entries.sort((a, b) => a.name.localeCompare(b.name))
  writeFileSync('src/catalog.json', JSON.stringify(entries, null, 2) + '\n')
  console.log(`\nwrote ${entries.length} entries`)
}

// Only run when invoked directly, so importing for tests does not hit the network.
if (import.meta.url === `file://${process.argv[1]}`) {
  await main()
}
