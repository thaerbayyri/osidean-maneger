"""
Obsidian Vault Reorganizer  (Taxonomy Edition)
==============================================
Organizes a vault using a PREDEFINED topic taxonomy supplied by the user.

Two layers
----------
1. PRIMARY TOPIC  (one per note) -> tag in frontmatter + section in MOC.md
2. CYBER DOMAINS  (multi-label)  -> copies of the file go into
                                    "cyber domains/<Domain>/" subfolders.

Safe by default
---------------
* Dry-run unless --apply
* Full timestamped backup before any change
* Re-running is idempotent (auto-block markers in each note)

Usage
-----
    pip install scikit-learn numpy
    python obsidian_reorganize.py "D:\\bayyari\\bmt"
    python obsidian_reorganize.py "D:\\bayyari\\bmt" --apply
"""

import argparse
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
except ImportError:
    print("Missing dependencies. Install with:\n    pip install scikit-learn numpy")
    sys.exit(1)


# =============================================================================
# TAXONOMY  -- edit these keyword lists to tune classification.
# Tip: pad short/ambiguous tokens with spaces (e.g. ' ad ', ' soc ') to enforce
# word boundaries. Multi-word phrases are matched as plain substrings.
# =============================================================================

PRIMARY_TOPICS = {
    'Linux'            : ['linux','ubuntu','debian','kali','centos','redhat','rhel','fedora','arch linux',
                          'bash','shell script','systemd','apt-get',' apt ',' yum',' dnf','grep ',' sed ',
                          ' awk ','/etc/','/var/',' sudo','cron','iptables','nftables'],
    'Windows'          : ['windows','win10','win11','win 10','win 11','powershell','wmi','sysmon',
                          'event viewer','active directory',' ad ','active-directory','ntlm','kerberos',
                          'registry','group policy',' gpo ','cmd.exe','windefend'],
    'Network'          : ['network','networking',' tcp','udp ','tcp/ip',' ip ',' dns','dhcp','vlan',
                          'subnet','routing','router','switch','firewall','vpn ',' ospf',' bgp',' nat ',
                          'packet','wireshark','nmap','port scan','osi model',' ftp ',' ssh '],
    'Cloud'            : ['cloud',' aws','amazon web services',' azure',' gcp','google cloud',' ec2',
                          ' s3 ','lambda ','kubernetes',' k8s','terraform','cloudformation','iam role',
                          ' vpc',' eks',' aks',' gke'],
    'HTU Camp'         : ['htu','htu camp','hashemite university','bayyari camp'],
    'Docker'           : ['docker','dockerfile','docker compose','docker-compose','container image',
                          'containerization','docker hub','podman'],
    'Tools'            : ['toolkit','utility','cheatsheet','cheat sheet','reference card','tooling',
                          'tool collection'],
    'Notion'           : ['notion','notion.so'],
    'N8N'              : [' n8n ','workflow automation','no-code automation','low-code automation'],
    'Certificates'     : ['certificate','certification','certified',' ceh ',' oscp','security+',
                          'sec+ ','comptia','sans ',' giac','gcih',' gpen','gcfa','exam','study guide',
                          'exam prep','cysa+','pentest+'],
    'Red Team'         : ['red team','red-team','offensive','exploit','exploitation','penetration test',
                          'pentest','pen test','attack chain','malware','payload',' c2 ',
                          'command and control','metasploit','cobalt strike','beacon','lateral movement',
                          'privilege escalation','privesc','reverse shell','bind shell','initial access'],
    'Blue Team'        : ['blue team','blue-team','defensive','defender',' siem',' edr',' xdr',
                          'detection engineering','threat hunt','log analysis','sigma rule','yara'],
    'DFIR'             : [' dfir','forensic','forensics','incident response','memory analysis',
                          'disk image','volatility','autopsy','timeline analysis',' ir ','triage',
                          'chain of custody'],
    'SOC'              : [' soc ','soc analyst','security operations center','tier 1','tier 2',
                          'tier-1','tier-2','alert triage','playbook','runbook'],
    'ISO27001'         : ['iso 27001','iso27001','iso-27001',' isms','annex a',
                          'statement of applicability'],
    'AI LLM Security'  : [' ai ','artificial intelligence',' llm','large language model',' gpt',
                          'prompt injection','jailbreak',' mcp ','model context protocol',' rag ',
                          'prompt engineering','ai security','ai safety'],
    'Phantom Scan'     : ['phantom scan','phantom-scan','phantomscan'],
    'ISC2 Org'         : ['isc2','isc-2','(isc)','cissp','ccsp',' sscp',' cgrc'],
    'Projects'         : ['my project','side project','build log','project plan','project notes'],
}

CYBER_DOMAINS = {
    'Security Audit'                              : ['audit','auditing','audit trail','compliance audit',
                                                     'evidence collection','audit log','internal audit',
                                                     'external audit'],
    'Security and Risk Management'                : ['risk','governance',' grc','policy','compliance',
                                                     'gdpr','hipaa',' sox ','regulatory',
                                                     'business continuity',' bcp ',' drp',
                                                     'disaster recovery','risk assessment',
                                                     'risk management','threat model','risk register'],
    'Asset Security'                              : ['asset','asset management','data classification',
                                                     'classification','retention','data owner',
                                                     'data custodian','labeling','data lifecycle'],
    'Security Architecture and Engineering'       : ['architecture','secure design','secure architecture',
                                                     'cryptography','encryption','hashing',' pki ',
                                                     ' hsm',' tpm','zero trust','defense in depth',
                                                     'reference architecture'],
    'Communication and Network Security'          : ['network','firewall','vpn',' ids',' ips',' tls',
                                                     ' ssl','segmentation','vlan','packet','wireshark',
                                                     ' dns','dnssec','tcp/ip',' osi'],
    'Identity and Access Management (IAM)'        : [' iam ','identity','authentication','authorization',
                                                     ' sso',' mfa','2fa',' rbac',' abac','kerberos',
                                                     'ldap','oauth','saml','password policy',
                                                     'privileged access',' pam '],
    'Security Assessment and Testing'             : ['assessment','vulnerability scan',
                                                     'vulnerability assessment','pentest',
                                                     'penetration test','pen test','red team',
                                                     'code review','security testing','exploit'],
    'Security Operations'                         : [' soc ','security operations',' siem','incident',
                                                     'alert','log analysis',' edr',' xdr','detection',
                                                     'response',' dfir','forensic','incident response'],
    'Software Development Security'               : ['sdlc','devsecops','secure coding','owasp',' sast',
                                                     ' dast',' iast','code review','ci/cd',
                                                     'supply chain','dependency',' sbom'],
    'Cloud Security'                              : ['cloud',' aws',' azure',' gcp','kubernetes',
                                                     'container security','cspm','cwpp',' saas',
                                                     ' paas',' iaas','cloud iam'],
    'Endpoint Security'                           : ['endpoint',' edr','antivirus',' av ',
                                                     'host-based','workstation','laptop',
                                                     'mobile device',' mdm','hardening',
                                                     'endpoint protection'],
    'Threat Intelligence'                         : ['threat intel','threat intelligence',' ioc ',
                                                     'indicator of compromise',' ttp','mitre',
                                                     'att&ck','attack framework',' apt',
                                                     'threat hunting',' cti '],
    'Physical Security'                           : ['physical security','badge','surveillance',
                                                     'cctv','perimeter','door lock','biometric',
                                                     'facility','tailgating','mantrap'],
    'Data Loss Prevention (DLP)'                  : [' dlp ','data loss prevention',
                                                     'data exfiltration','exfiltration',
                                                     'data leakage','data leak','sensitive data',
                                                     'data masking'],
}


# =============================================================================
# regex / IO helpers
# =============================================================================

FRONTMATTER_RE = re.compile(r'^---\s*\n(.*?)\n---\s*\n', re.DOTALL)
AUTO_BEGIN     = '<!-- BMT_AUTO_BEGIN -->'
AUTO_END       = '<!-- BMT_AUTO_END -->'
AUTO_BLOCK_RE  = re.compile(re.escape(AUTO_BEGIN) + r'.*?' + re.escape(AUTO_END), re.DOTALL)
INVALID_FS_CHARS = re.compile(r'[<>:"|?*]')


def read_note(path: Path):
    text = path.read_text(encoding='utf-8', errors='replace')
    if text.startswith('\ufeff'):
        text = text[1:]
    m = FRONTMATTER_RE.match(text)
    if m:
        return m.group(1), text[m.end():]
    return '', text


def write_note(path: Path, frontmatter: str, body: str):
    if frontmatter.strip():
        out = f'---\n{frontmatter.strip()}\n---\n\n{body.lstrip()}'
    else:
        out = body
    path.write_text(out, encoding='utf-8')


def slugify(text: str) -> str:
    text = re.sub(r'[^\w\s-]', '', text, flags=re.UNICODE)
    text = re.sub(r'[\s_-]+', '-', text).strip('-')
    return text.lower() or 'untitled'


def safe_folder_name(name: str) -> str:
    return INVALID_FS_CHARS.sub('', name).strip().rstrip('.')


# =============================================================================
# classification
# =============================================================================

def score_keywords(text_lower: str, keywords) -> int:
    return sum(text_lower.count(kw.lower()) for kw in keywords)


def assign_primary(text_lower: str):
    scores = {topic: score_keywords(text_lower, kws)
              for topic, kws in PRIMARY_TOPICS.items()}
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return 'Uncategorized', scores
    return best, scores


def assign_domains(text_lower: str):
    return [d for d, kws in CYBER_DOMAINS.items()
            if score_keywords(text_lower, kws) > 0]


# =============================================================================
# frontmatter helpers
# =============================================================================

def upsert_list_in_frontmatter(fm: str, key: str, values) -> str:
    """Set or merge `key: [a, b, ...]` in YAML-ish frontmatter."""
    values = [v for v in values if v]
    if not values:
        return fm
    if not fm.strip():
        return f'{key}: [{", ".join(values)}]'

    lines = fm.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(f'{key}:'):
            m_inline = re.match(rf'(\s*{key}:\s*)\[(.*?)\]\s*$', line)
            if m_inline:
                existing = [t.strip() for t in m_inline.group(2).split(',') if t.strip()]
                merged = existing + [v for v in values if v not in existing]
                lines[i] = f'{m_inline.group(1)}[{", ".join(merged)}]'
                return '\n'.join(lines)
            j = i + 1
            block, end = [], i
            while j < len(lines) and re.match(r'\s*-\s+', lines[j]):
                block.append(lines[j].strip().lstrip('-').strip())
                end = j
                j += 1
            merged = block + [v for v in values if v not in block]
            new_block = [f'{key}:'] + [f'  - {v}' for v in merged]
            lines[i:end + 1 if block else i + 1] = new_block
            return '\n'.join(lines)

    lines.append(f'{key}: [{", ".join(values)}]')
    return '\n'.join(lines)


# =============================================================================
# main
# =============================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('vault', help=r'Path to the vault, e.g. D:\bayyari\bmt')
    ap.add_argument('--apply', action='store_true',
                    help='Actually write changes. Without this flag, dry-run only.')
    ap.add_argument('--top-k-related', type=int, default=5)
    ap.add_argument('--threshold', type=float, default=0.10)
    ap.add_argument('--cyber-folder', default='cyber domains',
                    help='Folder name (under the vault) for domain copies.')
    args = ap.parse_args()

    vault = Path(args.vault)
    if not vault.is_dir():
        print(f'ERROR: {vault} is not a directory.')
        sys.exit(1)

    cyber_root = vault / args.cyber_folder

    # collect notes; ignore the cyber-domains folder so we don't classify copies
    md_files = sorted(p for p in vault.rglob('*.md')
                      if cyber_root not in p.parents
                      and p.name != 'MOC.md'
                      and not p.name.startswith('_'))
    if not md_files:
        print('No .md files found.')
        sys.exit(0)

    notes = []
    for p in md_files:
        fm, body = read_note(p)
        body_clean = AUTO_BLOCK_RE.sub('', body).rstrip() + '\n'
        haystack = f' {p.stem} {body_clean} '.lower()
        primary, _ = assign_primary(haystack)
        domains    = assign_domains(haystack)
        notes.append({
            'path': p, 'frontmatter': fm, 'body': body_clean,
            'primary': primary, 'domains': domains,
        })

    by_primary = defaultdict(list)
    by_domain  = defaultdict(list)
    for n in notes:
        by_primary[n['primary']].append(n)
        for d in n['domains']:
            by_domain[d].append(n)

    # TF-IDF for the per-note "Related" section
    corpus = [f'{n["path"].stem} {n["path"].stem} {n["body"]}' for n in notes]
    vec = TfidfVectorizer(max_features=4000, ngram_range=(1, 2), min_df=1,
                          token_pattern=r"(?u)\b\w[\w'-]+\b")
    X = vec.fit_transform(corpus)
    sim = cosine_similarity(X)
    related_idx = []
    for i in range(sim.shape[0]):
        sim[i, i] = -1
        idx = sim[i].argsort()[::-1][:args.top_k_related]
        idx = [j for j in idx if sim[i, j] >= args.threshold]
        related_idx.append(idx)

    # ----- print plan ---------------------------------------------------------
    print(f'\nFound {len(notes)} notes in {vault}\n')
    print('=' * 72)
    print('PRIMARY TOPIC PLAN')
    print('=' * 72)
    for topic in list(PRIMARY_TOPICS) + ['Uncategorized']:
        ns = by_primary.get(topic, [])
        if not ns:
            continue
        print(f'\n[{topic}]  ({len(ns)} notes)')
        for n in sorted(ns, key=lambda x: x['path'].stem.lower()):
            print(f'   - {n["path"].relative_to(vault)}')

    print('\n' + '=' * 72)
    print('CYBER DOMAIN ASSIGNMENTS  (a note can appear in multiple)')
    print('=' * 72)
    for domain in CYBER_DOMAINS:
        ns = by_domain.get(domain, [])
        if not ns:
            continue
        print(f'\n[{domain}]  ({len(ns)} notes)')
        for n in sorted(ns, key=lambda x: x['path'].stem.lower()):
            extras = [d for d in n['domains'] if d != domain]
            tail = f'  (also: {", ".join(extras)})' if extras else ''
            print(f'   - {n["path"].name}{tail}')

    no_domain = [n for n in notes if not n['domains']]
    if no_domain:
        print(f'\n[no cyber-domain match]  ({len(no_domain)} notes)')
        for n in sorted(no_domain, key=lambda x: x['path'].stem.lower()):
            print(f'   - {n["path"].name}')

    if not args.apply:
        print('\nDry-run only. Re-run with --apply to write changes.')
        return

    # ----- backup -------------------------------------------------------------
    backup = vault.parent / f'{vault.name}_backup_{datetime.now():%Y%m%d_%H%M%S}'
    shutil.copytree(vault, backup)
    print(f'\nBackup created: {backup}')

    # ----- rewrite each note --------------------------------------------------
    for i, note in enumerate(notes):
        primary = note['primary']
        domains = note['domains']
        topic_tag   = slugify(primary)
        domain_tags = [slugify(d) for d in domains]

        block = [AUTO_BEGIN, '', '## Related', '']
        if related_idx[i]:
            for j in related_idx[i]:
                block.append(f'- [[{notes[j]["path"].stem}]]')
        else:
            block.append('_No strongly related notes found._')
        block += ['', f'**Topic:** [[MOC#{primary}|{primary}]]']
        if domains:
            dom_links = ', '.join(f'[[Cyber Domains MOC#{d}|{d}]]' for d in domains)
            block.append(f'**Cyber Domains:** {dom_links}')
        block += ['', AUTO_END]

        body = note['body'].rstrip()
        body = AUTO_BLOCK_RE.sub('', body).rstrip()
        new_body = body + '\n\n---\n\n' + '\n'.join(block) + '\n'

        new_fm = upsert_list_in_frontmatter(note['frontmatter'], 'tags', [topic_tag])
        new_fm = upsert_list_in_frontmatter(new_fm, 'domains', domain_tags)
        write_note(note['path'], new_fm, new_body)

    # ----- main MOC -----------------------------------------------------------
    moc = vault / 'MOC.md'
    lines = ['# Map of Content', '',
             f'_Auto-generated on {datetime.now():%Y-%m-%d %H:%M}._', '',
             f'{len(notes)} notes total. See also '
             f'[[{args.cyber_folder}/Cyber Domains MOC|Cyber Domains MOC]].',
             '']
    for topic in list(PRIMARY_TOPICS) + ['Uncategorized']:
        ns = by_primary.get(topic, [])
        if not ns:
            continue
        lines += [f'## {topic}', '']
        for n in sorted(ns, key=lambda x: x['path'].stem.lower()):
            lines.append(f'- [[{n["path"].stem}]]')
        lines.append('')
    moc.write_text('\n'.join(lines), encoding='utf-8')
    print(f'Wrote: {moc}')

    # ----- cyber-domains folder with COPIES -----------------------------------
    if cyber_root.exists():
        for sub in cyber_root.iterdir():
            if sub.is_dir():
                shutil.rmtree(sub)
            elif sub.name == 'Cyber Domains MOC.md':
                sub.unlink()
    cyber_root.mkdir(exist_ok=True)

    cyber_lines = ['# Cyber Domains MOC', '',
                   f'_Auto-generated on {datetime.now():%Y-%m-%d %H:%M}._', '',
                   'Files appear in every domain they match. '
                   'See also [[../MOC|Main MOC]].',
                   '']
    for domain in CYBER_DOMAINS:
        ns = by_domain.get(domain, [])
        if not ns:
            continue
        folder = cyber_root / safe_folder_name(domain)
        folder.mkdir(exist_ok=True)
        for n in ns:
            shutil.copy2(n['path'], folder / n['path'].name)
        cyber_lines += [f'## {domain}', '',
                        f'_Folder: `{args.cyber_folder}/{safe_folder_name(domain)}/`_',
                        '']
        for n in sorted(ns, key=lambda x: x['path'].stem.lower()):
            cyber_lines.append(f'- [[{n["path"].stem}]]')
        cyber_lines.append('')
    (cyber_root / 'Cyber Domains MOC.md').write_text('\n'.join(cyber_lines),
                                                     encoding='utf-8')
    print(f'Wrote: {cyber_root / "Cyber Domains MOC.md"}')

    print('\nDone. Open the vault in Obsidian.')
    print('Note: copies in "cyber domains/" share filenames with the originals;')
    print('Obsidian will warn about ambiguous wikilinks. Links resolve to the')
    print('closest match by folder, so the originals remain the canonical copy.')


if __name__ == '__main__':
    main()
