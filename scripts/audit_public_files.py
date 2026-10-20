"""Public artifact allowlist and secret-pattern checks. Copyright 2026 mofu.
This is a release check, not a guarantee that no sensitive text exists.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = {'index.html', 'help.html', 'about.html', 'app.js', 'style.css',
          'icon.svg', 'incidents.json', 'service-names.json', 'update-status.json', '_headers', '.nojekyll'}
PATTERNS = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            r'\bgh[pousr]_[A-Za-z0-9]{20,}', r'\bgithub_pat_[A-Za-z0-9_]{20,}',
            r'\bAKIA[A-Z0-9]{16}\b', r'\bsk-[A-Za-z0-9_-]{24,}',
            r'(?i)https?://[^\s/]+:[^\s/]+@',
            r'(?i)[A-Z]:[\\/](?:Users|CodexData)[\\/]',
            r'(?i)(?:127\.0\.0\.1|localhost):\d+']

def main():
    count = 0
    for path in (ROOT / 'dist').rglob('*'):
        if path.is_dir():
            continue
        assert not path.is_symlink(), 'Public symlink is forbidden'
        assert path.relative_to(ROOT / 'dist').as_posix() in PUBLIC, 'Unapproved public file'
        text = path.read_text(encoding='utf-8-sig')
        for pattern in PATTERNS:
            assert not re.search(pattern, text), 'Potential sensitive content: ' + path.name
        if path.suffix == '.html':
            assert 'http-equiv="Content-Security-Policy"' in text
            assert 'name="referrer" content="no-referrer"' in text
        count += 1
    print(f'Public allowlist and sensitive-pattern audit passed: {count} files. Manual review still required.')

if __name__ == '__main__':
    main()
