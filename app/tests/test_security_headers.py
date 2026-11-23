"""Content Security Policy split: strict for the app, CyberChef's looser one on its own routes."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

failures = []
cases = 0


def case(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)


def directives(header):
    return {part.split()[0]: part.split()[1:] for part in header.split(';') if part.strip()}


def main():
    os.environ.setdefault('SECRET_KEY', 'test-only')
    from app import create_app
    client = create_app().test_client()

    for path in ('/', '/ip_search', '/cyberchef', '/privacy'):
        response = client.get(path)
        policy = directives(response.headers.get('Content-Security-Policy', ''))
        script = policy.get('script-src', [])
        case("'unsafe-eval'" not in script, f'{path}: app policy allows unsafe-eval')
        case('blob:' not in script, f'{path}: app policy allows blob: scripts')
        case(policy.get('connect-src') == ["'self'"], f'{path}: connect-src is {policy.get("connect-src")}')
        case(policy.get('object-src') == ["'none'"], f'{path}: object-src is not none')
        case(policy.get('base-uri') == ["'self'"], f'{path}: base-uri is not self')
        case('Access-Control-Allow-Origin' not in response.headers, f'{path}: sends a CORS header')

    # Talisman sets its header after blueprint after_request hooks, so a policy that is
    # not applied through Talisman never reaches the browser and CyberChef's workers fail.
    for path in ('/cyberchef_app/', '/cyberchef_app/assets/main.js'):
        response = client.get(path)
        policy = directives(response.headers.get('Content-Security-Policy', ''))
        case(response.status_code == 200, f'{path}: status {response.status_code}')
        case("'unsafe-eval'" in policy.get('script-src', []), f'{path}: CyberChef lost unsafe-eval')
        case('blob:' in policy.get('worker-src', []), f'{path}: CyberChef lost blob: workers')
        case(policy.get('frame-ancestors') == ["'self'"], f'{path}: CyberChef is frameable cross-site')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} security header cases')


if __name__ == '__main__':
    main()
