#!/usr/bin/env python3
"""NexusTrace: operator tool for sign-in accounts.

Accounts have no admin page, so blocking an abusive one means this tool.

Usage:
    python3 scripts/manage_accounts.py list
    python3 scripts/manage_accounts.py disable <id>
    python3 scripts/manage_accounts.py enable <id>
    python3 scripts/manage_accounts.py delete <id> [--yes]

Pick the account by the ID that `list` prints. A display name is not unique (a Google
name especially), so it cannot say who is who; the provider and its own subject can.

A disabled account is signed out on its next request and cannot sign in again, and its
saved keys stay in place. `delete` removes the account and every key it saved, and a
person who signs in again gets a new, empty account. It asks you to type `yes` unless
--yes is passed.

The database is data/accounts.db, or NEXUSTRACE_ACCOUNTS_DB when that is set; pass
--db to point at another file. Nothing here needs the encryption key and nothing prints
a saved key. An operator tool: deliberately not wired into the app, a cron or Docker.

Exit status: 0 success, 2 no such account (and, from argparse, a usage error),
3 declined at the prompt.
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from app.utils import accounts  # noqa: E402


def _list(args):
    users = accounts.list_users(args.db)
    if not users:
        print('No accounts.')
        return 0
    print(f"{'ID':>4}  {'PROVIDER':<8}  {'SUBJECT':<24}  {'LOGIN':<24}  "
          f"{'LAST SIGN-IN':<20}  {'STATE':<8}  KEYS")
    for user in users:
        print(f"{user['id']:>4}  {user['provider']:<8}  {user['subject'][:24]:<24}  "
              f"{user['login'][:24]:<24}  {user['last_login_at']:<20}  "
              f"{'disabled' if user['disabled'] else 'active':<8}  "
              f"{', '.join(user['services']) or '-'}")
    return 0


def _set_disabled(args, disabled):
    if not accounts.set_disabled(args.id, disabled, args.db):
        print(f'No account {args.id}.', file=sys.stderr)
        return 2
    print(f"Account {args.id} {'disabled' if disabled else 'enabled'}.")
    return 0


def _delete(args):
    match = next((u for u in accounts.list_users(args.db) if u['id'] == args.id), None)
    if match is None:
        print(f'No account {args.id}.', file=sys.stderr)
        return 2
    if not args.yes:
        print(f"Delete account {match['id']} ({match['provider']} {match['login']}) and "
              f"its saved keys?")
        if input('Type yes to continue: ').strip().lower() != 'yes':
            print('Not deleted.')
            return 3
    accounts.delete_user(args.id, args.db)
    print(f'Account {args.id} deleted.')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='Manage NexusTrace sign-in accounts.')
    parser.add_argument('--db', help='accounts database (default: data/accounts.db)')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list', help='show every account')
    for name in ('disable', 'enable', 'delete'):
        sub = commands.add_parser(name)
        sub.add_argument('id', type=int)
        if name == 'delete':
            sub.add_argument('--yes', action='store_true', help='skip the confirmation')
    args = parser.parse_args(argv)
    if args.command == 'list':
        return _list(args)
    if args.command == 'delete':
        return _delete(args)
    return _set_disabled(args, args.command == 'disable')


if __name__ == '__main__':
    sys.exit(main())
