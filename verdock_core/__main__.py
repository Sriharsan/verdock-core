"""Command line.

python -m verdock_core verify <file> --public-key <hex>
    Prints one line per receipt and a summary. Exit status 0 when every line
    passes, 1 when any line fails, 2 for usage or file errors. No network.

python -m verdock_core egress --policy <file> --listen <host:port> --receipts <file> --seed <file>
    Runs the egress gateway for the policy's egress.allow_hosts and prints its
    receipt public key. Creates the seed file if it does not exist.
"""

import argparse
import sys

from . import __version__
from .receipts import verify_log


def _verify(args):
    try:
        report = verify_log(args.file, args.public_key)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.file, exc.strerror or exc), file=sys.stderr)
        return 2
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    by_line = {}
    for failure in report["failures"]:
        by_line.setdefault(failure["line"], []).append(failure["reason"])
    for number in range(1, report["count"] + 1):
        reasons = by_line.get(number)
        if reasons:
            print("line %d: FAIL %s" % (number, "; ".join(reasons)))
        else:
            print("line %d: ok" % number)
    if report["ok"]:
        print("verified: %d lines, chain intact, signed by the trusted key" % report["count"])
        return 0
    print("failed: %d problems in %d lines" % (len(report["failures"]), report["count"]))
    return 1


def _egress(args):
    import os
    from .egress import EgressGateway, allowed_hosts
    from .policy import load_policy
    from .receipts import ReceiptLog, create_seed, load_seed
    hosts = allowed_hosts(load_policy(args.policy))
    if not os.path.exists(args.seed):
        create_seed(args.seed)
    log = ReceiptLog(args.receipts, load_seed(args.seed))
    host, _, port = args.listen.rpartition(":")
    server = EgressGateway((host, int(port)), hosts, log)
    print("egress gateway on %s, allowing %s, receipts signed by %s" % (args.listen, ", ".join(hosts) or "nothing", log.public_key), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m verdock_core")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify a receipt log")
    verify.add_argument("file", help="NDJSON receipt log")
    verify.add_argument("--public-key", required=True, help="trusted Ed25519 public key, 64 hex characters")
    egress = commands.add_parser("egress", help="run the egress gateway")
    egress.add_argument("--policy", required=True)
    egress.add_argument("--listen", default="0.0.0.0:8080")
    egress.add_argument("--receipts", required=True)
    egress.add_argument("--seed", required=True)
    args = parser.parse_args(argv)
    if args.command == "verify":
        return _verify(args)
    if args.command == "egress":
        return _egress(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
