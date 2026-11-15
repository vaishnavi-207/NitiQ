"""SAFE sandbox activity emulator - for demos and tests only.

It NEVER touches anything outside a folder that (a) contains the marker file `.nitiq_sandbox`
and (b) only edits files that start with the header `NITIQ-DUMMY` (dummy files that NitiQ itself
created).  "Encryption" = overwriting the dummy file with random bytes (no key, no ransom note,
no network).  Run as its own process so the Guardian can see it and suspend it.

Styles:  inplace | rename | copy_delete   (ransomware-like)
         benign_copy | benign_edit        (harmless activity, to prove no false alarm)
"""
import argparse
import os
import sys
import time

HEADER = b"NITIQ-DUMMY"
MARKER = ".nitiq_sandbox"


def _check_sandbox(root):
    root = os.path.realpath(root)
    marker = os.path.join(root, MARKER)
    if not os.path.isfile(marker):
        sys.exit(f"Refusing to run: {root} has no {MARKER} marker (not a NitiQ sandbox).")
    return root


def _inside(root, p):
    rp = os.path.realpath(p)
    return rp == root or rp.startswith(root + os.sep)


def _targets(root):
    out = []
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for fn in sorted(fns):
            if fn == MARKER:
                continue
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not _inside(root, p):
                continue
            out.append(p)
    return out


def _is_dummy(p):
    try:
        with open(p, "rb") as f:
            return f.read(len(HEADER)) == HEADER
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--rate", type=float, default=15.0, help="files per second")
    ap.add_argument("--style", default="rename")
    ap.add_argument("--max-files", type=int, default=100000)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to wait before starting")
    a = ap.parse_args()
    root = _check_sandbox(a.dir)
    time.sleep(a.delay)
    done, t0 = 0, time.time()
    print(f"[emulator] style={a.style} rate={a.rate}/s root={root} pid={os.getpid()}", flush=True)

    if a.style == "benign_copy":
        dst = os.path.join(root, f"copied_{int(time.time())}")
        os.makedirs(dst, exist_ok=True)
        while done < a.max_files:
            with open(os.path.join(dst, f"photo_{done:05d}.jpg"), "wb") as f:
                f.write(os.urandom(20000))
            done += 1
            time.sleep(max(0.0, t0 + done / a.rate - time.time()))
        return

    for p in _targets(root):
        if done >= a.max_files:
            break
        if not _is_dummy(p):
            continue
        try:
            if a.style == "benign_edit":
                with open(p, "ab") as f:
                    f.write(b"\nedited by user\n")
            else:
                size = os.path.getsize(p)
                with open(p, "rb") as f:
                    f.read()
                if a.style == "copy_delete":
                    with open(p + ".locked", "wb") as f:
                        f.write(os.urandom(size))
                    os.remove(p)
                else:
                    with open(p, "r+b") as f:
                        f.write(os.urandom(size))
                    if a.style == "rename":
                        os.rename(p, p + ".locked")
        except OSError:
            continue
        done += 1
        time.sleep(max(0.0, t0 + done / a.rate - time.time()))
    print(f"[emulator] finished {done} files", flush=True)


if __name__ == "__main__":
    main()
