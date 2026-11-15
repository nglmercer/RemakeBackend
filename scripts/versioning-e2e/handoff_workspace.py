# End-to-end helper for the versioning slice. Run it against a backend started with the environment
# documented in docs/VERSIONING-BUILD.md. It registers or signs in an account, completes the native
# handoff with PKCE, creates a workspace (or reissues a credential with "reuse"), and writes the
# repository id and native credential to the file given as the third argument. Standard library only.
import base64, hashlib, json, os, secrets, sys, urllib.parse, urllib.request, urllib.error
BASE = "http://127.0.0.1:43000"
ORIGIN = BASE
EMAIL = sys.argv[1]; PASSWORD = "e2e password with enough chars"; NAME = sys.argv[2]
OUT = sys.argv[3]

def req(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"content-type": "application/json", "origin": ORIGIN}
    h.update(headers or {})
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read()
            return resp.status, dict(resp.headers), (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: parsed = json.loads(raw)
        except Exception: parsed = raw.decode(errors="replace")
        return e.code, dict(e.headers), parsed

# 1. account: sign up (idempotent: fall back to sign-in)
status, headers, body = req("POST", "/api/auth/sign-up/email", {"email": EMAIL, "password": PASSWORD, "name": NAME})
if status != 200:
    status, headers, body = req("POST", "/api/auth/sign-in/email", {"email": EMAIL, "password": PASSWORD})
assert status == 200, (status, body)
cookie = [v for k, v in headers.items() if k.lower() == "set-cookie"][0].split(";")[0]
print("cookie ok")

# 2. browser-side handoff with PKCE (S256)
verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_urlsafe(24)
redirect = "http://127.0.0.1:53999/callback"
status, _, issued = req("POST", "/api/v1/desktop/handoff",
                        {"redirectUri": redirect, "codeChallenge": challenge, "state": state},
                        {"cookie": cookie})
assert status == 200, (status, issued)
query = urllib.parse.parse_qs(urllib.parse.urlparse(issued["callbackUrl"]).query)
code = query["code"][0]
assert query["state"][0] == state
print("handoff code issued")

# 3. redeem the code for a native bearer session
status, _, redeemed = req("POST", "/api/v1/native/handoff/redeem",
                          {"code": code, "redirectUri": redirect, "codeVerifier": verifier})
assert status == 200, (status, redeemed)
bearer = redeemed["sessionToken"]
auth = {"authorization": f"Bearer {bearer}"}
print("native session redeemed")

# 4. workspace (unless reusing an existing one) and credential
if len(sys.argv) > 4 and sys.argv[4] == "reuse":
    ws = json.load(open(OUT))
    status, _, cred = req("POST", "/api/versioning/v1/native-credentials", None, auth)
    assert status == 200, (status, cred)
    json.dump({"repositoryId": ws["repositoryId"], "token": cred["token"], "bearer": bearer}, open(OUT, "w"))
    print("reissued", cred["repositories"])
    sys.exit(0)
status, _, ws = req("POST", "/api/versioning/v1/workspaces", {"name": NAME + " stream"}, auth)
assert status == 201, (status, ws)
status, _, cred = req("POST", "/api/versioning/v1/native-credentials", None, auth)
assert status == 200, (status, cred)
print("workspace", ws["repositoryId"], "credential repositories", cred["repositories"])
json.dump({"repositoryId": ws["repositoryId"], "token": cred["token"], "bearer": bearer},
          open(OUT, "w"))
