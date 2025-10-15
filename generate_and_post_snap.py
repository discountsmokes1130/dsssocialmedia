#!/usr/bin/env python3
import os, io, time, base64, datetime, requests
from pathlib import Path

# ---- Endpoints ----
SNAP_API = "https://businessapi.snapchat.com/v1"
GITHUB_API = "https://api.github.com"

# ---- Helpers ----
def ist_today():
    utc = datetime.datetime.utcnow()
    ist = utc + datetime.timedelta(hours=5, minutes=30)
    return ist.strftime("%Y-%m-%d")

def gen_image(prompt: str, size: str, openai_key: str) -> bytes:
    r = requests.post(
        "https://api.openai.com/v1/images/generations",
        headers={"Authorization": f"Bearer {openai_key}"},
        json={"model": "gpt-image-1", "prompt": prompt, "size": size, "n": 1},
        timeout=180,
    )
    r.raise_for_status()
    return base64.b64decode(r.json()["data"][0]["b64_json"])

def add_footer(img_bytes: bytes, text: str) -> bytes:
    from PIL import Image, ImageDraw, ImageFont
    import io as _io
    img = Image.open(_io.BytesIO(img_bytes)).convert("RGB")
    w, h = img.size
    bar_h = max(60, h // 18)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, h - bar_h, w, h], fill=(0, 0, 0))
    try:
        font = ImageFont.truetype("arial.ttf", size=max(24, bar_h // 2))
    except:
        font = ImageFont.load_default()
    try:
        tw = draw.textlength(text, font=font); th = font.size
    except:
        tw, th = draw.textsize(text, font=font)
    draw.text(((w - tw) // 2, h - bar_h + (bar_h - th) // 2), text, fill=(255, 255, 255), font=font)
    out = _io.BytesIO(); img.save(out, format="JPEG", quality=92); return out.getvalue()

def gh_headers(token): return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

def gh_put_file(token, repo, branch, path, content_bytes, message, prev_sha=None):
    owner, name = repo.split("/", 1)
    url = f"{GITHUB_API}/repos/{owner}/{name}/contents/{path.lstrip('/')}"
    payload = {"message": message, "content": base64.b64encode(content_bytes).decode(), "branch": branch}
    if prev_sha: payload["sha"] = prev_sha
    r = requests.put(url, headers=gh_headers(token), json=payload, timeout=60)
    r.raise_for_status(); return r.json()

def gh_get_sha(token, repo, branch, path):
    owner, name = repo.split("/", 1)
    url = f"{GITHUB_API}/repos/{owner}/{name}/contents/{path.lstrip('/')}"
    r = requests.get(url, headers=gh_headers(token), params={"ref": branch}, timeout=30)
    if r.status_code == 200: return r.json().get("sha")
    return None

# ---- Snapchat encryption (AES-256-CBC) ----
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

def aes256_cbc_encrypt(raw_bytes: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(raw_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def snap_post_story(image_bytes: bytes, profile_id: str, bearer_token: str):
    headers_json = {"Authorization": bearer_token}

    key = secrets.token_bytes(32)
    iv  = secrets.token_bytes(16)
    # Encrypt per Snapchat Public Profile API
    enc = aes256_cbc_encrypt(image_bytes, key, iv)
    key64 = base64.b64encode(key).decode()
    iv64  = base64.b64encode(iv).decode()

    # 1) Create media container
    cr = requests.post(
        f"{SNAP_API}/public_profiles/{profile_id}/media",
        headers=headers_json,
        json={"type": "IMAGE", "name": f"auto-{int(time.time())}.jpg", "key": key64, "iv": iv64},
        timeout=60
    )
    cr.raise_for_status()
    cjson = cr.json()
    if cjson.get("request_status") != "SUCCESS":
        raise RuntimeError(f"Snap create media failed: {cjson}")
    media_id = cjson["media_id"]; add_path = cjson["add_path"]; finalize_path = cjson["finalize_path"]

    # 2) Upload encrypted bytes (single part)
    add_url = f"https://businessapi.snapchat.com{add_path}"
    files = {
        "action": (None, "ADD"),
        "file": ("media.enc", io.BytesIO(enc), "application/octet-stream"),
        "part_number": (None, "1")
    }
    ar = requests.post(add_url, headers={"Authorization": bearer_token}, files=files, timeout=180)
    ar.raise_for_status()

    # 3) Finalize
    fin_url = f"https://businessapi.snapchat.com{finalize_path}"
    fin = requests.post(fin_url, headers={"Authorization": bearer_token},
                        files={"action": (None, "FINALIZE")}, timeout=60)
    fin.raise_for_status()

    # 4) Post story
    sr = requests.post(
        f"{SNAP_API}/public_profiles/{profile_id}/stories",
        headers=headers_json,
        json={"media_id": media_id},
        timeout=60
    )
    sr.raise_for_status()
    sjson = sr.json()
    if sjson.get("request_status") != "SUCCESS":
        raise RuntimeError(f"Snap story post failed: {sjson}")
    return sjson.get("request_id")

def main():
    # Required env
    OPENAI = os.environ["OPENAI_API_KEY"]
    SNAP_ACCESS_TOKEN = os.environ["SNAP_ACCESS_TOKEN"]   # include 'Bearer ' prefix
    SNAP_PROFILE_ID   = os.environ["SNAP_PROFILE_ID"]

    GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
    REPO = os.environ["GITHUB_REPO"]
    BRANCH = os.getenv("GITHUB_BRANCH", "main")
    IMAGES_DIR = os.getenv("IMAGES_FOLDER", "images/")
    SIZE = os.getenv("IMAGE_SIZE", "1024x1024")
    FOOTER = os.getenv("CAPTION_FOOTER", "Discount Smokes")

    today = ist_today()
    prompt = "Bold, minimal promotional graphic for a smoke shop; clean white background; premium vibe."
    print("Generating image…")
    img = gen_image(prompt, SIZE, OPENAI)
    img = add_footer(img, f"{FOOTER} • {today}")

    # Commit under images/
    filename = f"{today}-snap.jpg"
    rel_path = f"{IMAGES_DIR.rstrip('/')}/{filename}"
    prev_sha = gh_get_sha(GITHUB_TOKEN, REPO, BRANCH, rel_path)
    print(f"Committing {rel_path} …")
    gh_put_file(GITHUB_TOKEN, REPO, BRANCH, rel_path, img, f"auto: add {rel_path}", prev_sha)

    # Post to Snapchat Story
    print("Posting Snapchat Story…")
    request_id = snap_post_story(img, SNAP_PROFILE_ID, SNAP_ACCESS_TOKEN)
    print("Snap request_id:", request_id)

if __name__ == "__main__":
    main()
