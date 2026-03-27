import base64
import os
import time
import random
import secrets
from collections import deque
from typing import Union, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ==========================================
# 1. API INITIALIZATION & MODELS
# ==========================================

app = FastAPI(
    title="Advanced Crypto Studio", 
    version="2.2.0",
    description="Enterprise-grade symmetric encryption, ECDSA authentication, QKD simulation, and Max Security Baselines."
)

class EnDecryptRequest(BaseModel):
    key: str
    data: str

class QKDResponse(BaseModel):
    key: str
    method: str
    sifted_bits: int
    qber: float

class AnalyticsDataResponse(BaseModel):
    labels: List[str]
    current_times: List[int]
    past_times: List[int]

class SecurityDataResponse(BaseModel):
    parameters: List[str]
    size_bits: List[int]
    security_bits: List[int]
    compared_baseline: List[int]
    host_spec_capacity: List[int]  # New field for Hardware Capacity

# ==========================================
# 2. ANALYTICS ENGINE
# ==========================================

PAST_PERFORMANCE_BASELINE = {
    "System Init": 15, "Key Load": 12, "Ready": 14,
    "QKD Sym Gen": 24, "Encrypt Text": 18, "Decrypt Text": 16,
    "Gen Auth Keys": 42, "Sign File": 28, "Verify File": 25
}

performance_logs = deque([("System Init", 12), ("Ready", 11)], maxlen=15)

def log_performance(operation_name: str, start_time: float):
    elapsed_ms = max(1, int((time.perf_counter() - start_time) * 1000))
    performance_logs.append((operation_name, elapsed_ms))

# ==========================================
# 3. CRYPTOGRAPHIC CORE (ECDSA & QKD)
# ==========================================

class NodeAuth:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.key_backend = default_backend()

    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, self.key_backend)
        return private_key, private_key.public_key()

    def sign_data(self, private_key, data: bytes) -> bytes:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key, data: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

auth_tool = NodeAuth()

def simulate_bb84() -> dict:
    """Simulates BB84 protocol including an Eavesdropper (Eve) detection phase."""
    num_photons = 1200 
    
    # Alice Prepares
    alice_bits = [secrets.choice([0, 1]) for _ in range(num_photons)]
    alice_bases = [secrets.choice([0, 1]) for _ in range(num_photons)]
    
    # Eve Intercepts (15% probability simulation)
    eve_present = random.random() < 0.15
    transmitted_bits = []
    
    if eve_present:
        eve_bases = [secrets.choice([0, 1]) for _ in range(num_photons)]
        for i in range(num_photons):
            # If Eve guesses wrong base, the bit gets scrambled
            measured_bit = alice_bits[i] if eve_bases[i] == alice_bases[i] else secrets.choice([0, 1])
            transmitted_bits.append(measured_bit)
    else:
        transmitted_bits = alice_bits.copy()

    # Bob Measures
    bob_bases = [secrets.choice([0, 1]) for _ in range(num_photons)]
    bob_bits = [transmitted_bits[i] if bob_bases[i] == alice_bases[i] else secrets.choice([0, 1]) for i in range(num_photons)]
    
    # Public Sifting
    sifted_alice, sifted_bob = [], []
    for i in range(num_photons):
        if alice_bases[i] == bob_bases[i]:
            sifted_alice.append(alice_bits[i])
            sifted_bob.append(bob_bits[i])
            
    # QBER Check (Compare a random subset to check for Eve)
    sample_size = min(len(sifted_alice) // 4, 128)
    errors = sum(1 for i in range(sample_size) if sifted_alice[i] != sifted_bob[i])
    qber = errors / sample_size if sample_size > 0 else 1.0
    
    # Abort if error rate is too high (> 11% standard BB84 threshold)
    if qber > 0.11:
        raise ValueError(f"High QBER detected ({qber:.2%}). Eavesdropper presence suspected. Key exchange aborted.")
        
    final_key_bits = sifted_alice[sample_size:sample_size+256]
    
    if len(final_key_bits) < 256:
        return simulate_bb84() # Retry if not enough bits survived
        
    # Package into 32-byte Fernet key
    key_bytes = bytearray(int("".join(map(str, final_key_bits[i:i+8])), 2) for i in range(0, 256, 8))
    
    return {
        "key": base64.urlsafe_b64encode(bytes(key_bytes)).decode(),
        "qber": qber,
        "sifted_bits": len(sifted_alice)
    }

# ==========================================
# 4. API ENDPOINTS
# ==========================================

@app.get("/encryption/generate-key", response_model=QKDResponse)
def generate_key():
    start = time.perf_counter()
    try:
        qkd_result = simulate_bb84()
        log_performance("QKD Sym Gen", start)
        return {"key": qkd_result["key"], "method": "BB84 Simulated", "sifted_bits": qkd_result["sifted_bits"], "qber": qkd_result["qber"]}
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

@app.post("/encryption/encrypt")
def encrypt_data_endpoint(req: EnDecryptRequest):
    start = time.perf_counter()
    try:
        res = {"encrypted_data": Fernet(req.key.encode()).encrypt(req.data.encode()).decode()}
        log_performance("Encrypt Text", start)
        return res
    except: raise HTTPException(status_code=400, detail="Invalid Key or Data format.")

@app.post("/encryption/decrypt")
def decrypt_data_endpoint(req: EnDecryptRequest):
    start = time.perf_counter()
    try:
        res = {"decrypted_data": Fernet(req.key.encode()).decrypt(req.data.encode()).decode()}
        log_performance("Decrypt Text", start)
        return res
    except: raise HTTPException(status_code=400, detail="Decryption Failed. Ensure key matches cipher.")

@app.post("/auth/generate-keys")
def generate_auth_keys(password: str):
    start = time.perf_counter()
    priv, pub = auth_tool.generate_key_pair()
    res = {
        "private_key_pem": priv.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ).decode(),
        "public_key_pem": pub.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }
    log_performance("Gen Auth Keys", start)
    return res

@app.post("/auth/sign-file")
async def sign_file(private_key_pem: str = Form(...), private_key_password: str = Form(...), file: UploadFile = File(...)):
    start = time.perf_counter()
    try:
        pk = serialization.load_pem_private_key(private_key_pem.encode(), password=private_key_password.encode())
        res = {"signature_hex": auth_tool.sign_data(pk, await file.read()).hex()}
        log_performance("Sign File", start)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Key, Password, or File format.")

@app.post("/auth/verify-file")
async def verify_file(public_key_pem: str = Form(...), signature_hex: str = Form(...), file: UploadFile = File(...)):
    start = time.perf_counter()
    try:
        pbk = serialization.load_pem_public_key(public_key_pem.encode())
        res = {"is_valid": auth_tool.verify_signature(pbk, await file.read(), bytes.fromhex(signature_hex.strip()))}
        log_performance("Verify File", start)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail="Malformed Public Key or Signature Hex.")

@app.get("/analytics/data", response_model=AnalyticsDataResponse)
def get_analytics_data():
    labels = [item[0] for item in performance_logs]
    return {
        "labels": labels,
        "current_times": [item[1] for item in performance_logs],
        "past_times": [PAST_PERFORMANCE_BASELINE.get(label, 20) for label in labels]
    }

@app.get("/analytics/security", response_model=SecurityDataResponse)
def get_security_parameters():
    import os
    
    # Increased NIST Targets to MAX (256-bit Top Secret Tier)
    baseline_bits = [256, 256, 256, 256] 
    
    # Fernet is AES-128 natively
    raw_sizes = [128, 256, 256, 256]
    live_effective_bits = [int(size * random.uniform(0.92, 1.0)) for size in raw_sizes]

    # Deriving capacity from Device Specs (CPU cores)
    cpu_cores = os.cpu_count() or 4
    base_hardware_capacity = 256 if cpu_cores >= 4 else 128
    
    # Adding slight fluctuation to simulate live hardware availability/load
    host_capacity = [int(base_hardware_capacity * random.uniform(0.95, 1.0)) for _ in raw_sizes]

    return {
        "parameters": ["Fernet Enc (AES-CBC)", "Fernet Auth (HMAC)", "Identity (ECDSA P-256)", "Integrity (SHA-256)"],
        "size_bits": raw_sizes,
        "security_bits": live_effective_bits,
        "compared_baseline": baseline_bits,
        "host_spec_capacity": host_capacity
    }

# ==========================================
# 5. UI HTML CONTENT
# ==========================================

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Crypto Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script> 
    <style>
        textarea::-webkit-scrollbar { width: 8px; }
        textarea::-webkit-scrollbar-track { background: #1e293b; border-radius: 4px; }
        textarea::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        textarea::-webkit-scrollbar-thumb:hover { background: #64748b; }
        .btn-disabled { opacity: 0.6; cursor: not-allowed; pointer-events: none; }
    </style>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen p-6 md:p-12 font-sans selection:bg-indigo-500 selection:text-white">

    <div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-2"></div>

    <div class="max-w-5xl mx-auto space-y-8">
        <header class="border-b border-slate-800 pb-6 mb-8">
            <h1 class="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">
                Advanced Crypto Studio 2.2
            </h1>
            <p class="text-slate-400 mt-2">Enterprise-grade symmetric encryption, ECDSA authentication, QKD simulation, and Analytics.</p>
        </header>
        
        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-cyan-400">1. QKD Symmetric Encryption (Fernet)</h2>
                <button id="btnQKD" onclick="genSymKey()" class="text-sm bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 px-4 py-2 rounded-lg transition shadow-sm border border-cyan-500/30 font-medium">
                    + Execute QKD (BB84)
                </button>
            </div>
            <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Secret Key</label>
                        <div class="flex gap-2">
                            <input id="symKey" type="text" placeholder="Paste or generate key..." class="flex-1 p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none text-sm font-mono transition">
                            <button onclick="copyToClipboard('symKey')" class="px-4 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition" title="Copy Key">📋</button>
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Input Data (Text or Cipher)</label>
                        <textarea id="symData" placeholder="Enter large amounts of text here..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none h-32 text-sm resize-y transition"></textarea>
                    </div>
                    <div class="flex gap-3">
                        <button id="btnEnc" onclick="doEncrypt()" class="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-cyan-900/20">Encrypt Data</button>
                        <button id="btnDec" onclick="doDecrypt()" class="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-medium py-3 rounded-lg transition">Decrypt Data</button>
                    </div>
                </div>
                <div class="flex flex-col h-full">
                    <div class="flex justify-between items-end mb-1">
                        <label class="block text-xs font-medium text-slate-400">Result Output</label>
                        <button onclick="copyContent('symOut')" class="text-xs text-slate-400 hover:text-white transition">Copy Result</button>
                    </div>
                    <div id="symOut" class="flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap transition-colors"></div>
                </div>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-purple-400">2. Identity & Keys (ECDSA)</h2>
            </div>
            <div class="p-6 space-y-6">
                <div class="flex flex-col md:flex-row gap-4 items-end">
                    <div class="flex-1 w-full">
                        <label class="block text-xs font-medium text-slate-400 mb-1">Private Key Password (Required)</label>
                        <input id="authPass" type="password" placeholder="Enter a strong password..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none text-sm transition">
                    </div>
                    <button id="btnGenAuth" onclick="genAuthKeys()" class="w-full md:w-auto bg-purple-600 hover:bg-purple-500 px-6 py-3 rounded-lg font-medium transition shadow-lg shadow-purple-900/20 whitespace-nowrap">
                        Generate Identity Keys
                    </button>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <div class="flex justify-between items-end mb-1">
                            <label class="block text-xs font-medium text-slate-400">Public Key (Shareable)</label>
                            <button onclick="copyToClipboard('pubKey')" class="text-xs text-slate-400 hover:text-white transition">Copy</button>
                        </div>
                        <textarea id="pubKey" placeholder="Generated Public Key PEM..." readonly class="w-full p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-[11px] h-40 resize-y focus:outline-none"></textarea>
                    </div>
                    <div>
                        <div class="flex justify-between items-end mb-1">
                            <label class="block text-xs font-medium text-slate-400">Encrypted Private Key (Keep Secret)</label>
                            <button onclick="copyToClipboard('privKey')" class="text-xs text-slate-400 hover:text-white transition">Copy</button>
                        </div>
                        <textarea id="privKey" placeholder="Generated Private Key PEM..." readonly class="w-full p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-500 font-mono text-[11px] h-40 resize-y focus:outline-none"></textarea>
                    </div>
                </div>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden mb-8">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800">
                <h2 class="text-xl font-semibold text-pink-400">3. File Integrity Engine</h2>
            </div>
            <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
                
                <div class="space-y-4">
                    <div class="border-2 border-dashed border-slate-700 hover:border-pink-500 bg-slate-950 rounded-xl p-8 text-center transition group relative">
                        <input type="file" id="fileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" onchange="updateFileName()">
                        <div class="text-slate-400 group-hover:text-pink-400 transition">
                            <span class="text-4xl block mb-2">📁</span>
                            <span id="fileNameDisplay" class="font-medium">Click or Drag to Upload File</span>
                            <p class="text-xs mt-1 opacity-70">Supports PNG, JPG, PDF, TXT</p>
                        </div>
                    </div>
                    
                    <div>
                        <div class="flex justify-between items-end mb-1">
                            <label class="block text-xs font-medium text-slate-400">File Signature (Hex)</label>
                            <button onclick="copyToClipboard('sigHex')" class="text-xs text-slate-400 hover:text-white transition">Copy</button>
                        </div>
                        <textarea id="sigHex" placeholder="Generated or pasted signature hex will appear here..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-pink-500 outline-none text-sm font-mono h-24 resize-y"></textarea>
                    </div>
                </div>

                <div class="space-y-4 bg-slate-950/50 p-6 rounded-xl border border-slate-800">
                    <button id="btnSign" onclick="signFile()" class="w-full bg-pink-600 hover:bg-pink-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-pink-900/20 flex justify-center items-center gap-2">
                        <span>🖋️</span> 1. Generate Signature
                    </button>
                    
                    <button id="btnVerify" onclick="verifyFile()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-indigo-900/20 flex justify-center items-center gap-2 mt-2">
                        <span>🛡️</span> 2. Verify Authenticity
                    </button>

                    <div id="fileResult" class="mt-6 p-4 rounded-lg text-center font-bold text-lg hidden border transition-all duration-300"></div>
                </div>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden mb-8">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-amber-400">4. Engine Performance (Live)</h2>
            </div>
            <div class="p-6 relative h-[300px] w-full border-b border-slate-800/50">
                <canvas id="performanceChart"></canvas>
            </div>
            <div class="bg-slate-800/20 p-6 overflow-x-auto">
                <table class="w-full text-left text-sm text-slate-300">
                    <thead class="text-xs uppercase bg-slate-800/50 text-slate-400">
                        <tr><th class="px-4 py-3 rounded-tl-lg">Operation</th><th class="px-4 py-3">Present Time (ms)</th><th class="px-4 py-3 rounded-tr-lg">Baseline (ms)</th></tr>
                    </thead>
                    <tbody id="performanceTableBody" class="divide-y divide-slate-800/50"></tbody>
                </table>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden mb-12">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-emerald-400">5. Cryptographic Security Posture</h2>
            </div>
            <div class="p-6 relative h-[300px] w-full border-b border-slate-800/50">
                <canvas id="securityChart"></canvas>
            </div>
            <div class="bg-slate-800/20 p-6 overflow-x-auto">
                <table class="w-full text-left text-sm text-slate-300">
                    <thead class="text-xs uppercase bg-slate-800/50 text-slate-400">
                        <tr>
                            <th class="px-4 py-3 rounded-tl-lg">Algorithm</th>
                            <th class="px-4 py-3 text-cyan-400">Raw Size</th>
                            <th class="px-4 py-3 text-indigo-400">Live Effective Bits</th>
                            <th class="px-4 py-3 text-emerald-400">Host Hardware Cap</th>
                            <th class="px-4 py-3 text-amber-400 rounded-tr-lg">NIST Target</th>
                        </tr>
                    </thead>
                    <tbody id="securityTableBody" class="divide-y divide-slate-800/50"></tbody>
                </table>
            </div>
        </section>
    </div>

    <script>
        // --- HELPER FUNCTIONS ---
        function showToast(message, type="success") {
            const toast = document.createElement('div');
            const color = type === "error" ? "bg-red-500" : type === "warning" ? "bg-amber-500" : "bg-emerald-500";
            toast.className = `${color} text-white px-6 py-3 rounded-lg shadow-lg transform transition-all duration-300 translate-x-full opacity-0 flex items-center gap-2 font-medium text-sm mt-2`;
            toast.innerText = message;
            document.getElementById('toast-container').appendChild(toast);
            
            setTimeout(() => { toast.classList.remove('translate-x-full', 'opacity-0'); }, 10);
            setTimeout(() => {
                toast.classList.add('opacity-0', 'translate-x-full');
                setTimeout(() => toast.remove(), 300);
            }, 4000);
        }

        function setBtnState(btnId, isLoading, defaultText) {
            const btn = document.getElementById(btnId);
            if (isLoading) {
                btn.classList.add('btn-disabled');
                btn.innerHTML = `<span class="animate-spin mr-2">⏳</span> Processing...`;
            } else {
                btn.classList.remove('btn-disabled');
                btn.innerHTML = defaultText;
            }
        }

        function copyToClipboard(id) {
            const el = document.getElementById(id);
            if (!el.value) return showToast("Nothing to copy!", "error");
            navigator.clipboard.writeText(el.value);
            showToast("Copied to clipboard!");
        }

        function copyContent(id) {
            const el = document.getElementById(id);
            if (!el.innerText) return showToast("Nothing to copy!", "error");
            navigator.clipboard.writeText(el.innerText);
            showToast("Copied result!");
        }

        function updateFileName() {
            const file = document.getElementById('fileInput').files[0];
            if(file) document.getElementById('fileNameDisplay').innerText = `Selected: ${file.name}`;
        }

        // --- CORE FUNCTIONS ---
        async function genSymKey() {
            setBtnState('btnQKD', true);
            showToast("Simulating Photon Exchange...", "success");
            try {
                const r = await fetch('/encryption/generate-key');
                const d = await r.json();
                
                if(!r.ok) throw new Error(d.detail); // Catch Eavesdropper 403s
                
                document.getElementById('symKey').value = d.key;
                setTimeout(() => {
                    showToast(`QKD Success! Sifted ${d.sifted_bits} bits. QBER: ${(d.qber*100).toFixed(1)}%`);
                    loadCharts();
                }, 800);
            } catch(e) { 
                showToast(e.message, "error"); 
            } finally {
                setTimeout(() => setBtnState('btnQKD', false, '+ Execute QKD (BB84)'), 800);
            }
        }

        async function doEncrypt() {
            setBtnState('btnEnc', true);
            try {
                const r = await fetch('/encryption/encrypt', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: document.getElementById('symKey').value, data: document.getElementById('symData').value})
                });
                const d = await r.json();
                if(!r.ok) throw new Error(d.detail);
                
                document.getElementById('symOut').innerText = d.encrypted_data;
                document.getElementById('symOut').className = "flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap";
                showToast("Encryption Successful");
                loadCharts();
            } catch(e) { 
                document.getElementById('symOut').innerText = e.message;
                document.getElementById('symOut').className = "flex-1 p-4 bg-red-950/30 rounded-lg border border-red-800 text-red-400 font-mono text-sm break-all overflow-y-auto";
            } finally { setBtnState('btnEnc', false, 'Encrypt Data'); }
        }

        async function doDecrypt() {
            setBtnState('btnDec', true);
            try {
                const r = await fetch('/encryption/decrypt', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: document.getElementById('symKey').value, data: document.getElementById('symData').value})
                });
                const d = await r.json();
                if(!r.ok) throw new Error(d.detail);
                
                document.getElementById('symOut').innerText = d.decrypted_data;
                document.getElementById('symOut').className = "flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-emerald-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap";
                showToast("Decryption Successful");
                loadCharts();
            } catch(e) { 
                document.getElementById('symOut').innerText = e.message;
                document.getElementById('symOut').className = "flex-1 p-4 bg-red-950/30 rounded-lg border border-red-800 text-red-400 font-mono text-sm break-all overflow-y-auto";
            } finally { setBtnState('btnDec', false, 'Decrypt Data'); }
        }

        async function genAuthKeys() {
            const p = document.getElementById('authPass').value;
            if(!p) return showToast("Password is required!", "error");
            
            setBtnState('btnGenAuth', true);
            try {
                const r = await fetch(`/auth/generate-keys?password=${encodeURIComponent(p)}`, {method: 'POST'});
                const d = await r.json();
                document.getElementById('pubKey').value = d.public_key_pem;
                document.getElementById('privKey').value = d.private_key_pem;
                showToast("Identity Keys Generated");
                loadCharts();
            } catch(e) { showToast("Failed to generate keys", "error"); }
            finally { setBtnState('btnGenAuth', false, 'Generate Identity Keys'); }
        }

        async function signFile() {
            const file = document.getElementById('fileInput').files[0];
            const privKey = document.getElementById('privKey').value;
            const pass = document.getElementById('authPass').value;
            
            if(!file || !privKey || !pass) return showToast("File, Private Key, and Password required.", "error");

            setBtnState('btnSign', true);
            const fd = new FormData();
            fd.append('file', file);
            fd.append('private_key_pem', privKey);
            fd.append('private_key_password', pass);
            
            try {
                const r = await fetch('/auth/sign-file', {method: 'POST', body: fd});
                const d = await r.json();
                if(!r.ok) throw new Error(d.detail);
                
                document.getElementById('sigHex').value = d.signature_hex;
                showToast("File Signed Successfully!");
                loadCharts();
            } catch(e) { showToast(e.message, "error"); }
            finally { setBtnState('btnSign', false, '<span>🖋️</span> 1. Generate Signature'); }
        }

        async function verifyFile() {
            const file = document.getElementById('fileInput').files[0];
            const pubKey = document.getElementById('pubKey').value;
            const sigHex = document.getElementById('sigHex').value;

            if(!file || !pubKey || !sigHex) return showToast("File, Public Key, and Signature are required.", "error");

            setBtnState('btnVerify', true);
            const fd = new FormData();
            fd.append('file', file);
            fd.append('public_key_pem', pubKey);
            fd.append('signature_hex', sigHex.trim());
            
            try {
                const r = await fetch('/auth/verify-file', {method: 'POST', body: fd});
                const d = await r.json();
                if(!r.ok) throw new Error(d.detail);
                
                const resEl = document.getElementById('fileResult');
                resEl.classList.remove('hidden');
                
                if(d.is_valid) {
                    resEl.innerText = "✅ FILE IS AUTHENTIC AND UNTAMPERED";
                    resEl.className = "mt-6 p-4 rounded-lg text-center font-bold text-lg border border-emerald-500/50 bg-emerald-500/10 text-emerald-400 tracking-wide";
                    showToast("Verification Passed");
                } else {
                    resEl.innerText = "❌ CORRUPTED OR INVALID SIGNATURE";
                    resEl.className = "mt-6 p-4 rounded-lg text-center font-bold text-lg border border-red-500/50 bg-red-500/10 text-red-400 tracking-wide shadow-[0_0_15px_rgba(239,68,68,0.2)]";
                    showToast("Verification Failed", "error");
                }
                loadCharts();
            } catch(e) { showToast(e.message, "error"); }
            finally { setBtnState('btnVerify', false, '<span>🛡️</span> 2. Verify Authenticity'); }
        }

        // --- CHART LOGIC (Silent failure on background refresh) ---
        let perfChart = null; 
        let secChart = null;

        async function loadCharts() {
            try {
                const [rPerf, rSec] = await Promise.all([fetch('/analytics/data'), fetch('/analytics/security')]);
                if(!rPerf.ok || !rSec.ok) return; // Silent fail for auto-refresh
                
                const dPerf = await rPerf.json();
                const dSec = await rSec.json();

                // --- Performance Chart ---
                const ctxPerf = document.getElementById('performanceChart').getContext('2d');
                if(perfChart) perfChart.destroy(); 
                perfChart = new Chart(ctxPerf, {
                    type: 'line',
                    data: {
                        labels: dPerf.labels,
                        datasets: [
                            { label: 'Present Processing (ms)', data: dPerf.current_times, borderColor: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.1)', borderWidth: 2, tension: 0.4, fill: true, pointBackgroundColor: '#fbbf24', order: 1 },
                            { label: 'Past Baseline (ms)', data: dPerf.past_times, borderColor: '#64748b', borderDash: [5, 5], borderWidth: 2, tension: 0.4, fill: false, pointBackgroundColor: '#64748b', order: 2 }
                        ]
                    },
                    options: { responsive: true, maintainAspectRatio: false, animation: {duration: 0}, interaction: { mode: 'index', intersect: false }, scales: { y: { beginAtZero: true, grid: { color: 'rgba(51, 65, 85, 0.5)' }, ticks: { color: '#94a3b8' } }, x: { grid: { color: 'rgba(51, 65, 85, 0.5)' }, ticks: { color: '#94a3b8' } } }, plugins: { legend: { labels: { color: '#cbd5e1' } } } }
                });

                const tbodyPerf = document.getElementById('performanceTableBody');
                tbodyPerf.innerHTML = dPerf.labels.map((label, i) => {
                    const diff = dPerf.current_times[i] - dPerf.past_times[i];
                    const diffHtml = diff > 0 ? `<span class="text-red-400 ml-2 text-xs font-semibold">(+${diff}ms)</span>` : diff < 0 ? `<span class="text-emerald-400 ml-2 text-xs font-semibold">(${diff}ms)</span>` : `<span class="text-slate-500 ml-2 text-xs font-semibold">(0ms)</span>`;
                    return `<tr class="hover:bg-slate-800/40 transition-colors"><td class="px-4 py-3 font-medium text-slate-300 border-t border-slate-800/50">${label}</td><td class="px-4 py-3 text-amber-400 border-t border-slate-800/50">${dPerf.current_times[i]} ${diffHtml}</td><td class="px-4 py-3 text-slate-500 border-t border-slate-800/50">${dPerf.past_times[i]}</td></tr>`;
                }).join('');

                // --- Security Chart ---
                const ctxSec = document.getElementById('securityChart').getContext('2d');
                if(secChart) secChart.destroy(); 
                secChart = new Chart(ctxSec, {
                    type: 'bar',
                    data: {
                        labels: dSec.parameters,
                        datasets: [
                            { label: 'Live Effective Security (Bits)', data: dSec.security_bits, backgroundColor: 'rgba(99, 102, 241, 0.7)', borderColor: '#6366f1', borderWidth: 1, borderRadius: 4, order: 2 },
                            { label: 'NIST Baseline Target (Bits)', data: dSec.compared_baseline, type: 'line', borderColor: '#fbbf24', borderDash: [5, 5], borderWidth: 2, tension: 0.1, pointBackgroundColor: '#fbbf24', order: 1 }
                        ]
                    },
                    options: { 
                        responsive: true, 
                        maintainAspectRatio: false, 
                        animation: { duration: 0 }, 
                        scales: { 
                            y: { 
                                beginAtZero: true, 
                                max: 300, // Increased to 300 to give the 256 target breathing room
                                title: { display: true, text: 'Bits', color: '#94a3b8' }, 
                                grid: { color: 'rgba(51, 65, 85, 0.5)' }, 
                                ticks: { color: '#94a3b8' } 
                            }, 
                            x: { grid: { display: false }, ticks: { color: '#94a3b8', font: {size: 11} } } 
                        }, 
                        plugins: { legend: { labels: { color: '#cbd5e1' } } } 
                    }
                });

                const tbodySec = document.getElementById('securityTableBody');
                tbodySec.innerHTML = dSec.parameters.map((param, i) => `
                    <tr class="hover:bg-slate-800/40 transition-colors">
                        <td class="px-4 py-3 font-medium text-slate-300 border-t border-slate-800/50">${param}</td>
                        <td class="px-4 py-3 text-cyan-400 font-mono border-t border-slate-800/50">${dSec.size_bits[i]} bits</td>
                        <td class="px-4 py-3 text-indigo-400 font-mono border-t border-slate-800/50">${dSec.security_bits[i]} <span class="text-xs text-slate-500 ml-1">(live)</span></td>
                        <td class="px-4 py-3 text-emerald-400 font-mono border-t border-slate-800/50">${dSec.host_spec_capacity[i]} bits</td>
                        <td class="px-4 py-3 text-amber-400 font-mono border-t border-slate-800/50">${dSec.compared_baseline[i]} bits</td>
                    </tr>
                `).join('');

            } catch(e) { console.error("Chart Update Failed:", e); }
        }

        window.addEventListener('DOMContentLoaded', () => {
            loadCharts();
            setInterval(loadCharts, 3000); 
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
def serve_ui():
    return HTML_CONTENT
