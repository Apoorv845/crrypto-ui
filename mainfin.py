import base64
import os
import io
import time
from collections import deque
from typing import Union
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Initialize the App
app = FastAPI(title="6-Layer Crypto API", version="1.5.0")

# ==========================================
# ANALYTICS ENGINE (Present vs Past)
# ==========================================

# Mock database of past averages to compare against live data
PAST_PERFORMANCE_BASELINE = {
    "System Init": 15,
    "Key Load": 12,
    "Ready": 14,
    "Gen Sym Key": 8,
    "Encrypt Text": 18,
    "Decrypt Text": 16,
    "Gen Auth Keys": 42,
    "Sign File": 28,
    "Verify File": 25
}

# Store the last 15 live operations
performance_logs = deque([
    ("System Init", 12),
    ("Key Load", 10),
    ("Ready", 11)
], maxlen=15)

def log_performance(operation_name: str, start_time: float):
    """Calculates elapsed time in ms and adds it to the analytics queue."""
    elapsed_ms = max(1, int((time.perf_counter() - start_time) * 1000))
    performance_logs.append((operation_name, elapsed_ms))

# ==========================================
# CORE LOGIC
# ==========================================

class NodeAuth:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.key_backend = default_backend()

    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, self.key_backend)
        return private_key, private_key.public_key()

    def sign_data(self, private_key, data: Union[str, bytes]) -> bytes:
        content = data.encode() if isinstance(data, str) else data
        return private_key.sign(content, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key, data: Union[str, bytes], signature: bytes) -> bool:
        content = data.encode() if isinstance(data, str) else data
        try:
            public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

auth_tool = NodeAuth()

# ==========================================
# UI HTML CONTENT (With 2 Graphs & Tables)
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
    </style>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen p-6 md:p-12 font-sans selection:bg-indigo-500 selection:text-white">

    <div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-2"></div>

    <div class="max-w-5xl mx-auto space-y-8">
        <header class="border-b border-slate-800 pb-6 mb-8">
            <h1 class="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">
                Advanced Crypto Studio
            </h1>
            <p class="text-slate-400 mt-2">Enterprise-grade symmetric encryption, ECDSA file authentication, and Comparative Analytics.</p>
        </header>
        
        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-cyan-400">1. Symmetric Encryption (Fernet)</h2>
                <button onclick="genSymKey()" class="text-sm bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 px-4 py-2 rounded-lg transition">
                    + Generate New Key
                </button>
            </div>
            <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Secret Key</label>
                        <div class="flex gap-2">
                            <input id="symKey" type="text" placeholder="Paste or generate key..." class="flex-1 p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none text-sm font-mono">
                            <button onclick="copyToClipboard('symKey')" class="px-4 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition" title="Copy Key">📋</button>
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Input Data (Text or Cipher)</label>
                        <textarea id="symData" placeholder="Enter large amounts of text here..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none h-32 text-sm resize-y"></textarea>
                    </div>
                    <div class="flex gap-3">
                        <button onclick="doEncrypt()" class="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-cyan-900/20">Encrypt Data</button>
                        <button onclick="doDecrypt()" class="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-medium py-3 rounded-lg transition">Decrypt Data</button>
                    </div>
                </div>
                <div class="flex flex-col h-full">
                    <div class="flex justify-between items-end mb-1">
                        <label class="block text-xs font-medium text-slate-400">Result Output</label>
                        <button onclick="copyContent('symOut')" class="text-xs text-slate-400 hover:text-white transition">Copy Result</button>
                    </div>
                    <div id="symOut" class="flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap"></div>
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
                        <input id="authPass" type="password" placeholder="Enter a strong password..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none text-sm">
                    </div>
                    <button onclick="genAuthKeys()" class="w-full md:w-auto bg-purple-600 hover:bg-purple-500 px-6 py-3 rounded-lg font-medium transition shadow-lg shadow-purple-900/20 whitespace-nowrap">
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
                    <p class="text-sm text-slate-400 mb-4">Ensure your keys and password are filled out in Section 2 before proceeding.</p>
                    
                    <button onclick="signFile()" class="w-full bg-pink-600 hover:bg-pink-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-pink-900/20 flex justify-center items-center gap-2">
                        <span>🖋️</span> 1. Generate Signature
                    </button>
                    
                    <button onclick="verifyFile()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-indigo-900/20 flex justify-center items-center gap-2 mt-2">
                        <span>🛡️</span> 2. Verify Authenticity
                    </button>

                    <div id="fileResult" class="mt-6 p-4 rounded-lg text-center font-bold text-lg hidden border"></div>
                </div>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden mb-8">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-amber-400">4. Engine Performance (Past vs Present)</h2>
                <button onclick="loadCharts()" class="text-sm bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 px-4 py-2 rounded-lg transition shadow-sm border border-amber-500/30">
                    Refresh Graph & Data
                </button>
            </div>
            
            <div class="p-6 relative h-[300px] w-full border-b border-slate-800/50">
                <canvas id="performanceChart"></canvas>
            </div>
            
            <div class="bg-slate-800/20 p-6 overflow-x-auto">
                <h3 class="text-sm font-medium text-slate-400 mb-4 uppercase tracking-wider">Raw Performance Metrics</h3>
                <table class="w-full text-left text-sm text-slate-300">
                    <thead class="text-xs uppercase bg-slate-800/50 text-slate-400">
                        <tr>
                            <th class="px-4 py-3 rounded-tl-lg">Operation</th>
                            <th class="px-4 py-3">Present Time (ms)</th>
                            <th class="px-4 py-3 rounded-tr-lg">Past Baseline (ms)</th>
                        </tr>
                    </thead>
                    <tbody id="performanceTableBody" class="divide-y divide-slate-800/50">
                        </tbody>
                </table>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden mb-12">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-emerald-400">5. Cryptographic Security Posture</h2>
                <span class="text-xs bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full border border-emerald-500/20">System Specs</span>
            </div>
            
            <div class="p-6 relative h-[300px] w-full border-b border-slate-800/50">
                <canvas id="securityChart"></canvas>
            </div>
            
            <div class="bg-slate-800/20 p-6 overflow-x-auto">
                <h3 class="text-sm font-medium text-slate-400 mb-4 uppercase tracking-wider">Security Parameter Values (Bits)</h3>
                <table class="w-full text-left text-sm text-slate-300">
                    <thead class="text-xs uppercase bg-slate-800/50 text-slate-400">
                        <tr>
                            <th class="px-4 py-3 rounded-tl-lg">Algorithm / Component</th>
                            <th class="px-4 py-3 text-cyan-400">Parameter / Key Size</th>
                            <th class="px-4 py-3 text-indigo-400 rounded-tr-lg">Effective Security Level</th>
                        </tr>
                    </thead>
                    <tbody id="securityTableBody" class="divide-y divide-slate-800/50">
                        </tbody>
                </table>
            </div>
        </section>
    </div>

    <script>
        function showToast(message, type="success") {
            const toast = document.createElement('div');
            const color = type === "error" ? "bg-red-500" : "bg-emerald-500";
            toast.className = `${color} text-white px-6 py-3 rounded-lg shadow-lg transform transition-all duration-300 translate-x-full opacity-0 flex items-center gap-2 font-medium text-sm`;
            toast.innerText = message;
            
            const container = document.getElementById('toast-container');
            container.appendChild(toast);
            
            setTimeout(() => { toast.classList.remove('translate-x-full', 'opacity-0'); }, 10);
            
            setTimeout(() => {
                toast.classList.add('opacity-0');
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        function copyToClipboard(elementId) {
            const el = document.getElementById(elementId);
            if (!el.value) return showToast("Nothing to copy!", "error");
            navigator.clipboard.writeText(el.value);
            showToast("Copied to clipboard!");
        }

        function copyContent(elementId) {
            const el = document.getElementById(elementId);
            if (!el.innerText) return showToast("Nothing to copy!", "error");
            navigator.clipboard.writeText(el.innerText);
            showToast("Copied result!");
        }

        function updateFileName() {
            const file = document.getElementById('fileInput').files[0];
            const display = document.getElementById('fileNameDisplay');
            if(file) display.innerText = `Selected: ${file.name}`;
        }

        async function genSymKey() {
            try {
                const r = await fetch('/encryption/generate-key');
                const d = await r.json();
                document.getElementById('symKey').value = d.key;
                showToast("New Symmetric Key Generated");
                loadCharts();
            } catch(e) { showToast("Error generating key", "error"); }
        }

        async function doEncrypt() {
            try {
                const r = await fetch('/encryption/encrypt', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: document.getElementById('symKey').value, data: document.getElementById('symData').value})
                });
                const d = await r.json();
                if(r.ok) {
                    document.getElementById('symOut').innerText = d.encrypted_data;
                    document.getElementById('symOut').className = "flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap";
                    showToast("Encryption Successful");
                    loadCharts();
                } else { throw new Error(d.detail); }
            } catch(e) { 
                document.getElementById('symOut').innerText = e.message;
                document.getElementById('symOut').className = "flex-1 p-4 bg-red-950/30 rounded-lg border border-red-800 text-red-400 font-mono text-sm break-all overflow-y-auto";
            }
        }

        async function doDecrypt() {
            try {
                const r = await fetch('/encryption/decrypt', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: document.getElementById('symKey').value, data: document.getElementById('symData').value})
                });
                const d = await r.json();
                if(r.ok) {
                    document.getElementById('symOut').innerText = d.decrypted_data;
                    document.getElementById('symOut').className = "flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-emerald-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap";
                    showToast("Decryption Successful");
                    loadCharts();
                } else { throw new Error(d.detail); }
            } catch(e) { 
                document.getElementById('symOut').innerText = "Failed: Check your key and cipher formatting.";
                document.getElementById('symOut').className = "flex-1 p-4 bg-red-950/30 rounded-lg border border-red-800 text-red-400 font-mono text-sm break-all overflow-y-auto";
            }
        }

        async function genAuthKeys() {
            const p = document.getElementById('authPass').value;
            if(!p) return showToast("Password is required to secure private key!", "error");
            
            try {
                const r = await fetch(`/auth/generate-keys?password=${encodeURIComponent(p)}`, {method: 'POST'});
                const d = await r.json();
                document.getElementById('pubKey').value = d.public_key_pem;
                document.getElementById('privKey').value = d.private_key_pem;
                showToast("Identity Keys Generated");
                loadCharts();
            } catch(e) { showToast("Failed to generate keys", "error"); }
        }

        async function signFile() {
            const file = document.getElementById('fileInput').files[0];
            const privKey = document.getElementById('privKey').value;
            const pass = document.getElementById('authPass').value;
            
            if(!file) return showToast("Please select a file first.", "error");
            if(!privKey || !pass) return showToast("Private key and password required.", "error");

            const fd = new FormData();
            fd.append('file', file);
            fd.append('private_key_pem', privKey);
            fd.append('private_key_password', pass);
            
            try {
                showToast("Processing Signature...");
                const r = await fetch('/auth/sign-file', {method: 'POST', body: fd});
                const d = await r.json();
                if(r.ok) {
                    document.getElementById('sigHex').value = d.signature_hex;
                    showToast("File Signed Successfully!");
                    loadCharts();
                } else { throw new Error(d.detail); }
            } catch(e) { showToast("Signing failed: " + e.message, "error"); }
        }

        async function verifyFile() {
            const file = document.getElementById('fileInput').files[0];
            const pubKey = document.getElementById('pubKey').value;
            const sigHex = document.getElementById('sigHex').value;

            if(!file || !pubKey || !sigHex) return showToast("File, Public Key, and Signature are all required.", "error");

            const fd = new FormData();
            fd.append('file', file);
            fd.append('public_key_pem', pubKey);
            fd.append('signature_hex', sigHex.trim());
            
            try {
                const r = await fetch('/auth/verify-png', {method: 'POST', body: fd});
                const d = await r.json();
                
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
            } catch(e) { showToast("Verification Request Failed", "error"); }
        }

        let perfChart = null; 
        let secChart = null;

        async function loadCharts() {
            // --- LOAD PERFORMANCE DATA (Section 4) ---
            try {
                const rPerf = await fetch('/analytics/data');
                const dPerf = await rPerf.json();

                const ctxPerf = document.getElementById('performanceChart').getContext('2d');
                if(perfChart) perfChart.destroy(); 
                
                perfChart = new Chart(ctxPerf, {
                    type: 'line',
                    data: {
                        labels: dPerf.labels,
                        datasets: [
                            {
                                label: 'Present Processing (ms)',
                                data: dPerf.current_times,
                                borderColor: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.1)',
                                borderWidth: 2, tension: 0.4, fill: true, pointBackgroundColor: '#fbbf24', order: 1
                            },
                            {
                                label: 'Past Baseline (ms)',
                                data: dPerf.past_times,
                                borderColor: '#64748b', backgroundColor: 'transparent',
                                borderDash: [5, 5], borderWidth: 2, tension: 0.4, fill: false, pointBackgroundColor: '#64748b', order: 2
                            }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        interaction: { mode: 'index', intersect: false },
                        scales: { y: { beginAtZero: true, grid: { color: 'rgba(51, 65, 85, 0.5)' }, ticks: { color: '#94a3b8' } },
                                  x: { grid: { color: 'rgba(51, 65, 85, 0.5)' }, ticks: { color: '#94a3b8' } } },
                        plugins: { legend: { labels: { color: '#cbd5e1' } } }
                    }
                });

                const tbodyPerf = document.getElementById('performanceTableBody');
                tbodyPerf.innerHTML = ''; 
                for (let i = 0; i < dPerf.labels.length; i++) {
                    const tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-800/40 transition-colors';
                    const diff = dPerf.current_times[i] - dPerf.past_times[i];
                    let diffHtml = diff > 0 ? `<span class="text-red-400 ml-2 text-xs font-semibold">(+${diff}ms)</span>` : 
                                   diff < 0 ? `<span class="text-emerald-400 ml-2 text-xs font-semibold">(${diff}ms)</span>` : 
                                   `<span class="text-slate-500 ml-2 text-xs font-semibold">(0ms)</span>`;
                    tr.innerHTML = `<td class="px-4 py-3 font-medium text-slate-300 border-t border-slate-800/50">${dPerf.labels[i]}</td>
                                    <td class="px-4 py-3 text-amber-400 border-t border-slate-800/50">${dPerf.current_times[i]} ${diffHtml}</td>
                                    <td class="px-4 py-3 text-slate-500 border-t border-slate-800/50">${dPerf.past_times[i]}</td>`;
                    tbodyPerf.appendChild(tr);
                }
            } catch(e) { console.error("Perf Chart Error:", e); }

            // --- LOAD SECURITY PARAMETERS DATA (Section 5) ---
            try {
                const rSec = await fetch('/analytics/security');
                const dSec = await rSec.json();

                const ctxSec = document.getElementById('securityChart').getContext('2d');
                if(secChart) secChart.destroy(); 
                
                secChart = new Chart(ctxSec, {
                    type: 'bar',
                    data: {
                        labels: dSec.parameters,
                        datasets: [
                            {
                                label: 'Raw Parameter Size (Bits)',
                                data: dSec.size_bits,
                                backgroundColor: 'rgba(34, 211, 238, 0.7)', // Cyan
                                borderColor: '#22d3ee',
                                borderWidth: 1,
                                borderRadius: 4
                            },
                            {
                                label: 'Effective Security Level (Bits)',
                                data: dSec.security_bits,
                                backgroundColor: 'rgba(99, 102, 241, 0.7)', // Indigo
                                borderColor: '#6366f1',
                                borderWidth: 1,
                                borderRadius: 4
                            }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        scales: { 
                            y: { 
                                beginAtZero: true, 
                                max: 300,
                                title: { display: true, text: 'Bits', color: '#94a3b8' },
                                grid: { color: 'rgba(51, 65, 85, 0.5)' }, ticks: { color: '#94a3b8' } 
                            },
                            x: { grid: { display: false }, ticks: { color: '#94a3b8', font: {size: 11} } } 
                        },
                        plugins: { legend: { labels: { color: '#cbd5e1' } } }
                    }
                });

                const tbodySec = document.getElementById('securityTableBody');
                tbodySec.innerHTML = ''; 
                for (let i = 0; i < dSec.parameters.length; i++) {
                    const tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-800/40 transition-colors';
                    tr.innerHTML = `
                        <td class="px-4 py-3 font-medium text-slate-300 border-t border-slate-800/50">${dSec.parameters[i]}</td>
                        <td class="px-4 py-3 text-cyan-400 font-mono border-t border-slate-800/50">${dSec.size_bits[i]} bits</td>
                        <td class="px-4 py-3 text-indigo-400 font-mono border-t border-slate-800/50">${dSec.security_bits[i]} bits</td>
                    `;
                    tbodySec.appendChild(tr);
                }
            } catch(e) { console.error("Sec Chart Error:", e); }
        }

        window.addEventListener('DOMContentLoaded', loadCharts);
    </script>
</body>
</html>
"""

# ==========================================
# API ENDPOINTS
# ==========================================

@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
def serve_ui():
    return HTML_CONTENT

@app.get("/encryption/generate-key")
def generate_key():
    start = time.perf_counter()
    key = Fernet.generate_key().decode()
    log_performance("Gen Sym Key", start)
    return {"key": key}

class EnDecryptRequest(BaseModel):
    key: str
    data: str

@app.post("/encryption/encrypt")
def encrypt_data_endpoint(req: EnDecryptRequest):
    start = time.perf_counter()
    try:
        f = Fernet(req.key.encode())
        res = {"encrypted_data": f.encrypt(req.data.encode()).decode()}
        log_performance("Encrypt Text", start)
        return res
    except: raise HTTPException(status_code=400, detail="Invalid Key/Data")

@app.post("/encryption/decrypt")
def decrypt_data_endpoint(req: EnDecryptRequest):
    start = time.perf_counter()
    try:
        f = Fernet(req.key.encode())
        res = {"decrypted_data": f.decrypt(req.data.encode()).decode()}
        log_performance("Decrypt Text", start)
        return res
    except: raise HTTPException(status_code=400, detail="Decryption Failed")

@app.post("/auth/generate-keys")
def generate_auth_keys(password: str):
    start = time.perf_counter()
    priv, pub = auth_tool.generate_key_pair()
    res = {
        "private_key_pem": priv.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ).decode(),
        "public_key_pem": pub.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }
    log_performance("Gen Auth Keys", start)
    return res

@app.post("/auth/sign-file")
async def sign_file(private_key_pem: str = Form(...), private_key_password: str = Form(...), file: UploadFile = File(...)):
    start = time.perf_counter()
    fb = await file.read()
    pk = serialization.load_pem_private_key(private_key_pem.encode(), password=private_key_password.encode())
    res = {"signature_hex": auth_tool.sign_data(pk, fb).hex()}
    log_performance("Sign File", start)
    return res

@app.post("/auth/verify-png")
async def verify_png(public_key_pem: str = Form(...), signature_hex: str = Form(...), file: UploadFile = File(...)):
    start = time.perf_counter()
    fb = await file.read()
    pbk = serialization.load_pem_public_key(public_key_pem.encode())
    res = {"is_valid": auth_tool.verify_signature(pbk, fb, bytes.fromhex(signature_hex))}
    log_performance("Verify File", start)
    return res

@app.get("/analytics/data")
def get_analytics_data():
    """Returns actual processing times alongside historical baselines for comparison."""
    labels = [item[0] for item in performance_logs]
    current_times = [item[1] for item in performance_logs]
    
    past_times = [PAST_PERFORMANCE_BASELINE.get(label, 20) for label in labels]

    return {
        "labels": labels,
        "current_times": current_times,
        "past_times": past_times
    }

@app.get("/analytics/security")
def get_security_parameters():
    """Returns static security parameters representing the exact algorithms used in this API."""
    return {
        "parameters": [
            "Fernet Encryption (AES-128 CBC)", 
            "Fernet Auth (HMAC-SHA256)", 
            "File Identity (ECDSA P-256)", 
            "File Integrity (SHA-256)"
        ],
        "size_bits": [128, 256, 256, 256],       # The raw size of the keys/hashes
        "security_bits": [128, 128, 128, 128]    # The effective security level they provide against brute force
    }