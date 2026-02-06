import { KyuStream } from './kyu.js';

const fileInput = document.getElementById('fileInput');
const dropZone = document.getElementById('dropZone');
const playBtn = document.getElementById('playBtn');
const downloadBtn = document.getElementById('downloadBtn');
const status = document.getElementById('status');
const video = document.getElementById('videoPlayer');
const passInput = document.getElementById('passInput');

let kyu = null;
let currentDecryptedBlobUrl = null;
let originalFileName = "";

// --- Drag & Drop Handling ---
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => { 
    e.preventDefault(); 
    dropZone.style.borderColor = '#007bff'; 
    dropZone.style.background = '#252525';
});

dropZone.addEventListener('dragleave', () => { 
    dropZone.style.borderColor = '#444'; 
    dropZone.style.background = '';
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = '#444';
    dropZone.style.background = '';
    if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        handleFileSelect();
    }
});

fileInput.addEventListener('change', handleFileSelect);

function handleFileSelect() {
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        originalFileName = file.name;
        
        // Reset UI
        downloadBtn.disabled = true;
        if (currentDecryptedBlobUrl) {
            URL.revokeObjectURL(currentDecryptedBlobUrl);
            currentDecryptedBlobUrl = null;
        }

        dropZone.innerHTML = `
            <p style="color:#55ff55; font-weight:bold; font-size:1.1em;">
                Ready: ${file.name}
            </p>
            <p style="color:#888; font-size:0.9em;">
                ${(file.size / 1024 / 1024).toFixed(2)} MB
            </p>
        `;
        dropZone.style.borderColor = "#55ff55";
        
        status.textContent = "File Loaded. Enter password if required.";
        status.style.color = "#fff";
        playBtn.disabled = false;
    }
}

// --- Decryption Logic ---

playBtn.addEventListener('click', async () => {
    try {
        playBtn.disabled = true;
        downloadBtn.disabled = true;
        status.textContent = "Initializing WASM...";
        status.style.color = "#aaa";

        // 1. Get Password
        const password = passInput.value || "kyu-insecure-default";

        // 2. Initialize Kyu
        status.textContent = "Deriving Key (Argon2id)...";
        kyu = await KyuStream.create(password);
        
        status.textContent = "Buffering & Decrypting...";
        const file = fileInput.files[0];

        // 3. Setup Streams
        const fileStream = file.stream();
        const decryptedStream = fileStream.pipeThrough(kyu.transform);

        // 4. Blob & Play
        const newResponse = new Response(decryptedStream);
        const rawBlob = await newResponse.blob();
        
        const videoBlob = new Blob([rawBlob], { type: 'video/mp4' });
        currentDecryptedBlobUrl = URL.createObjectURL(videoBlob);
        
        video.src = currentDecryptedBlobUrl;
        video.play();
        
        status.textContent = "Playing Secure Stream";
        status.style.color = "#55ff55";
        
        // Enable Controls
        playBtn.disabled = false;
        downloadBtn.disabled = false;

    } catch (e) {
        console.error(e);
        const msg = e.message || "";
        
        if (msg.includes("-103")) {
            status.textContent = "Error: Wrong Password!";
        } else if (msg.includes("-104")) {
            status.textContent = "Error: Invalid File Format (Not KYU5)";
        } else if (msg.includes("-107")) {
            status.textContent = "Error: Buffer Too Small (Corrupt Packet?)";
        } else {
            status.textContent = `Error: ${msg}`;
        }
        
        status.style.color = "#ff5555";
        playBtn.disabled = false;
    }
});

// --- Download Logic ---
downloadBtn.addEventListener('click', () => {
    if (!currentDecryptedBlobUrl) return;

    const a = document.createElement('a');
    a.href = currentDecryptedBlobUrl;
    
    // Intelligent renaming: remove .kyu extension if present
    let downloadName = originalFileName.replace(/\.kyu$/, "");
    if (downloadName === originalFileName) {
        downloadName += ".decrypted.mp4";
    }
    
    a.download = downloadName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
});
