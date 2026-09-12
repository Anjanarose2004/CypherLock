/**
 * Cypher-Lock Enterprise Web Studio - Client Engine
 * Fully integrated reactive logic for keys, encryption, decryption, and password management.
 */

document.addEventListener("DOMContentLoaded", () => {
    // --- State Store ---
    const state = {
        keyStatus: null,
        files: {
            receiverPub: null,
            senderPriv: null,
            targetFile: null,
            encFile: null,
            decPriv: null,
            senderPub: null
        }
    };

    // --- Element Selectors ---
    const el = {
        // Status & Badge
        keyStatusBadge: document.getElementById("keyStatusBadge"),
        vaultPathText: document.getElementById("vaultPathText"),
        pubKeyVaultStatus: document.getElementById("pubKeyVaultStatus"),
        privKeyVaultStatus: document.getElementById("privKeyVaultStatus"),
        pubKeyFingerprintVal: document.getElementById("pubKeyFingerprintVal"),
        btnCopyPublicKey: document.getElementById("btnCopyPublicKey"),

        // Navigation Tabs
        tabBtns: document.querySelectorAll(".nav-item"),
        panels: document.querySelectorAll(".panel"),

        // Encrypt Form
        receiverPubDropZone: document.getElementById("receiverPubDropZone"),
        receiverPubInput: document.getElementById("receiverPubInput"),
        receiverPubPill: document.getElementById("receiverPubPill"),
        receiverPubName: document.getElementById("receiverPubName"),
        receiverPubBadge: document.getElementById("receiverPubBadge"),
        removeReceiverPub: document.getElementById("removeReceiverPub"),

        radioUseDefaultPriv: document.getElementById("radioUseDefaultPriv"),
        radioUseCustomPriv: document.getElementById("radioUseCustomPriv"),
        lblUseDefaultPriv: document.getElementById("lblUseDefaultPriv"),
        lblUseCustomPriv: document.getElementById("lblUseCustomPriv"),
        senderPrivDropZone: document.getElementById("senderPrivDropZone"),
        senderPrivInput: document.getElementById("senderPrivInput"),
        senderPrivPill: document.getElementById("senderPrivPill"),
        senderPrivName: document.getElementById("senderPrivName"),
        removeSenderPriv: document.getElementById("removeSenderPriv"),
        encryptPassphrase: document.getElementById("encryptPassphrase"),

        targetFileDropZone: document.getElementById("targetFileDropZone"),
        targetFileInput: document.getElementById("targetFileInput"),
        targetFilePill: document.getElementById("targetFilePill"),
        targetFileName: document.getElementById("targetFileName"),
        targetFileSize: document.getElementById("targetFileSize"),
        removeTargetFile: document.getElementById("removeTargetFile"),
        btnRunEncrypt: document.getElementById("btnRunEncrypt"),
        encryptResultCard: document.getElementById("encryptResultCard"),
        resEncFileName: document.getElementById("resEncFileName"),

        // Decrypt Form
        encFileDropZone: document.getElementById("encFileDropZone"),
        encFileInput: document.getElementById("encFileInput"),
        encFilePill: document.getElementById("encFilePill"),
        encFileName: document.getElementById("encFileName"),
        encFileSize: document.getElementById("encFileSize"),
        removeEncFile: document.getElementById("removeEncFile"),

        radioDecUseDefaultPriv: document.getElementById("radioDecUseDefaultPriv"),
        radioDecUseCustomPriv: document.getElementById("radioDecUseCustomPriv"),
        lblDecUseDefaultPriv: document.getElementById("lblDecUseDefaultPriv"),
        lblDecUseCustomPriv: document.getElementById("lblDecUseCustomPriv"),
        decPrivDropZone: document.getElementById("decPrivDropZone"),
        decPrivInput: document.getElementById("decPrivInput"),
        decPrivPill: document.getElementById("decPrivPill"),
        decPrivName: document.getElementById("decPrivName"),
        removeDecPriv: document.getElementById("removeDecPriv"),
        decryptPassphrase: document.getElementById("decryptPassphrase"),

        senderPubDropZone: document.getElementById("senderPubDropZone"),
        senderPubInput: document.getElementById("senderPubInput"),
        senderPubPill: document.getElementById("senderPubPill"),
        senderPubName: document.getElementById("senderPubName"),
        senderPubBadge: document.getElementById("senderPubBadge"),
        removeSenderPub: document.getElementById("removeSenderPub"),

        btnRunDecrypt: document.getElementById("btnRunDecrypt"),
        decryptResultCard: document.getElementById("decryptResultCard"),
        resDecFileName: document.getElementById("resDecFileName"),
        resEncTimestamp: document.getElementById("resEncTimestamp"),

        // Key Generation
        newKeyPassphrase: document.getElementById("newKeyPassphrase"),
        pwdStrengthBar: document.getElementById("pwdStrengthBar"),
        critLen: document.getElementById("crit-len"),
        critUpper: document.getElementById("crit-upper"),
        critLower: document.getElementById("crit-lower"),
        critNum: document.getElementById("crit-num"),
        critSym: document.getElementById("crit-sym"),
        btnRunGenerateKey: document.getElementById("btnRunGenerateKey"),

        // Passphrase Rotation
        currPassphrase: document.getElementById("currPassphrase"),
        changeNewPassphrase: document.getElementById("changeNewPassphrase"),
        btnRunChangePwd: document.getElementById("btnRunChangePwd"),

        // Modals & Toasts
        confirmModal: document.getElementById("confirmModal"),
        modalTitle: document.getElementById("modalTitle"),
        modalMsg: document.getElementById("modalMsg"),
        modalCancelBtn: document.getElementById("modalCancelBtn"),
        modalConfirmBtn: document.getElementById("modalConfirmBtn"),
        toastContainer: document.getElementById("toastContainer")
    };

    // --- Toast Notifications ---
    function showToast(message, type = "info", title = "") {
        if (!el.toastContainer) return;
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        
        let iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
        if (type === "success") {
            iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>';
        } else if (type === "error") {
            iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
        } else if (type === "warning") {
            iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
        }

        toast.innerHTML = `
            <div class="toast-icon">${iconSvg}</div>
            <div>
                ${title ? `<div class="toast-title">${escapeHtml(title)}</div>` : ""}
                <div class="toast-desc">${escapeHtml(message)}</div>
            </div>
        `;
        el.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(8px)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(() => toast.remove(), 300);
        }, 4500);
    }

    function escapeHtml(str) {
        return (str || "").replace(/[&<>"']/g, m => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[m]));
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    // --- Tab Navigation Switching ---
    el.tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            el.tabBtns.forEach(b => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            el.panels.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");
            const panel = document.getElementById(targetTab);
            if (panel) panel.classList.add("active");
        });
    });

    // --- Password Visibility Toggles ---
    document.querySelectorAll(".btn-toggle-pwd").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const input = document.getElementById(targetId);
            if (!input) return;
            const eyeOpen = btn.querySelector(".eye-open");
            const eyeClosed = btn.querySelector(".eye-closed");

            if (input.type === "password") {
                input.type = "text";
                if (eyeOpen) eyeOpen.classList.add("hidden");
                if (eyeClosed) eyeClosed.classList.remove("hidden");
            } else {
                input.type = "password";
                if (eyeOpen) eyeOpen.classList.remove("hidden");
                if (eyeClosed) eyeClosed.classList.add("hidden");
            }
        });
    });

    // --- Password Strength Meter ---
    if (el.newKeyPassphrase) {
        el.newKeyPassphrase.addEventListener("input", () => {
            const val = el.newKeyPassphrase.value;
            const criteria = {
                len: val.length >= 12,
                upper: /[A-Z]/.test(val),
                lower: /[a-z]/.test(val),
                num: /[0-9]/.test(val),
                sym: /[^A-Za-z0-9]/.test(val)
            };

            updateCriterion(el.critLen, criteria.len);
            updateCriterion(el.critUpper, criteria.upper);
            updateCriterion(el.critLower, criteria.lower);
            updateCriterion(el.critNum, criteria.num);
            updateCriterion(el.critSym, criteria.sym);

            const score = Object.values(criteria).filter(Boolean).length;
            if (!el.pwdStrengthBar) return;
            el.pwdStrengthBar.className = "meter-fill";
            if (score <= 2) {
                el.pwdStrengthBar.classList.add("weak");
            } else if (score < 5) {
                el.pwdStrengthBar.classList.add("medium");
            } else {
                el.pwdStrengthBar.classList.add("strong");
            }
        });
    }

    function updateCriterion(elem, isMet) {
        if (!elem) return;
        if (isMet) elem.classList.add("met");
        else elem.classList.remove("met");
    }

    // --- Status Refresh ---
    async function refreshStatus() {
        try {
            const res = await fetch("/api/status");
            if (!res.ok) throw new Error("Status check failed");
            const data = await res.json();
            state.keyStatus = data;

            if (el.vaultPathText && data.app_dir) {
                el.vaultPathText.textContent = data.app_dir;
            }

            // Global navbar badge
            if (el.keyStatusBadge) {
                if (data.keys_exist) {
                    el.keyStatusBadge.className = "key-status-chip ready";
                    el.keyStatusBadge.innerHTML = '<span class="status-dot"></span><span class="status-label">Identity Vault Active</span>';
                } else {
                    el.keyStatusBadge.className = "key-status-chip missing";
                    el.keyStatusBadge.innerHTML = '<span class="status-dot"></span><span class="status-label">No Keys in Vault</span>';
                }
            }

            // Key Hub Tab
            if (el.pubKeyVaultStatus) {
                if (data.has_public_key) {
                    el.pubKeyVaultStatus.className = "status-chip active";
                    el.pubKeyVaultStatus.textContent = "Present (RSA-3072)";
                } else {
                    el.pubKeyVaultStatus.className = "status-chip none";
                    el.pubKeyVaultStatus.textContent = "Missing";
                }
            }
            if (el.privKeyVaultStatus) {
                if (data.has_private_key) {
                    el.privKeyVaultStatus.className = "status-chip active";
                    el.privKeyVaultStatus.textContent = "Present (PKCS#8)";
                } else {
                    el.privKeyVaultStatus.className = "status-chip none";
                    el.privKeyVaultStatus.textContent = "Missing";
                }
            }
            if (el.pubKeyFingerprintVal) {
                el.pubKeyFingerprintVal.textContent = data.pub_fingerprint || "None (Generate keypair to activate)";
            }

        } catch (err) {
            console.error("Status fetch error:", err);
            if (el.keyStatusBadge) {
                el.keyStatusBadge.className = "key-status-chip missing";
                el.keyStatusBadge.innerHTML = '<span class="status-dot"></span><span class="status-label">Offline</span>';
            }
        }
    }

    // --- Copy Public Key PEM ---
    if (el.btnCopyPublicKey) {
        el.btnCopyPublicKey.addEventListener("click", async () => {
            if (!state.keyStatus || !state.keyStatus.public_key_text) {
                showToast("No public key found to copy.", "warning");
                return;
            }
            try {
                await navigator.clipboard.writeText(state.keyStatus.public_key_text);
                showToast("Public Key PEM copied to clipboard!", "success");
            } catch (e) {
                showToast("Failed to copy key to clipboard.", "error");
            }
        });
    }

    // --- Generic File Dropzone Wiring ---
    function setupDropzone(dropZone, input, pill, nameElem, clearBtn, onFileLoaded) {
        if (!dropZone || !input) return;

        dropZone.addEventListener("click", (e) => {
            if (e.target.closest(".btn-clear-file")) return;
            input.click();
        });

        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("dragover");
        });

        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleFile(e.dataTransfer.files[0]);
            }
        });

        input.addEventListener("change", () => {
            if (input.files && input.files.length > 0) {
                handleFile(input.files[0]);
            }
        });

        function handleFile(file) {
            if (nameElem) nameElem.textContent = file.name;
            if (pill) pill.classList.remove("hidden");
            const idle = dropZone.querySelector(".drop-idle-state");
            if (idle) idle.classList.add("hidden");
            if (onFileLoaded) onFileLoaded(file);
        }

        if (clearBtn) {
            clearBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                input.value = "";
                if (pill) pill.classList.add("hidden");
                const idle = dropZone.querySelector(".drop-idle-state");
                if (idle) idle.classList.remove("hidden");
                if (onFileLoaded) onFileLoaded(null);
            });
        }
    }

    // 1. Recipient Public Key (Encrypt)
    setupDropzone(
        el.receiverPubDropZone,
        el.receiverPubInput,
        el.receiverPubPill,
        el.receiverPubName,
        el.removeReceiverPub,
        async (file) => {
            state.files.receiverPub = file;
            if (!file) return;
            // Validate PEM structure via server
            const formData = new FormData();
            formData.append("file", file);
            formData.append("type", "public");
            try {
                const res = await fetch("/api/keys/validate-pem", { method: "POST", body: formData });
                const json = await res.json();
                if (el.receiverPubBadge) {
                    if (json.valid) {
                        el.receiverPubBadge.className = "pill-tag success";
                        el.receiverPubBadge.textContent = "Verified RSA-3072";
                    } else {
                        el.receiverPubBadge.className = "pill-tag";
                        el.receiverPubBadge.style.background = "rgba(239,68,68,0.2)";
                        el.receiverPubBadge.style.color = "#fca5a5";
                        el.receiverPubBadge.textContent = "Invalid Key";
                        showToast(json.error || "Public key is not valid RSA-3072", "error");
                    }
                }
            } catch (err) {
                console.error(err);
            }
        }
    );

    // 2. Sender Private Key Radio & Dropzone
    if (el.radioUseDefaultPriv && el.radioUseCustomPriv) {
        el.radioUseDefaultPriv.addEventListener("change", () => {
            el.lblUseDefaultPriv.classList.add("active");
            el.lblUseCustomPriv.classList.remove("active");
            el.senderPrivDropZone.classList.add("hidden");
        });
        el.radioUseCustomPriv.addEventListener("change", () => {
            el.lblUseCustomPriv.classList.add("active");
            el.lblUseDefaultPriv.classList.remove("active");
            el.senderPrivDropZone.classList.remove("hidden");
        });
    }

    setupDropzone(
        el.senderPrivDropZone,
        el.senderPrivInput,
        el.senderPrivPill,
        el.senderPrivName,
        el.removeSenderPriv,
        (file) => { state.files.senderPriv = file; }
    );

    // 3. Target Payload (Encrypt)
    setupDropzone(
        el.targetFileDropZone,
        el.targetFileInput,
        el.targetFilePill,
        el.targetFileName,
        el.removeTargetFile,
        (file) => {
            state.files.targetFile = file;
            if (file && el.targetFileSize) {
                el.targetFileSize.textContent = formatBytes(file.size);
            }
        }
    );

    // 4. Encrypted File (Decrypt)
    setupDropzone(
        el.encFileDropZone,
        el.encFileInput,
        el.encFilePill,
        el.encFileName,
        el.removeEncFile,
        (file) => {
            state.files.encFile = file;
            if (file && el.encFileSize) {
                el.encFileSize.textContent = formatBytes(file.size);
            }
        }
    );

    // 5. Decrypt Private Key Radio & Dropzone
    if (el.radioDecUseDefaultPriv && el.radioDecUseCustomPriv) {
        el.radioDecUseDefaultPriv.addEventListener("change", () => {
            el.lblDecUseDefaultPriv.classList.add("active");
            el.lblDecUseCustomPriv.classList.remove("active");
            el.decPrivDropZone.classList.add("hidden");
        });
        el.radioDecUseCustomPriv.addEventListener("change", () => {
            el.lblDecUseCustomPriv.classList.add("active");
            el.lblDecUseDefaultPriv.classList.remove("active");
            el.decPrivDropZone.classList.remove("hidden");
        });
    }

    setupDropzone(
        el.decPrivDropZone,
        el.decPrivInput,
        el.decPrivPill,
        el.decPrivName,
        el.removeDecPriv,
        (file) => { state.files.decPriv = file; }
    );

    // 6. Sender Public Key (Decrypt)
    setupDropzone(
        el.senderPubDropZone,
        el.senderPubInput,
        el.senderPubPill,
        el.senderPubName,
        el.removeSenderPub,
        async (file) => {
            state.files.senderPub = file;
            if (!file) return;
            const formData = new FormData();
            formData.append("file", file);
            formData.append("type", "public");
            try {
                const res = await fetch("/api/keys/validate-pem", { method: "POST", body: formData });
                const json = await res.json();
                if (el.senderPubBadge) {
                    if (json.valid) {
                        el.senderPubBadge.className = "pill-tag success";
                        el.senderPubBadge.textContent = "Verified RSA-3072";
                    } else {
                        el.senderPubBadge.className = "pill-tag";
                        el.senderPubBadge.style.background = "rgba(239,68,68,0.2)";
                        el.senderPubBadge.style.color = "#fca5a5";
                        el.senderPubBadge.textContent = "Invalid Key";
                        showToast(json.error || "Sender public key is not valid RSA-3072", "error");
                    }
                }
            } catch (err) {
                console.error(err);
            }
        }
    );

    // --- Trigger Encryption Workflow ---
    if (el.btnRunEncrypt) {
        el.btnRunEncrypt.addEventListener("click", async () => {
            if (!state.files.receiverPub) {
                showToast("Recipient's public key (RSA-3072) is required.", "warning");
                return;
            }
            const useDefaultPriv = el.radioUseDefaultPriv && el.radioUseDefaultPriv.checked;
            if (!useDefaultPriv && !state.files.senderPriv) {
                showToast("Please upload sender's private key or use default key.", "warning");
                return;
            }
            if (useDefaultPriv && (!state.keyStatus || !state.keyStatus.has_private_key)) {
                showToast("Default private key not found in vault. Generate keys in Key Management.", "error");
                return;
            }
            if (!state.files.targetFile) {
                showToast("Please select a target payload file to encrypt.", "warning");
                return;
            }

            const spinner = el.btnRunEncrypt.querySelector(".spinner");
            el.btnRunEncrypt.disabled = true;
            if (spinner) spinner.classList.remove("hidden");

            const formData = new FormData();
            formData.append("receiver_pub", state.files.receiverPub);
            formData.append("use_default_priv", useDefaultPriv ? "true" : "false");
            if (!useDefaultPriv && state.files.senderPriv) {
                formData.append("sender_priv", state.files.senderPriv);
            }
            if (el.encryptPassphrase && el.encryptPassphrase.value) {
                formData.append("passphrase", el.encryptPassphrase.value);
            }
            formData.append("file", state.files.targetFile);

            try {
                const res = await fetch("/api/encrypt", { method: "POST", body: formData });
                if (!res.ok) {
                    const errJson = await res.json().catch(() => ({ error: "Encryption error" }));
                    throw new Error(errJson.error || "Encryption failed");
                }

                const blob = await res.blob();
                const outFilename = res.headers.get("X-Encrypted-Filename") || (state.files.targetFile.name + ".enc");
                
                // Automatic Browser Download
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = downloadUrl;
                a.download = outFilename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(downloadUrl);

                showToast(`Payload encrypted and downloaded: ${outFilename}`, "success", "Encryption Success");

                if (el.encryptResultCard) {
                    el.encryptResultCard.classList.remove("hidden");
                    if (el.resEncFileName) el.resEncFileName.textContent = outFilename;
                }

            } catch (err) {
                showToast(err.message, "error", "Operation Failed");
            } finally {
                el.btnRunEncrypt.disabled = false;
                if (spinner) spinner.classList.add("hidden");
            }
        });
    }

    // --- Trigger Decryption Workflow ---
    if (el.btnRunDecrypt) {
        el.btnRunDecrypt.addEventListener("click", async () => {
            if (!state.files.encFile) {
                showToast("Please select the encrypted (*.enc) file.", "warning");
                return;
            }
            const useDefaultPriv = el.radioDecUseDefaultPriv && el.radioDecUseDefaultPriv.checked;
            if (!useDefaultPriv && !state.files.decPriv) {
                showToast("Recipient private key is required.", "warning");
                return;
            }
            if (useDefaultPriv && (!state.keyStatus || !state.keyStatus.has_private_key)) {
                showToast("Default private key not found in vault. Generate keys in Key Management.", "error");
                return;
            }
            if (!state.files.senderPub) {
                showToast("Sender's public key is required to authenticate digital signature.", "warning");
                return;
            }

            const spinner = el.btnRunDecrypt.querySelector(".spinner");
            el.btnRunDecrypt.disabled = true;
            if (spinner) spinner.classList.remove("hidden");

            const formData = new FormData();
            formData.append("file", state.files.encFile);
            formData.append("use_default_priv", useDefaultPriv ? "true" : "false");
            if (!useDefaultPriv && state.files.decPriv) {
                formData.append("receiver_priv", state.files.decPriv);
            }
            if (el.decryptPassphrase && el.decryptPassphrase.value) {
                formData.append("passphrase", el.decryptPassphrase.value);
            }
            formData.append("sender_pub", state.files.senderPub);

            try {
                const res = await fetch("/api/decrypt", { method: "POST", body: formData });
                if (!res.ok) {
                    const errJson = await res.json().catch(() => ({ error: "Decryption error" }));
                    throw new Error(errJson.error || "Decryption failed");
                }

                const blob = await res.blob();
                const outFilename = res.headers.get("X-Decrypted-Filename") || "decrypted_file";
                const encTime = res.headers.get("X-Encrypted-Timestamp") || "Verified";

                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = downloadUrl;
                a.download = outFilename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(downloadUrl);

                showToast(`Verified and decrypted: ${outFilename}`, "success", "Decryption Success");

                if (el.decryptResultCard) {
                    el.decryptResultCard.classList.remove("hidden");
                    if (el.resDecFileName) el.resDecFileName.textContent = outFilename;
                    if (el.resEncTimestamp) el.resEncTimestamp.textContent = encTime;
                }

            } catch (err) {
                showToast(err.message, "error", "Decryption Failed");
            } finally {
                el.btnRunDecrypt.disabled = false;
                if (spinner) spinner.classList.add("hidden");
            }
        });
    }

    // --- Keypair Generation Workflow ---
    if (el.btnRunGenerateKey) {
        el.btnRunGenerateKey.addEventListener("click", () => {
            const pwd = el.newKeyPassphrase ? el.newKeyPassphrase.value : "";
            if (!pwd) {
                showToast("Please enter a passphrase for the private key.", "warning");
                return;
            }

            // If keys already exist, trigger confirmation modal
            if (state.keyStatus && state.keyStatus.keys_exist) {
                showConfirmModal(
                    "Overwrite Existing Keypair?",
                    "Existing RSA keys are present in ~/.cypher_lock/. Generating new keys will permanently make older encrypted payloads unrecoverable. Are you sure?",
                    () => executeGenerate(pwd, true)
                );
            } else {
                executeGenerate(pwd, false);
            }
        });
    }

    async function executeGenerate(passphrase, force = false) {
        const spinner = el.btnRunGenerateKey.querySelector(".spinner");
        el.btnRunGenerateKey.disabled = true;
        if (spinner) spinner.classList.remove("hidden");

        try {
            const res = await fetch("/api/keys/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ passphrase, force })
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.error || "Key generation failed");
            }

            showToast(data.message, "success", "Keys Generated");
            if (el.newKeyPassphrase) el.newKeyPassphrase.value = "";
            await refreshStatus();

        } catch (err) {
            showToast(err.message, "error");
        } finally {
            el.btnRunGenerateKey.disabled = false;
            if (spinner) spinner.classList.add("hidden");
        }
    }

    // --- Passphrase Rotation Workflow ---
    if (el.btnRunChangePwd) {
        el.btnRunChangePwd.addEventListener("click", async () => {
            const oldPwd = el.currPassphrase ? el.currPassphrase.value : "";
            const newPwd = el.changeNewPassphrase ? el.changeNewPassphrase.value : "";

            if (!newPwd) {
                showToast("Please provide the new passphrase.", "warning");
                return;
            }

            const spinner = el.btnRunChangePwd.querySelector(".spinner");
            el.btnRunChangePwd.disabled = true;
            if (spinner) spinner.classList.remove("hidden");

            try {
                const res = await fetch("/api/keys/change-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ old_passphrase: oldPwd, new_passphrase: newPwd })
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || "Failed to update passphrase");
                }

                showToast(data.message, "success", "Passphrase Updated");
                if (el.currPassphrase) el.currPassphrase.value = "";
                if (el.changeNewPassphrase) el.changeNewPassphrase.value = "";

            } catch (err) {
                showToast(err.message, "error");
            } finally {
                el.btnRunChangePwd.disabled = false;
                if (spinner) spinner.classList.add("hidden");
            }
        });
    }

    // --- Confirmation Modal Handlers ---
    let pendingConfirmAction = null;

    function showConfirmModal(title, msg, onConfirm) {
        if (!el.confirmModal) return;
        if (el.modalTitle) el.modalTitle.textContent = title;
        if (el.modalMsg) el.modalMsg.textContent = msg;
        pendingConfirmAction = onConfirm;
        el.confirmModal.classList.remove("hidden");
    }

    if (el.modalCancelBtn) {
        el.modalCancelBtn.addEventListener("click", () => {
            if (el.confirmModal) el.confirmModal.classList.add("hidden");
            pendingConfirmAction = null;
        });
    }

    if (el.modalConfirmBtn) {
        el.modalConfirmBtn.addEventListener("click", () => {
            if (el.confirmModal) el.confirmModal.classList.add("hidden");
            if (pendingConfirmAction) pendingConfirmAction();
            pendingConfirmAction = null;
        });
    }

    // Initial Load
    refreshStatus();
});
