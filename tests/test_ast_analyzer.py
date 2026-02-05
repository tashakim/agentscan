"""
Tests for AST-based pattern detection.

This is a starter template - add more tests!
"""

import pytest
from anchorscan.ast_analyzer import ASTAnalyzer, Detection


class TestLoggingDetection:
    """Test logging pattern detection."""
    
    def test_logging_import_detected(self):
        """Test that logging import is detected."""
        code = "import logging\nlogger = logging.getLogger()"
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_logging_imports()
        
        assert len(detections) > 0
        assert detections[0].category == "logging_import"
        assert detections[0].detection_type == "import"
    
    def test_logging_call_detected(self):
        """Test that logging calls are detected."""
        code = """
import logging
logger = logging.getLogger()
logger.info("test message")
"""
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_logging_calls()
        
        assert len(detections) > 0
        assert any(d.category == "logging_call" for d in detections)
    
    def test_unused_import_not_detected_as_call(self):
        """Test that unused imports don't create false positives."""
        code = "import logging\n# Never used"
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        
        import_detections = analyzer.check_logging_imports()
        call_detections = analyzer.check_logging_calls()
        
        assert len(import_detections) > 0  # Import is detected
        assert len(call_detections) == 0   # But no calls = not used


class TestSecretDetection:
    """Test hardcoded secret detection."""
    
    def test_openai_key_detected(self):
        """Test that OpenAI API keys are detected."""
        code = 'api_key = "sk-1234567890abcdefghijklmnop"'
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_hardcoded_secrets()
        
        assert len(detections) > 0
        assert any("secret" in d.category for d in detections)
    
    def test_env_var_not_detected_as_secret(self):
        """Test that env vars are not flagged as secrets."""
        code = 'api_key = os.getenv("OPENAI_API_KEY")'
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_hardcoded_secrets()
        
        assert len(detections) == 0  # Should not detect env vars as secrets


class TestErrorHandling:
    """Test error handling detection."""
    
    def test_try_except_detected(self):
        """Test that try/except blocks are detected."""
        code = """
try:
    result = risky_operation()
except Exception as e:
    handle_error(e)
"""
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_error_handling()
        
        assert len(detections) > 0
        assert any("try_except" in d.category for d in detections)
    
    def test_bare_except_antipattern_detected(self):
        """Test that bare except clauses are detected as antipattern."""
        code = """
try:
    result = risky_operation()
except:  # Bare except - bad!
    pass
"""
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_error_handling()
        
        assert any("bare_except" in d.category for d in detections)


class TestEnvVarUsage:
    """Test environment variable usage detection."""
    
    def test_os_getenv_detected(self):
        """Test that os.getenv() is detected."""
        code = 'import os\napi_key = os.getenv("OPENAI_API_KEY")'
        analyzer = ASTAnalyzer("test.py", code)
        analyzer.parse()
        detections = analyzer.check_env_var_usage()
        
        assert len(detections) > 0
        assert any(d.category == "env_var_usage" for d in detections)


# TODO: Add more test classes:
# - TestCheckpointingPatterns
# - TestPIIPatterns  
# - TestRetentionPatterns
# - TestPolicyEnforcementPatterns
# - TestRollbackPatterns
# - TestRateLimitingPatterns
# - TestMonitoringPatterns

