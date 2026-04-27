"""Unit tests for the CodeAnalyzer class.

Tests AST parsing, scanner extraction, and metadata generation.
"""

import tempfile
from pathlib import Path

import pytest

from patent_docs.analyzers.code_analyzer import (
    CodeAnalyzer,
)


# Sample code for testing
SAMPLE_SCANNER_CODE = '''"""Sample scanner for testing."""

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class TestScanner(PromptScanner):
    """A test scanner for unit testing.
    
    This scanner detects test patterns in prompts.
    """
    
    scanner_name = "test_scanner"
    scanner_type = "prompt"
    
    def __init__(self, threshold: float = 0.5, custom_param: str = "default", **kwargs):
        """Initialize the test scanner.
        
        Args:
            threshold: Detection threshold.
            custom_param: Custom configuration parameter.
        """
        super().__init__(threshold=threshold, **kwargs)
        self.custom_param = custom_param
    
    def scan(self, text: str, **kwargs) -> ScanResult:
        """Scan text for test patterns.
        
        Args:
            text: Text to scan.
            
        Returns:
            ScanResult with detection status.
        """
        score = self._compute_score(text)
        is_valid = score < self.threshold
        
        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.LOW,
        )
    
    def _compute_score(self, text: str) -> float:
        """Compute detection score."""
        return 0.5
    
    def _analyze_patterns(self, text: str) -> dict:
        """Analyze text patterns."""
        return {"pattern_count": 0}
'''

SAMPLE_BASE_CLASS_CODE = '''"""Sample base class for testing."""

from abc import ABC, abstractmethod


class BaseValidator(ABC):
    """Base class for validators."""
    
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
    
    @abstractmethod
    def validate(self, text: str) -> bool:
        """Validate text."""
        pass
'''


class TestCodeAnalyzer:
    """Test suite for CodeAnalyzer."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def analyzer(self, temp_dir):
        """Create a CodeAnalyzer instance."""
        return CodeAnalyzer(str(temp_dir))
    
    @pytest.fixture
    def sample_scanner_file(self, temp_dir):
        """Create a sample scanner file."""
        file_path = temp_dir / "test_scanner.py"
        file_path.write_text(SAMPLE_SCANNER_CODE)
        return file_path
    
    @pytest.fixture
    def sample_base_file(self, temp_dir):
        """Create a sample base class file."""
        file_path = temp_dir / "base_validator.py"
        file_path.write_text(SAMPLE_BASE_CLASS_CODE)
        return file_path
    
    def test_analyze_file_basic(self, analyzer, sample_scanner_file):
        """Test basic file analysis."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        
        assert module_info.file_path == str(sample_scanner_file)
        assert module_info.docstring == "Sample scanner for testing."
        assert len(module_info.classes) == 1
        assert module_info.classes[0].name == "TestScanner"
    
    def test_extract_class_info(self, analyzer, sample_scanner_file):
        """Test class information extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        assert class_info.name == "TestScanner"
        assert "PromptScanner" in class_info.base_classes
        assert class_info.docstring is not None
        assert "test scanner" in class_info.docstring.lower()
        assert class_info.is_scanner is True
    
    def test_extract_class_variables(self, analyzer, sample_scanner_file):
        """Test extraction of class variables."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        assert "scanner_name" in class_info.class_variables
        assert class_info.class_variables["scanner_name"] == "test_scanner"
        assert "scanner_type" in class_info.class_variables
        assert class_info.class_variables["scanner_type"] == "prompt"
    
    def test_extract_methods(self, analyzer, sample_scanner_file):
        """Test method extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        method_names = [m.name for m in class_info.methods]
        assert "__init__" in method_names
        assert "scan" in method_names
        assert "_compute_score" in method_names
        assert "_analyze_patterns" in method_names
    
    def test_extract_method_details(self, analyzer, sample_scanner_file):
        """Test detailed method information extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        scan_method = next(m for m in class_info.methods if m.name == "scan")
        assert scan_method.docstring is not None
        assert "text" in scan_method.args
        assert scan_method.return_annotation == "ScanResult"
    
    def test_extract_decorators(self, analyzer, sample_scanner_file):
        """Test decorator extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        assert "register_scanner" in class_info.decorators
    
    def test_extract_abstract_methods(self, analyzer, sample_base_file):
        """Test abstract method detection."""
        module_info = analyzer.analyze_file(str(sample_base_file))
        class_info = module_info.classes[0]
        
        validate_method = next(m for m in class_info.methods if m.name == "validate")
        assert validate_method.is_abstract is True
        assert "abstractmethod" in validate_method.decorators
    
    def test_is_scanner_class(self, analyzer, sample_scanner_file):
        """Test scanner class detection."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        assert analyzer._is_scanner_class(class_info) is True
    
    def test_extract_scanners(self, analyzer, sample_scanner_file):
        """Test scanner extraction from modules."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        scanners = analyzer.extract_scanners([module_info])
        
        assert len(scanners) == 1
        scanner_info = scanners[0]
        assert scanner_info.name == "TestScanner"
        assert scanner_info.scanner_name == "test_scanner"
        assert scanner_info.scanner_type == "prompt"
    
    def test_extract_algorithms(self, analyzer, sample_scanner_file):
        """Test algorithm extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        algorithms = analyzer.extract_algorithms(class_info)
        assert "scan" in algorithms
        assert "_compute_score" in algorithms
        assert "_analyze_patterns" in algorithms
    
    def test_extract_config_options(self, analyzer, sample_scanner_file):
        """Test configuration option extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        class_info = module_info.classes[0]
        
        config_options = analyzer.extract_config_options(class_info)
        assert "threshold" in config_options
        assert "custom_param" in config_options
    
    def test_analyze_directory(self, analyzer, temp_dir, sample_scanner_file, sample_base_file):
        """Test directory analysis."""
        modules = analyzer.analyze_directory(str(temp_dir))
        
        assert len(modules) == 2
        module_names = [Path(m.file_path).name for m in modules]
        assert "test_scanner.py" in module_names
        assert "base_validator.py" in module_names
    
    def test_extract_imports(self, analyzer, sample_scanner_file):
        """Test import extraction."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        
        assert "sentinelguard.core.scanner" in module_info.imports
    
    def test_invalid_syntax_handling(self, analyzer, temp_dir):
        """Test handling of files with syntax errors."""
        invalid_file = temp_dir / "invalid.py"
        invalid_file.write_text("def broken syntax here")
        
        with pytest.raises(ValueError, match="Failed to parse"):
            analyzer.analyze_file(str(invalid_file))
    
    def test_scanner_detection_methods(self, analyzer, sample_scanner_file):
        """Test detection method extraction from scanners."""
        module_info = analyzer.analyze_file(str(sample_scanner_file))
        scanners = analyzer.extract_scanners([module_info])
        
        scanner_info = scanners[0]
        assert "scan" in scanner_info.detection_methods


class TestRealScannerAnalysis:
    """Test CodeAnalyzer on real SentinelGuard scanner files."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer for the real codebase."""
        return CodeAnalyzer("sentinelguard")
    
    def test_analyze_prompt_injection_scanner(self, analyzer):
        """Test analysis of the real PromptInjectionScanner."""
        file_path = "sentinelguard/scanners/prompt/prompt_injection.py"
        module_info = analyzer.analyze_file(file_path)
        
        assert len(module_info.classes) >= 1
        
        # Find the PromptInjectionScanner class
        scanner_class = next(
            (c for c in module_info.classes if c.name == "PromptInjectionScanner"),
            None
        )
        assert scanner_class is not None
        assert scanner_class.is_scanner is True
        assert "PromptScanner" in scanner_class.base_classes
    
    def test_extract_real_scanner_algorithms(self, analyzer):
        """Test algorithm extraction from real scanner."""
        file_path = "sentinelguard/scanners/prompt/prompt_injection.py"
        module_info = analyzer.analyze_file(file_path)
        
        scanner_class = next(
            (c for c in module_info.classes if c.name == "PromptInjectionScanner"),
            None
        )
        
        algorithms = analyzer.extract_algorithms(scanner_class)
        assert "scan" in algorithms
        # Should detect internal analysis methods
        assert any("scan" in alg or "detect" in alg for alg in algorithms)
    
    def test_extract_real_scanner_config(self, analyzer):
        """Test config extraction from real scanner."""
        file_path = "sentinelguard/scanners/prompt/prompt_injection.py"
        module_info = analyzer.analyze_file(file_path)
        
        scanner_class = next(
            (c for c in module_info.classes if c.name == "PromptInjectionScanner"),
            None
        )
        
        config_options = analyzer.extract_config_options(scanner_class)
        assert "threshold" in config_options
