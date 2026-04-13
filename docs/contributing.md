# Contributing to E8Mate

Thanks for your interest in contributing to E8Mate! This project aims to make Essential Eight compliance accessible to every Australian organisation.

## Priority Areas

We're actively looking for help with:

1. **Collector implementations** — Each Essential Eight control needs a collector. See `e8mate/collectors/patch_os.py` for the pattern.
2. **Nuclei templates** — Network-side checks that complement the host-based scanner.
3. **ML2/ML3 rules** — Extending checks beyond Maturity Level 1.
4. **HTML report template** — A professional, audit-ready report design.
5. **Test coverage** — Unit tests for collectors, scoring, and reporters.
6. **Documentation** — Usage guides, control references, deployment guides.

## Getting Started

```bash
git clone https://github.com/e8mate/e8mate.git
cd e8mate
pip install -e ".[dev]"
pytest
```

## Writing a Collector

1. Create `e8mate/collectors/your_control.py`
2. Extend `BaseCollector`:

```python
from e8mate.collectors.base import BaseCollector
from e8mate.evidence.models import *

class YourControlCollector(BaseCollector):
    control = E8Control.YOUR_CONTROL
    display_name = "Your Control Name"

    def collect(self) -> ControlResult:
        self._check_something()
        self._check_something_else()
        return self.build_result()

    def _check_something(self):
        output = self.run_powershell("Your-PowerShell-Command")
        finding = Finding(
            check_id="XX-ML1-001",
            control=self.control,
            title="What this checks",
            description="Why it matters",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="How to fix it",
        )
        # Evaluate output, set finding.outcome
        if output:
            finding.outcome = ControlOutcome.EFFECTIVE
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY
        self.findings.append(finding)
```

3. Register in `e8mate/scanner.py` COLLECTOR_REGISTRY
4. Write tests in `tests/test_collectors/`

## Writing a Nuclei Template

Place templates in `nuclei-templates/e8-{control-name}/`. Follow this structure:

```yaml
id: e8-your-check-name
info:
  name: Essential Eight - Your Check Description
  author: e8mate
  severity: high
  tags: essential-eight,e8,{control},australia,compliance
  metadata:
    e8-control: control_name
    e8-maturity-level: 1
```

## Code Style

- Python 3.10+, type hints everywhere
- Format with `ruff`
- Docstrings on all public functions
- Follow ASD terminology and assessment outcomes exactly

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure `pytest` and `ruff check .` pass
4. Submit a PR with a clear description of what and why

## Code of Conduct

Be respectful, constructive, and collaborative. We're building something to help organisations stay secure — keep that mission in mind.
