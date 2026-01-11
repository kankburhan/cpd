# Contributing to CPD-SEC

First off, thanks for taking the time to contribute! 🎉

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find that you don't need to create one.

When creating a bug report, include:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide the output of `cpd-sec --version`**
- **Include the full command you ran**
- **Attach any relevant logs or screenshots**

Example:
```bash
cpd-sec scan --url https://example.com -v > debug.log 2>&1
```

### Reporting False Positives

If CPD-SEC reports a vulnerability that is benign:

1. Run the validation command:
```bash
   cpd-sec validate --url  --header "X-Forwarded-Host: evil.com"
```

2. Open an issue with:
   - The validation output
   - Why you believe it's a false positive
   - Details about the target (framework, CDN, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Create an issue with:

- **Clear title and description**
- **Explain why this enhancement would be useful**
- **List examples of other tools that have this feature** (if applicable)

### Adding New Signatures

To add a new cache poisoning signature:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/new-signature`)
3. Add your signature to `cpd/logic/poison.py`:
```python
   {"name": "My-New-Header", "header": "X-Custom-Header", "value": f"poison-{self.payload_id}"}
```
4. Add tests in `tests/test_poison_custom.py`
5. Submit a pull request with:
   - Description of the signature
   - Link to research/CVE/disclosure (if applicable)
   - Test coverage

### Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update tests to cover your changes
3. Ensure `pytest` passes:
```bash
   poetry run pytest
```
4. Format your code:
```bash
   poetry run black cpd/
   poetry run isort cpd/
```
5. The PR will be merged once approved by maintainers

## Development Setup
```bash
# Clone the repository
git clone https://github.com/kankburhan/cpd.git
cd cpd

# Install dependencies
poetry install

# Run tests
poetry run pytest

# Run linters
poetry run black cpd/
poetry run isort cpd/
poetry run mypy cpd/
```

## Code Style

- Follow PEP 8
- Use type hints where possible
- Add docstrings to public functions
- Keep functions focused and small
- Use descriptive variable names

## Testing Guidelines

- Write tests for all new features
- Maintain or improve code coverage
- Test both success and failure cases
- Use meaningful test names

Example:
```python
@pytest.mark.asyncio
async def test_my_feature_with_valid_input():
    """Test that my feature works with valid input"""
    # Test implementation
```

## Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests

Examples:
- `Add support for CloudFlare cache detection`
- `Fix false positive in method override detection (#123)`
- `Improve performance of baseline analysis`

## Questions?

Feel free to open an issue with the `question` label.
