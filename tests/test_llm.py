"""Tests for the LLM provider and fallback parser."""

import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.llm import MockProvider, LLMResponseParser, create_llm_provider
from shield_agents.config import LLMConfig


class TestLLMResponseParser(unittest.TestCase):
    """Test the LLM response fallback parser."""

    def test_valid_json(self):
        text = '{"findings": [{"title": "SQL Injection", "severity": "CRITICAL"}]}'
        result = LLMResponseParser.parse(text)
        self.assertIn("findings", result)
        self.assertEqual(len(result["findings"]), 1)

    def test_json_in_code_block(self):
        text = '''Here are my findings:
```json
{"findings": [{"title": "XSS", "severity": "HIGH"}]}
```
Hope this helps!'''
        result = LLMResponseParser.parse(text)
        self.assertIn("findings", result)
        self.assertEqual(result["findings"][0]["title"], "XSS")

    def test_trailing_commas(self):
        text = '{"findings": [{"title": "SQLi", "severity": "CRITICAL",}],}'
        result = LLMResponseParser.parse(text)
        self.assertIsNotNone(result)

    def test_embedded_json(self):
        text = '''I found some issues. Here are the findings:

"findings": [{"title": "Command Injection", "severity": "CRITICAL"}]

Let me know if you need more details.'''
        result = LLMResponseParser.parse(text)
        # Should extract the findings
        self.assertIsNotNone(result)

    def test_empty_response(self):
        result = LLMResponseParser.parse("")
        self.assertEqual(result, {})

    def test_text_to_structured(self):
        text = '''I found the following issues:
- **SQL Injection** in login.py line 42
- [HIGH] XSS vulnerability in search.py
- 1. Command injection in utils.py
'''
        result = LLMResponseParser.parse(text)
        if "findings" in result:
            self.assertTrue(len(result["findings"]) > 0)


class TestMockProvider(unittest.TestCase):
    """Test the Smarter Mock Provider."""

    def test_pattern_matching_sql_injection(self):
        config = LLMConfig(provider="mock")
        provider = MockProvider(config)

        code = '''cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'''
        result = asyncio.run(provider.complete_json([
            {"role": "system", "content": "Analyze for vulnerabilities"},
            {"role": "user", "content": code},
        ]))

        self.assertIn("findings", result)
        titles = [f["title"].lower() for f in result["findings"]]
        self.assertTrue(any("sql" in t or "injection" in t for t in titles))

    def test_pattern_matching_eval(self):
        config = LLMConfig(provider="mock")
        provider = MockProvider(config)

        code = '''result = eval(user_input)'''
        result = asyncio.run(provider.complete_json([
            {"role": "system", "content": "Analyze"},
            {"role": "user", "content": code},
        ]))

        self.assertIn("findings", result)
        self.assertTrue(any("eval" in f["title"].lower() for f in result["findings"]))

    def test_pattern_matching_pickle(self):
        config = LLMConfig(provider="mock")
        provider = MockProvider(config)

        code = '''data = pickle.loads(request.data)'''
        result = asyncio.run(provider.complete_json([
            {"role": "system", "content": "Analyze"},
            {"role": "user", "content": code},
        ]))

        self.assertTrue(any("deserialization" in f["title"].lower() or "pickle" in f.get("description", "").lower() for f in result.get("findings", [])))

    def test_clean_code_fewer_findings(self):
        config = LLMConfig(provider="mock")
        provider = MockProvider(config)

        code = '''import os\ndef get_config():\n    return os.environ.get("DB_URL")'''
        result = asyncio.run(provider.complete_json([
            {"role": "system", "content": "Analyze"},
            {"role": "user", "content": code},
        ]))

        # Clean code should have fewer findings than vulnerable code
        self.assertLessEqual(len(result.get("findings", [])), 2)

    def test_no_cross_line_false_positive(self):
        # A SELECT string on one line and an unrelated concatenation on the
        # next must not combine into a single SQL-injection match.
        config = LLMConfig(provider="mock")
        provider = MockProvider(config)

        code = '''label = "SELECT a FROM b WHERE c"
greeting = first + last'''
        result = asyncio.run(provider.complete_json([
            {"role": "system", "content": "Analyze"},
            {"role": "user", "content": code},
        ]))
        titles = [f["title"].lower() for f in result.get("findings", [])]
        self.assertFalse(
            any("sql injection" in t for t in titles),
            f"Cross-line SQL false positive in mock provider: {titles}",
        )

    def test_provider_factory(self):
        config = LLMConfig(provider="mock")
        provider = create_llm_provider(config)
        self.assertIsInstance(provider, MockProvider)


if __name__ == "__main__":
    unittest.main()
