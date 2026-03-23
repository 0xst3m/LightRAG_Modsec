import os
import unittest
import tempfile
from ingest.parser import (
    parse_crs_file,
    parse_mediawiki_file,
    ingest_all_files,
    _extract_conf_category,
    _extract_mediawiki_topic,
    _extract_section_name,
    SUPPORTED_EXTENSIONS,
)
from validation.validators import lint_sec_rule, test_waf_payload as waf_payload_test


class TestExtractConfCategory(unittest.TestCase):
    """Tests for _extract_conf_category() filename metadata extraction."""

    def test_request_attack_category(self):
        self.assertEqual(
            _extract_conf_category("REQUEST-932-APPLICATION-ATTACK-RCE.conf"),
            "APPLICATION ATTACK RCE",
        )

    def test_response_data_leakages(self):
        self.assertEqual(
            _extract_conf_category("RESPONSE-951-DATA-LEAKAGES-SQL.conf"),
            "DATA LEAKAGES SQL",
        )

    def test_single_word_category(self):
        self.assertEqual(
            _extract_conf_category("REQUEST-901-INITIALIZATION.conf"),
            "INITIALIZATION",
        )

    def test_two_word_category(self):
        self.assertEqual(
            _extract_conf_category("REQUEST-920-PROTOCOL-ENFORCEMENT.conf"),
            "PROTOCOL ENFORCEMENT",
        )

    def test_no_match_returns_stem(self):
        # Files that don't match the pattern return the full stem
        self.assertEqual(
            _extract_conf_category("custom-rules.conf"),
            "custom-rules",
        )

    def test_example_conf_filename(self):
        # .conf.example → stem is "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
        # which then matches the pattern and extracts the category
        self.assertEqual(
            _extract_conf_category("REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example"),
            "EXCLUSION RULES BEFORE CRS.conf",
        )


class TestExtractMediawikiTopic(unittest.TestCase):
    """Tests for _extract_mediawiki_topic() filename topic extraction."""

    def test_variables(self):
        self.assertEqual(
            _extract_mediawiki_topic("Reference-Manual-Variables.mediawiki"),
            "Variables",
        )

    def test_actions(self):
        self.assertEqual(
            _extract_mediawiki_topic("Reference-Manual-Actions.mediawiki"),
            "Actions",
        )

    def test_multi_word_topic(self):
        self.assertEqual(
            _extract_mediawiki_topic("Reference-Manual-Transformation-Functions.mediawiki"),
            "Transformation Functions",
        )

    def test_configuration_directives(self):
        self.assertEqual(
            _extract_mediawiki_topic("Reference-Manual-Configuration-Directives.mediawiki"),
            "Configuration Directives",
        )

    def test_main_reference_manual(self):
        self.assertEqual(
            _extract_mediawiki_topic("Reference-Manual.mediawiki"),
            "ModSecurity Reference Manual",
        )

    def test_faq(self):
        self.assertEqual(
            _extract_mediawiki_topic("ModSecurity-Frequently-Asked-Questions-(FAQ).mediawiki"),
            "Frequently Asked Questions (FAQ)",
        )

    def test_unknown_filename_fallback(self):
        self.assertEqual(
            _extract_mediawiki_topic("some-custom-doc.mediawiki"),
            "some custom doc",
        )


class TestParseCrsFile(unittest.TestCase):
    """Tests for parse_crs_file() — .conf rule parsing."""

    def _write_tmp(self, content, mode='w', suffix='.conf'):
        """Helper to write a temp .conf file and return its path."""
        kwargs = {'delete': False, 'suffix': suffix}
        if mode == 'wb':
            kwargs['mode'] = 'wb'
            f = tempfile.NamedTemporaryFile(**kwargs)
            f.write(content.encode('utf-8'))
        else:
            kwargs['mode'] = 'w'
            f = tempfile.NamedTemporaryFile(**kwargs)
            f.write(content)
        path = f.name
        f.close()
        return path

    def _parse_and_cleanup(self, content, **kwargs):
        path = self._write_tmp(content, **kwargs)
        rules = parse_crs_file(path)
        os.remove(path)
        return rules

    # --- Basic rule parsing ---

    def test_single_rule(self):
        rules = self._parse_and_cleanup(
            'SecRule REQUEST_METHOD "^GET$" "id:1,phase:1,pass"'
        )
        self.assertEqual(len(rules), 1)
        self.assertIn("SecRule REQUEST_METHOD", rules[0])
        self.assertIn("id:1,phase:1,pass", rules[0])

    def test_single_secaction(self):
        rules = self._parse_and_cleanup(
            'SecAction "id:900001,phase:1,pass,nolog"'
        )
        self.assertEqual(len(rules), 1)
        self.assertIn("SecAction", rules[0])

    def test_multiple_standalone_rules(self):
        content = (
            'SecRule ARGS "dirty" "id:1,pass"\n'
            'SecRule ARGS "evil" "id:2,pass"\n'
            'SecAction "id:3,pass"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 3)

    def test_empty_file(self):
        rules = self._parse_and_cleanup("")
        self.assertEqual(len(rules), 0)

    def test_comments_only_file(self):
        rules = self._parse_and_cleanup("# just a comment\n# another one\n")
        self.assertEqual(len(rules), 0)

    # --- Line continuations ---

    def test_line_continuation_lf(self):
        content = 'SecRule ARGS:test \\\n  "@rx payload" \\\n  "id:1,pass"'
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)
        self.assertNotIn("\\\n", rules[0])
        self.assertIn("SecRule ARGS:test", rules[0])
        self.assertIn("@rx payload", rules[0])
        self.assertIn("id:1,pass", rules[0])

    def test_line_continuation_crlf(self):
        content = 'SecRule ARGS:test \\\r\n  "@rx payload" \\\r\n  "id:1,pass"'
        rules = self._parse_and_cleanup(content, mode='wb')
        self.assertEqual(len(rules), 1)
        self.assertNotIn("\\\r\n", rules[0])
        self.assertIn("SecRule ARGS:test", rules[0])

    def test_multiline_rule_with_many_continuations(self):
        """Real-world style rule with many continuation lines."""
        content = (
            'SecRule REQUEST_METHOD "@rx ^GET$" \\\n'
            '    "id:5,\\\n'
            '    phase:1,\\\n'
            '    block,\\\n'
            '    t:none,\\\n'
            '    msg:\'Test\',\\\n'
            '    pass"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)
        self.assertIn("id:5", rules[0])
        self.assertIn("msg:'Test'", rules[0])

    # --- Indented rules ---

    def test_indented_rules_spaces(self):
        content = '   SecRule ARGS "@rx a" "id:1"\n   SecAction "id:2"'
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 2)

    def test_indented_rules_tabs(self):
        content = '\tSecRule ARGS "@rx a" "id:1"\n\tSecAction "id:2"'
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 2)

    # --- Chain grouping ---

    def test_simple_chain_two_rules(self):
        """Parent with chain + child = 1 chunk."""
        content = (
            'SecRule REQUEST_METHOD "@rx ^POST$" "id:2,phase:1,chain,pass"\n'
            '    SecRule ARGS:test "@eq 1" "setvar:tx.foo=1"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)
        self.assertIn("SecRule REQUEST_METHOD", rules[0])
        self.assertIn("SecRule ARGS:test", rules[0])

    def test_chain_three_levels(self):
        """Parent chain → child chain → grandchild = 1 chunk."""
        content = (
            'SecRule REQUEST_METHOD "@rx ^POST$" "id:2,phase:1,chain"\n'
            '    SecRule ARGS:test "@eq 1" "chain"\n'
            '    SecRule ARGS:test2 "@eq 2" "setvar:tx.foo=1"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)
        self.assertIn("SecRule REQUEST_METHOD", rules[0])
        self.assertIn("SecRule ARGS:test", rules[0])
        self.assertIn("SecRule ARGS:test2", rules[0])

    def test_chain_four_levels_with_continuations(self):
        """Real CRS-style 4-level chain with line continuations."""
        content = (
            'SecRule REQUEST_PROTOCOL "!@within HTTP/2" \\\n'
            '    "id:920180,\\\n'
            '    phase:1,\\\n'
            '    chain"\n'
            '    SecRule REQUEST_METHOD "@streq POST" \\\n'
            '        "chain"\n'
            '        SecRule &REQUEST_HEADERS:Content-Length "@eq 0" \\\n'
            '            "chain"\n'
            '            SecRule &REQUEST_HEADERS:Transfer-Encoding "@eq 0" \\\n'
            '                "setvar:\'tx.inbound_anomaly_score_pl1=+1\'"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)
        self.assertIn("REQUEST_PROTOCOL", rules[0])
        self.assertIn("Transfer-Encoding", rules[0])

    def test_chain_followed_by_standalone(self):
        """A chain rule followed by a standalone rule = 2 chunks."""
        content = (
            'SecRule ARGS "a" "id:1,chain"\n'
            '    SecRule ARGS "b" "pass"\n'
            'SecRule ARGS "c" "id:2,pass"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 2)

    def test_two_chains_back_to_back(self):
        """Two separate chain rules = 2 chunks."""
        content = (
            'SecRule ARGS "a" "id:1,chain"\n'
            '    SecRule ARGS "b" "pass"\n'
            'SecRule ARGS "c" "id:2,chain"\n'
            '    SecRule ARGS "d" "deny"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 2)

    def test_chain_keyword_in_quoted_action(self):
        """chain keyword at end of quoted action string: ...chain" """
        content = (
            'SecRule REQUEST_METHOD "@rx ^GET$" \\\n'
            '    "id:920170,\\\n'
            '    severity:\'CRITICAL\',\\\n'
            '    chain"\n'
            '    SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" \\\n'
            '        "t:none,\\\n'
            '        setvar:\'tx.score=+1\'"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)

    def test_malformed_chain_at_eof(self):
        """Chain keyword but no child rule (malformed) — still returns 1 chunk."""
        content = 'SecRule REQUEST_METHOD "^GET$" "id:6,phase:1,chain"\n'
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 1)
        self.assertIn("chain", rules[0])

    # --- Source and category metadata ---

    def test_source_prefix_present(self):
        content = 'SecRule ARGS "dirty" "id:1,pass"'
        path = self._write_tmp(content)
        rules = parse_crs_file(path)
        os.remove(path)
        self.assertTrue(rules[0].startswith("[Source:"))

    def test_category_in_prefix(self):
        """When file is named like a CRS rule file, category appears in prefix."""
        content = 'SecRule ARGS "dirty" "id:1,pass"'
        # Write to a file with a CRS-style name
        tmp_dir = tempfile.mkdtemp()
        filepath = os.path.join(tmp_dir, "REQUEST-941-APPLICATION-ATTACK-XSS.conf")
        with open(filepath, 'w') as f:
            f.write(content)
        rules = parse_crs_file(filepath)
        os.remove(filepath)
        os.rmdir(tmp_dir)
        self.assertIn("Category: APPLICATION ATTACK XSS", rules[0])

    # --- Encoding fallback ---

    def test_latin1_encoding_fallback(self):
        """File with Latin-1 characters should not crash."""
        content_bytes = b'SecRule ARGS "\xe9vil" "id:1,pass"'
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.conf', mode='wb')
        tmp.write(content_bytes)
        tmp.close()
        rules = parse_crs_file(tmp.name)
        os.remove(tmp.name)
        self.assertEqual(len(rules), 1)

    # --- Comments between rules ---

    def test_comments_between_rules_ignored(self):
        content = (
            '# Comment before rule\n'
            'SecRule ARGS "a" "id:1,pass"\n'
            '\n'
            '# Comment between rules\n'
            'SecRule ARGS "b" "id:2,pass"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 2)

    # --- Real-world CRS pattern ---

    def test_real_world_paranoia_skip_rules(self):
        """Paranoia level skip rules (single-line, no continuation)."""
        content = (
            'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" '
            '"id:920011,phase:1,pass,nolog,tag:\'OWASP_CRS\','
            'ver:\'OWASP_CRS/4.25.0-dev\','
            'skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"\n'
            'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" '
            '"id:920012,phase:2,pass,nolog,tag:\'OWASP_CRS\','
            'ver:\'OWASP_CRS/4.25.0-dev\','
            'skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"\n'
        )
        rules = self._parse_and_cleanup(content)
        self.assertEqual(len(rules), 2)


class TestParseMediawikiFile(unittest.TestCase):
    """Tests for parse_mediawiki_file()."""

    def test_basic_mediawiki(self):
        content = "= Title =\nSome documentation text."
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.mediawiki', mode='w'
        )
        tmp.write(content)
        tmp.close()
        chunks = parse_mediawiki_file(tmp.name)
        os.remove(tmp.name)
        self.assertEqual(len(chunks), 1)
        self.assertIn("[Source:", chunks[0])
        self.assertIn("| Topic:", chunks[0])
        self.assertIn("= Title =", chunks[0])
        self.assertIn("Some documentation text.", chunks[0])

    def test_empty_mediawiki(self):
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.mediawiki', mode='w'
        )
        tmp.write("")
        tmp.close()
        chunks = parse_mediawiki_file(tmp.name)
        os.remove(tmp.name)
        self.assertEqual(len(chunks), 0)

    def test_whitespace_only_mediawiki(self):
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.mediawiki', mode='w'
        )
        tmp.write("   \n\n  \t  ")
        tmp.close()
        chunks = parse_mediawiki_file(tmp.name)
        os.remove(tmp.name)
        self.assertEqual(len(chunks), 0)

    def test_latin1_mediawiki(self):
        content_bytes = b"= R\xe9f\xe9rence =\nContenu."
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.mediawiki', mode='wb'
        )
        tmp.write(content_bytes)
        tmp.close()
        chunks = parse_mediawiki_file(tmp.name)
        os.remove(tmp.name)
        self.assertEqual(len(chunks), 1)


class TestExtractSectionName(unittest.TestCase):
    """Tests for _extract_section_name() heading cleanup."""

    def test_level2_heading(self):
        self.assertEqual(_extract_section_name("== ARGS =="), "ARGS")

    def test_level3_heading(self):
        self.assertEqual(_extract_section_name("=== Commercial Help ==="), "Commercial Help")

    def test_trailing_space(self):
        self.assertEqual(_extract_section_name("== allow == "), "allow")

    def test_mixed_whitespace(self):
        self.assertEqual(_extract_section_name("==  ARGS  =="), "ARGS")


class TestMediawikiSectionSplitting(unittest.TestCase):
    """Tests for parse_mediawiki_file() section-based splitting."""

    def _write_wiki(self, content):
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.mediawiki', mode='w'
        )
        tmp.write(content)
        tmp.close()
        return tmp.name

    def _parse_and_cleanup(self, content):
        path = self._write_wiki(content)
        chunks = parse_mediawiki_file(path)
        os.remove(path)
        return chunks

    def test_multiple_sections_split(self):
        content = (
            "= Title =\n"
            "This is a sufficiently long preamble for the test to include it as a chunk.\n\n"
            "== Section One ==\n"
            "Content of section one.\n\n"
            "== Section Two ==\n"
            "Content of section two.\n"
        )
        chunks = self._parse_and_cleanup(content)
        # 1 preamble + 2 sections = 3 chunks
        self.assertEqual(len(chunks), 3)

    def test_each_section_has_metadata(self):
        content = (
            "= Title =\n"
            "This is a sufficiently long intro paragraph for the test to work correctly.\n\n"
            "== ARGS ==\nARGS is a collection.\n\n"
            "== ENV ==\nEnvironment variables.\n"
        )
        chunks = self._parse_and_cleanup(content)
        self.assertEqual(len(chunks), 3)
        # Check that section chunks have Section: metadata
        self.assertIn("Section: ARGS", chunks[1])
        self.assertIn("Section: ENV", chunks[2])

    def test_preamble_has_topic_only(self):
        content = (
            "= Title =\n"
            "This is a sufficiently long intro paragraph for the preamble test.\n\n"
            "== First ==\nContent.\n"
        )
        chunks = self._parse_and_cleanup(content)
        preamble = chunks[0]
        self.assertIn("| Topic:", preamble)
        self.assertNotIn("Section:", preamble)

    def test_no_sections_returns_single_chunk(self):
        """File with no == headings returns 1 chunk (whole file)."""
        content = "= Title =\nJust a title and some text.\n=== Subsection ===\nMore text."
        chunks = self._parse_and_cleanup(content)
        self.assertEqual(len(chunks), 1)

    def test_section_content_preserved(self):
        content = (
            "= Title =\nPreamble.\n\n"
            "== Variables ==\n"
            "ARGS is a collection.\n"
            "<code>SecRule ARGS dirty \"id:7\"</code>\n\n"
            "== Operators ==\n"
            "beginsWith checks prefix.\n"
        )
        chunks = self._parse_and_cleanup(content)
        variables_chunk = [c for c in chunks if "Section: Variables" in c][0]
        self.assertIn("ARGS is a collection", variables_chunk)
        self.assertIn("SecRule ARGS dirty", variables_chunk)

    def test_subsections_stay_with_parent(self):
        """=== Level 3 headings stay inside their parent == section."""
        content = (
            "= Title =\n"
            "This is a sufficiently long preamble paragraph for the subsection test.\n\n"
            "== Main Section ==\n"
            "Main content.\n"
            "=== Sub Section ===\n"
            "Sub content.\n\n"
            "== Next Section ==\n"
            "Next content.\n"
        )
        chunks = self._parse_and_cleanup(content)
        # preamble + Main Section (with sub) + Next Section = 3
        self.assertEqual(len(chunks), 3)
        main_chunk = [c for c in chunks if "Section: Main Section" in c][0]
        self.assertIn("Sub Section", main_chunk)
        self.assertIn("Sub content", main_chunk)

    def test_trailing_space_in_heading(self):
        """Headings like '== allow == ' have trailing space stripped."""
        content = (
            "= Title =\nPreamble.\n\n"
            "== allow == \n"
            "Allow content.\n"
        )
        chunks = self._parse_and_cleanup(content)
        section_chunk = [c for c in chunks if "Section:" in c][0]
        self.assertIn("Section: allow", section_chunk)
        self.assertNotIn("==", section_chunk.split('\n')[0].split("Section:")[1])

    def test_small_preamble_skipped(self):
        """Preamble under 50 chars is skipped."""
        content = (
            "= T =\n\n"  # very short preamble
            "== Section ==\n"
            "Content here.\n"
        )
        chunks = self._parse_and_cleanup(content)
        # Only the section, no preamble (it's too short)
        self.assertEqual(len(chunks), 1)
        self.assertIn("Section: Section", chunks[0])

    def test_real_world_variables_pattern(self):
        """Simulates Reference-Manual-Variables.mediawiki structure."""
        content = (
            "= ModSecurity Reference Manual =\n"
            "== Current as of v2.6 ==\n"
            "=== Copyright ===\n\n"
            "= Variables =\n"
            "The following variables are supported:\n\n"
            "== ARGS ==\n"
            "ARGS is a collection and can be used on its own.\n"
            "<code>SecRule ARGS dirty \"id:7\"</code>\n\n"
            "== ARGS_COMBINED_SIZE ==\n"
            "Contains the combined size of all request parameters.\n\n"
            "== ENV ==\n"
            "Collection for environment variables.\n"
            "<pre>SecRule ENV:tag \"suspicious\" \"id:16\"</pre>\n"
        )
        chunks = self._parse_and_cleanup(content)
        # Preamble with Current/Copyright + 3 sections (ARGS, ARGS_COMBINED_SIZE, ENV)
        # The "= Variables =" level-1 heading is part of the preamble before first ==
        section_names = []
        for c in chunks:
            prefix = c.split('\n')[0]
            if 'Section:' in prefix:
                name = prefix.split('Section: ')[1].rstrip(']')
                section_names.append(name)

        self.assertIn("ARGS", section_names)
        self.assertIn("ARGS_COMBINED_SIZE", section_names)
        self.assertIn("ENV", section_names)


class TestIngestAllFiles(unittest.TestCase):
    """Tests for ingest_all_files() unified ingestion."""

    def test_empty_list(self):
        self.assertEqual(ingest_all_files([]), [])

    def test_conf_and_mediawiki_mixed(self):
        """Ingesting both .conf and .mediawiki files."""
        tmp_dir = tempfile.mkdtemp()

        conf_path = os.path.join(tmp_dir, "REQUEST-941-APPLICATION-ATTACK-XSS.conf")
        with open(conf_path, 'w') as f:
            f.write('SecRule ARGS "xss" "id:941001,pass"')

        wiki_path = os.path.join(tmp_dir, "Reference-Manual-Variables.mediawiki")
        with open(wiki_path, 'w') as f:
            f.write("= Variables =\nARGS is a collection.")

        chunks = ingest_all_files([conf_path, wiki_path])

        os.remove(conf_path)
        os.remove(wiki_path)
        os.rmdir(tmp_dir)

        self.assertEqual(len(chunks), 2)
        # Check conf chunk has category
        conf_chunk = [c for c in chunks if "APPLICATION ATTACK XSS" in c]
        self.assertEqual(len(conf_chunk), 1)
        # Check mediawiki chunk
        wiki_chunk = [c for c in chunks if "Variables" in c]
        self.assertEqual(len(wiki_chunk), 1)

    def test_unsupported_extension_skipped(self):
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.txt', mode='w'
        )
        tmp.write("some text")
        tmp.close()

        chunks = ingest_all_files([tmp.name])
        os.remove(tmp.name)
        self.assertEqual(len(chunks), 0)

    def test_crs_setup_processed_first(self):
        """crs-setup.conf should be processed before other .conf files."""
        tmp_dir = tempfile.mkdtemp()

        regular = os.path.join(tmp_dir, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
        with open(regular, 'w') as f:
            f.write('SecRule ARGS "a" "id:1,pass"')

        setup = os.path.join(tmp_dir, "crs-setup.conf")
        with open(setup, 'w') as f:
            f.write('SecAction "id:900000,pass"')

        # Pass setup AFTER regular — it should still be first in output
        chunks = ingest_all_files([regular, setup])

        os.remove(regular)
        os.remove(setup)
        os.rmdir(tmp_dir)

        self.assertEqual(len(chunks), 2)
        # First chunk should be from crs-setup.conf
        self.assertIn("crs-setup.conf", chunks[0])

    def test_nonexistent_file_handled_gracefully(self):
        """A bad path should not crash the entire ingestion."""
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix='.conf', mode='w'
        )
        tmp.write('SecRule ARGS "x" "id:1,pass"')
        tmp.close()

        chunks = ingest_all_files(["/nonexistent/path.conf", tmp.name])
        os.remove(tmp.name)
        # Should still get the one valid file's chunk
        self.assertEqual(len(chunks), 1)


class TestSupportedExtensions(unittest.TestCase):
    """Tests for SUPPORTED_EXTENSIONS constant."""

    def test_only_conf_and_mediawiki(self):
        self.assertEqual(SUPPORTED_EXTENSIONS, {'.conf', '.mediawiki'})

    def test_no_pdf(self):
        self.assertNotIn('.pdf', SUPPORTED_EXTENSIONS)

    def test_no_txt(self):
        self.assertNotIn('.txt', SUPPORTED_EXTENSIONS)


class TestValidators(unittest.TestCase):
    """Tests for validation module (graceful failure when binaries missing)."""

    def test_lint_missing_binary_graceful(self):
        valid, msg = lint_sec_rule("SecRule ARGS '@rx ^.*$' 'id:123,pass'")
        self.assertIsInstance(valid, bool)
        self.assertIsInstance(msg, str)
        self.assertTrue(len(msg) > 0)
        if "not found" in msg.lower() or "not recognized" in msg.lower():
            self.assertFalse(valid)

    def test_waf_payload_missing_binary_graceful(self):
        valid, msg = waf_payload_test("SecRule", "dummy.yaml")
        self.assertIsInstance(valid, bool)
        self.assertIsInstance(msg, str)
        self.assertTrue(len(msg) > 0)
        if "not found" in msg.lower() or "not recognized" in msg.lower():
            self.assertFalse(valid)


class TestSkipIfIndexed(unittest.TestCase):
    """Tests for skip-if-indexed logic in pipeline."""

    def test_compute_chunks_hash_deterministic(self):
        from pipeline import _compute_chunks_hash
        chunks = ["chunk1", "chunk2", "chunk3"]
        h1 = _compute_chunks_hash(chunks)
        h2 = _compute_chunks_hash(chunks)
        self.assertEqual(h1, h2)

    def test_compute_chunks_hash_changes_with_content(self):
        from pipeline import _compute_chunks_hash
        h1 = _compute_chunks_hash(["a", "b"])
        h2 = _compute_chunks_hash(["a", "c"])
        self.assertNotEqual(h1, h2)

    def test_compute_chunks_hash_changes_with_order(self):
        from pipeline import _compute_chunks_hash
        h1 = _compute_chunks_hash(["a", "b"])
        h2 = _compute_chunks_hash(["b", "a"])
        self.assertNotEqual(h1, h2)

    def test_should_skip_no_manifest(self):
        from pipeline import _should_skip_indexing
        # No manifest file exists → should NOT skip
        self.assertFalse(_should_skip_indexing(["chunk"]))

    def test_should_skip_round_trip(self):
        import json
        from pipeline import _should_skip_indexing, _save_index_manifest, _compute_chunks_hash
        chunks = ["test chunk 1", "test chunk 2"]

        # Create a temp manifest
        tmp_dir = tempfile.mkdtemp()
        manifest_path = os.path.join(tmp_dir, "ingest_manifest.json")

        # Save manifest
        manifest = {
            "chunks_hash": _compute_chunks_hash(chunks),
            "chunks_count": len(chunks),
        }
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f)

        # Monkey-patch INDEX_MANIFEST for this test
        import pipeline
        original = pipeline.INDEX_MANIFEST
        try:
            from pathlib import Path
            pipeline.INDEX_MANIFEST = Path(manifest_path)
            self.assertTrue(_should_skip_indexing(chunks))
            self.assertFalse(_should_skip_indexing(["different chunk"]))
        finally:
            pipeline.INDEX_MANIFEST = original
            os.remove(manifest_path)
            os.rmdir(tmp_dir)


class TestQueryParam(unittest.TestCase):
    """Verify LightRAG QueryParam construction."""

    def test_hybrid_context_only(self):
        from lightrag.base import QueryParam
        qp = QueryParam(mode="hybrid", only_need_context=True)
        self.assertEqual(qp.mode, "hybrid")
        self.assertTrue(qp.only_need_context)


if __name__ == '__main__':
    unittest.main()
