import pytest

from cli.main import build_parser, main


def test_cli_corpus_stats_reports_empty_custom_database(tmp_path, capsys):
    database = tmp_path / "corpus.db"

    assert main(["corpus", "stats", "--db-path", str(database)]) == 0

    output = capsys.readouterr().out
    assert "Corpus entries: 0" in output
    assert "Corpus version:" in output


def test_cli_help_is_available(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    assert "Detect JavaScript vulnerability clones" in capsys.readouterr().out


def test_scan_explanation_defaults_are_explicit_and_local():
    args = build_parser().parse_args(["scan", "/tmp/project", "--explain-review"])

    assert args.explain_review is True
    assert args.ollama_model == "qwen3:8b"
    assert args.ollama_host == "http://127.0.0.1:11434"
    assert args.ollama_timeout == 180


def test_corpus_index_accepts_explicit_embedding_device():
    args = build_parser().parse_args(["corpus", "index", "--device", "cpu"])
    assert args.device == "cpu"


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf"])
def test_scan_rejects_invalid_ollama_timeout(timeout):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "/tmp/project", "--ollama-timeout", timeout])
