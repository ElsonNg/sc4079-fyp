from cli.main import main


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
