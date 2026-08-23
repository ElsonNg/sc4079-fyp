from scripts.validate_tier1_releases import _present_target_files


def test_tier1_requires_original_source_path(tmp_path):
    package = tmp_path / "package"
    (package / "packages" / "demo").mkdir(parents=True)
    (package / "packages" / "demo" / "index.ts").write_text("export const x: number = 1;\n")

    assert _present_target_files(
        tmp_path,
        {"packages/demo/index.ts"},
    ) == {"packages/demo/index.ts"}


def test_tier1_does_not_treat_compiled_javascript_as_typescript_source(tmp_path):
    package = tmp_path / "package"
    (package / "dist").mkdir(parents=True)
    (package / "dist" / "index.js").write_text("export const x = 1;\n")

    assert _present_target_files(tmp_path, {"packages/demo/index.ts"}) == set()
