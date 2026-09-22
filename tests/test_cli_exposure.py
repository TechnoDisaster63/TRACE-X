import cli

def test_new_subcommands_are_exposed(capsys):
    import sys
    for command in ("export-ioc", "feedback", "lifecycle"):
        sys.argv=["cli.py",command,"--help"]
        try: cli.main()
        except SystemExit as exc: assert exc.code == 0
