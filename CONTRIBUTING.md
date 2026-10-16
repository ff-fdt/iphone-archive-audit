# Contributing

Use generated media and temporary directories for examples and tests.

- For a format issue, include the extension, expected header and a small synthetic fixture.
- For archive grouping changes, test sidecars, filename collisions and duplicate content separately.
- Preserve source files and keep generated reports outside the source archive.
- Check JSON fields, Markdown output, SHA-256 ordering and exit codes when changing reports.
- Include the command and expected result in bug reports; replace personal paths and filenames with sample names.

Run `python3 -m unittest discover -v` before submitting a pull request.
Try `python3 examples/demo.py` to generate a sample archive and report.
