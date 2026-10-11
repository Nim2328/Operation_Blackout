#!/usr/bin/env bash
set -euo pipefail

PROJECT="$HOME/Projects/operation_blackout"
OUT="$PROJECT/submission_package"
ZIP="$HOME/IT24100947_IT24100995_IT24102340_IT24101128.zip"

cd "$PROJECT"

# Preserve the original project and database.
rm -rf "$OUT"
mkdir -p "$OUT/source" "$OUT/solver_scripts" "$OUT/testing_evidence"

# Copy the project while excluding temporary and local environment files.
tar \
  --exclude='./submission_package' \
  --exclude='./.git' \
  --exclude='./venv' \
  --exclude='./.venv' \
  --exclude='./env' \
  --exclude='./__pycache__' \
  --exclude='*.pyc' \
  --exclude='./.pytest_cache' \
  --exclude='./node_modules' \
  -cf - . | tar -xf - -C "$OUT/source"

# Collect existing solver scripts without inventing missing ones.
find "$PROJECT" \
  -path "$PROJECT/submission_package" -prune -o \
  -path "$PROJECT/venv" -prune -o \
  -path "$PROJECT/.venv" -prune -o \
  -type f \( -iname '*solver*.py' -o -iname '*solver*.sh' -o -iname '*solve*.py' -o -iname '*solve*.sh' \) \
  -print | while IFS= read -r file; do
    rel="${file#"$PROJECT"/}"
    mkdir -p "$OUT/solver_scripts/$(dirname "$rel")"
    cp -p "$file" "$OUT/solver_scripts/$rel"
  done

# Write the submission README.
cat > "$OUT/README.md" <<'README'
# Operation Blackout — IE3132 Assignment 02

## Project overview
Operation Blackout is a cybersecurity CTF Play Box for controlled,
educational investigation. The source folder contains the project files
collected from the existing implementation.

## Contents
- `source/` — project source, templates, evidence, configuration and
  existing database files that were present.
- `solver_scripts/` — existing files matching solver/solve script names.
- `testing_evidence/` — place genuine test logs, validation results and
  contribution evidence here.

## Requirements
Python 3 and the dependencies required by the project are needed.
Install dependencies using the existing `requirements.txt` if present.

## Setup
1. Extract this package.
2. Open a terminal in the `source/` directory.
3. Review the project configuration and README files.
4. Install dependencies in a virtual environment, for example:

   `python3 -m venv .venv`

   `source .venv/bin/activate`

   `pip install -r requirements.txt`

5. Start the application using the project's actual entry point.
   If `app.py` is the entry point, run:

   `python3 app.py`

6. Use the host and port configured by the application.

## Database and recovery
Back up the database before testing recovery procedures. Do not delete or
overwrite the supplied database unless a verified reset procedure requires
it. Follow any project-specific database initialization instructions.

## Solver scripts
Only scripts found in the existing project are copied into
`solver_scripts/`. Check each script's own usage and dependencies before
running it.

## Testing and evidence
Add actual test results, flag-validation evidence, progression checks,
reset/recovery results and member contribution records to
`testing_evidence/`. Do not treat this folder as proof that tests passed.

## Video
The final demonstration video must be no longer than 20 minutes.
Add the final permitted video as a separate submission item or include it
in the package when ready.

## Safety
Use the CTF only in the authorised, isolated lab environment.
README

# Include an existing dependency file at the package root when available.
if [ -f "$PROJECT/requirements.txt" ]; then
    cp -p "$PROJECT/requirements.txt" "$OUT/requirements.txt"
fi

# Create the ZIP without overwriting the original project.
rm -f "$ZIP"
cd "$PROJECT"
zip -qr "$ZIP" submission_package

echo
echo "Package created: $ZIP"
echo "Review contents:"
unzip -l "$ZIP" | tail -n 25
