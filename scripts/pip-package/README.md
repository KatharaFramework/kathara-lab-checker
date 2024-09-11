# Create a Kathara package for PyPI (pip)

## Requirements
Install the `build` package from PyPI:
```bash
python3 -m pip install build
```

## Build the package
1. Change the `kathara-lab-checker` version number in the following files:
    1. `src/main.py` (change `VERSION`).
    2. `pyproject.toml` (change `version`).
2. Run `make all`. This will:
   1. Create a Kathara Python package.
   2. Upload the packet on PyPI.
3. Output files are located in the `dist` directory.