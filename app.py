"""
Project Keystone — Top-Level Streamlit Entry Point
Allows running `streamlit run app.py` directly from the project root.
"""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Forward directly into the mortgage agent streamlit application
from mortgageagent import streamlit_app

