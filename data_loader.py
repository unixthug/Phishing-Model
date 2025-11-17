import pandas as pd
import os

def load_url_file(filepath: str):
    """
    Automatically detects CSV or XLSX files and loads them.
    Returns a pandas DataFrame.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = filepath.lower().split(".")[-1]

    if ext == "csv":
        print("📄 Detected CSV file")
        return pd.read_csv(filepath)

    elif ext in ["xlsx", "xls"]:
        print("📊 Detected Excel file")
        return pd.read_excel(filepath, engine="openpyxl")

    else:
        raise ValueError(f"Unsupported file type '.{ext}'. Use CSV or XLSX.")
