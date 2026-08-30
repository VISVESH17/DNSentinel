"""
Convenience wrapper to (re)train the DGA classifier from the project root.

Run with: python scripts/train_model.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.ml.train import train

if __name__ == "__main__":
    train()
