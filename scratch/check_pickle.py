import pickle
import os

file_path = "/Users/kunalrajendrabodke/Work/securegate/llm/SecureGate_Detector_redact_text_v2.pkl"

try:
    with open(file_path, "rb") as f:
        obj = pickle.load(f)
    print(f"Object type: {type(obj)}")
    if hasattr(obj, "__dict__"):
        print(f"Attributes: {list(obj.__dict__.keys())}")
    
    # Check if it's a scikit-learn model
    if hasattr(obj, "predict"):
        print("It has a predict() method.")
    if hasattr(obj, "predict_proba"):
        print("It has a predict_proba() method.")
        
    # Print a string representation
    print(f"Representation: {str(obj)[:200]}")
    
except Exception as e:
    print(f"Error loading pickle: {e}")
