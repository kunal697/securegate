import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))

import os
os.environ["SECUREGATE_SPACY_MODEL"] = "en_core_web_sm"
os.environ["SECUREGATE_LITE_MODE"] = "false"

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from securegate.pipeline import Pipeline
from securegate.models import AnalysisRequest, Action, SensitivityCategory

async def test_accuracy():
    pipeline = Pipeline()
    
    test_prompts = [
        # 1. Aadhaar
        ("Hi, my name is Kunal, born on 14/08/1992, and my Aadhaar number is 1234 5678 9012. Please update my profile address to Mumbai.", 
         [Action.MASK, Action.BLOCK], [SensitivityCategory.PERSONAL_INFO]),
        
        # 2. Bank transfer + IFSC
        ("Transfer ₹45,000 from account 9876543210 to ICICI account 1122334455 using IFSC ICIC0001234 before Friday.",
         [Action.MASK, Action.BLOCK], [SensitivityCategory.FINANCIAL_DATA]),
        
        # 3. Card + CVV
        ("My card number is 4111111111111111, expiry 09/29, CVV 482. Please process the payment immediately.",
         [Action.BLOCK], [SensitivityCategory.FINANCIAL_DATA]),
        
        # 4. Health
        ("Patient Kunal diagnosed with Type 2 Diabetes and hypertension. Prescription includes Metformin 500mg twice daily",
         [Action.BLOCK], [SensitivityCategory.HEALTH_INFO]),
        
        # 5. Acquisition (Business Secret)
        ("The acquisition agreement between Orion Tech Pvt Ltd and Nova Systems is valued at ₹42 crore and remains undisclosed until June 2026",
         [Action.BLOCK], [SensitivityCategory.SECRET_BUSINESS]),
        
        # 6. PAN / GSTIN
        ("PAN: BGTPS4432K GSTIN: 27BGTPS4432K1ZV. Annual declared revenue for FY2025: ₹2.4 crore.",
         [Action.BLOCK, Action.MASK], [SensitivityCategory.FINANCIAL_DATA, SensitivityCategory.SECRET_BUSINESS]),
        
        # 7. Project Falcon (Business Secret)
        ("Project Falcon will launch in Q3 with a planned 22% workforce restructuring across regional offices",
         [Action.BLOCK], [SensitivityCategory.SECRET_BUSINESS]),
    ]

    print("\n--- Starting Accuracy Verification ---\n")
    
    for i, (text, expected_actions, expected_cats) in enumerate(test_prompts, 1):
        req = AnalysisRequest(text=text)
        res = await pipeline.analyze(req)
        
        passed = res.action in expected_actions and res.category in expected_cats
            
        status = "PASSED" if passed else "FAILED"
        print(f"Test {i}: {status}")
        print(f"  Input: {text[:60]}...")
        print(f"  Detected Category: {res.category}")
        print(f"  Resulting Action: {res.action}")
        print(f"  Reasoning: {res.reasoning}\n")

if __name__ == "__main__":
    asyncio.run(test_accuracy())
