import os
import joblib
import pandas as pd
from scapy.all import sniff

from feature_extractor import extract_features

# Project root directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load trained model
model_path = os.path.join(base_dir, "models", "random_forest_model.pkl")
label_encoder_path = os.path.join(base_dir, "models", "label_encoder.pkl")

model = joblib.load(model_path)
label_encoder = joblib.load(label_encoder_path)

print("✅ Model Loaded Successfully")
print("✅ Label Encoder Loaded Successfully")


from flow_generator import update_flow

def process_packet(packet):

    flow = update_flow(packet)

    if flow is None:
        return

    print("\n" + "=" * 60)
    print("Live Flow")
    print(flow)

    # NOTE:
    # The model was trained on 78 CICIDS features.
    # Right now we only display extracted features.
    # Prediction will be added after we implement
    # flow-based feature extraction.

    # Example of how prediction will work later:
    #
    # df = pd.DataFrame([features])
    # prediction = model.predict(df)
    # attack = label_encoder.inverse_transform(prediction)
    # print("Prediction:", attack[0])


print("\n🚀 Starting Live Detection...")
print("Press Ctrl+C to stop.\n")

sniff(prn=process_packet, store=False)