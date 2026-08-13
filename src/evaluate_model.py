import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Project directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load dataset
df = pd.read_parquet(os.path.join(base_dir, "dataset", "merged_dataset.parquet"))

# Use a sample
df = df.sample(n=200000, random_state=42)

# Label column
label_column = "Label"

X = df.drop(columns=[label_column])
y = df[label_column]

if y.dtype == "object":
    encoder = LabelEncoder()
    y = encoder.fit_transform(y)
    joblib.dump(
    encoder,
    os.path.join(base_dir, "models", "label_encoder.pkl")
)

    # Save the encoder
    joblib.dump(
        encoder,
        os.path.join(base_dir, "models", "label_encoder.pkl")
    )

X = X.select_dtypes(include=["number"])
X = X.fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Load trained model
model = joblib.load(os.path.join(base_dir, "models", "random_forest_model.pkl"))

# Predictions
y_pred = model.predict(X_test)

# Confusion Matrix
disp = ConfusionMatrixDisplay.from_predictions(y_test, y_pred)
plt.title("Confusion Matrix")
plt.show()