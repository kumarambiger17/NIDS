import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Project root directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load merged dataset
file_path = os.path.join(base_dir, "dataset", "merged_dataset.parquet")
df = pd.read_parquet(file_path)

# Use a sample for faster training
df = df.sample(n=200000, random_state=42)

print("Dataset Shape:", df.shape)

# Label column
label_column = "Label"

# Features and labels
X = df.drop(columns=[label_column])
y = df[label_column]

# Encode labels
encoder = LabelEncoder()
y = encoder.fit_transform(y)

# Save label encoder
joblib.dump(
    encoder,
    os.path.join(base_dir, "models", "label_encoder.pkl")
)

# Keep only numeric columns
X = X.select_dtypes(include=["number"])
X = X.fillna(0)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=30,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Accuracy
print("\nAccuracy:", accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(
    model,
    os.path.join(base_dir, "models", "random_forest_model.pkl")
)

print("\n✅ Model saved successfully!")
print("✅ Label encoder saved successfully!")