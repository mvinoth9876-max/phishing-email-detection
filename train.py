
import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

DATASET_PATH = "dataset/emails.csv"
MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)

print("=" * 55)
print("       PHISHING EMAIL DETECTION - MODEL TRAINING")
print("=" * 55)

# Load dataset
df = pd.read_csv(DATASET_PATH)

# Separate features and target
X = df.drop(columns=["Prediction", "Email No."], errors="ignore")
y = df["Prediction"]

print("\nDataset loaded successfully!")
print("Total emails:", len(df))
print("Total features:", X.shape[1])

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# Models
models = {
    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ),
    "Naive Bayes": MultinomialNB()
}

best_model = None
best_accuracy = 0
best_model_name = ""

# Train and evaluate
for name, model in models.items():

    print("\n" + "=" * 55)
    print("Training:", name)
    print("=" * 55)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print("Accuracy:", round(accuracy * 100, 2), "%")

    print("\nClassification Report:")
    print(classification_report(y_test, predictions))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model
        best_model_name = name

# Save best model
model_path = os.path.join(MODEL_DIR, "best_model.pkl")

joblib.dump(best_model, model_path)

# Save feature names for prediction consistency
feature_path = os.path.join(MODEL_DIR, "feature_names.pkl")
joblib.dump(X.columns.tolist(), feature_path)

print("\n" + "=" * 55)
print("             TRAINING COMPLETED")
print("=" * 55)

print("Best Model:", best_model_name)
print("Best Accuracy:", round(best_accuracy * 100, 2), "%")
print("Model saved:", model_path)
print("Features saved:", feature_path)

print("\nIMPORTANT:")
print("Verify whether label 1 means phishing/spam")
print("and label 0 means legitimate email before")
print("using these predictions as phishing results.")
