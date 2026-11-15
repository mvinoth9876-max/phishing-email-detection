
import os
import joblib
import pandas as pd

MODEL_PATH = "models/best_model.pkl"
FEATURE_PATH = "models/feature_names.pkl"
DATASET_PATH = "dataset/emails.csv"


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Trained model not found. Run train.py first.")

    if not os.path.exists(FEATURE_PATH):
        raise FileNotFoundError("Feature names not found. Run train.py first.")

    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURE_PATH)

    return model, feature_names


def predict_email_features(feature_values):
    model, feature_names = load_model()

    if len(feature_values) != len(feature_names):
        raise ValueError(
            f"Expected {len(feature_names)} features, "
            f"but received {len(feature_values)}."
        )

    input_data = pd.DataFrame(
        [feature_values],
        columns=feature_names
    )

    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]
    confidence = max(probabilities) * 100

    return {
        "prediction_label": int(prediction),
        "confidence": round(float(confidence), 2)
    }


if __name__ == "__main__":
    print("=" * 50)
    print("       EMAIL PREDICTION MODULE")
    print("=" * 50)

    # Test using one existing dataset record
    df = pd.read_csv(DATASET_PATH)

    feature_names = joblib.load(FEATURE_PATH)

    sample = df[feature_names].iloc[0].tolist()

    result = predict_email_features(sample)

    print("\nPrediction label:", result["prediction_label"])
    print("Confidence:", str(result["confidence"]) + "%")

    print("\nPrediction module working!")
