# Phishing Link Detection — React + FastAPI

This project converts the Streamlit `app.py` UI into a React frontend while keeping the Python/scikit-learn functionality in a FastAPI backend.

## Architecture

- `frontend/` — React + Vite UI
- `backend/main.py` — FastAPI API containing URL feature extraction, Random Forest training/prediction, rule analysis, website analysis, VirusTotal, Google Safe Browsing, risk assessment, and PDF report generation.
- Put `phishing link detection dataset.csv` inside `backend/`.

## Run

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
```

The API runs at `http://localhost:8000`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite, normally `http://localhost:5173`.

## Notes

- The browser does not execute the scikit-learn model directly. React calls the FastAPI backend.
- The Random Forest configuration follows the supplied `app.py`: 200 estimators, `random_state=42`, balanced class weights.
- The target convention follows the supplied notebook/app: dataset `ClassLabel=0` means phishing and `ClassLabel=1` means legitimate; the internal ML target is reversed so `1` means phishing.
- VirusTotal and Google Safe Browsing API keys are optional. They are entered in the React UI and sent only for the scan request.


## Dataset requirement

The FastAPI backend trains the Random Forest model when it starts scanning. Put the CSV used by the phishing notebook in:

`backend/phishing link detection dataset.csv`

The CSV must contain `ClassLabel` and either the 16 engineered feature columns or a `URL` column. In the notebook convention, `ClassLabel=0` means phishing and `ClassLabel=1` means legitimate.

If the CSV is missing, the API will return a clear dataset error instead of the React error `Unexpected end of JSON input`.
