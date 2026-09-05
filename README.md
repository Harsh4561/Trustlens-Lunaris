# VoiceGuard

VoiceGuard is a local web prototype for classifying uploaded or recorded speech as likely human or AI-generated. It uses a FastAPI audio-processing pipeline and a React/Vite dashboard.

## What is implemented

- Upload and browser microphone recording (WAV, MP3, M4A, FLAC, OGG, WebM, and Opus)
- API validation, decoding, mono conversion, resampling, silence trimming, normalization, feature extraction, and technical metadata
- Real inference through `HyperMoon/wav2vec2-base-960h-finetuned-deepfake`, an ASVspoof2019-trained Wav2Vec2 audio-classification checkpoint
- Probabilistic classification, confidence, risk score, evidence indicators, warnings, and a non-definitive-result disclaimer
- Health, model-info, configuration, live-analysis, and demo endpoints

## Run locally

Use two terminals:

```powershell
cd backend
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:5173`. The first backend startup downloads the model; it requires an internet connection and can take a few minutes.

## Demo audio

Add legally obtained WAV files to `backend/demo_audio` named `real_human.wav` and `ai_generated.wav`. They are served and analyzed through the same API path as every upload. No fixed result is returned for a demo clip.

## Important limitation

This checkpoint was trained on ASVspoof-style synthetic-speech data. It is a research model, not proof that an audio sample is synthetic or authentic. Use its output as a screening signal and retain the shown warnings, model status, and disclaimer when presenting results.
