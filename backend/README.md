# ShadowGuard AI backend

## Windows PowerShell setup

From the project root, activate the existing virtual environment, install the
backend dependencies, and create a local environment file from the example:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\backend\requirements.txt
if (-not (Test-Path .\backend\.env)) { Copy-Item .\backend\.env.example .\backend\.env }
notepad .\backend\.env
```

In `backend\.env`, replace `your_api_key_here` with a valid OpenAI API key.
Set `MODEL_NAME` to a model available to that account, for example
`openai:gpt-4o-mini`. The `.env` file is ignored by Git; do not commit it or
share its contents. For an OpenRouter account, set `MODEL_NAME` to an available
OpenRouter model identifier such as `openrouter:openai/gpt-4o-mini`, and set
`OPENROUTER_API_KEY` (or use the existing `OPENAI_API_KEY` variable). Restart
the backend after changing either value.

Start the API from the backend directory:

```powershell
Set-Location .\backend
python -m uvicorn app.main:app --reload
```

Check `http://127.0.0.1:8000/api/health`, then send a POST request to
`http://127.0.0.1:8000/api/chat` with JSON such as
`{"message":"Hello","user_id":"demo-user"}`. A successful response includes
`response`, `status`, `approval_id`, `session_id`, `state`, and `provenance`.
Protected operations remain subject to ShadowGuard policy and human approval.

The ML trust and intent signals use saved synthetic-demonstration models. See
[`docs/ml-security-models.md`](../docs/ml-security-models.md) for training,
evaluation metrics, configuration, and limitations.
