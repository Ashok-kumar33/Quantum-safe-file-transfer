# QuantumSafe VPN Cloud - deploy on Render (free)

1. Put these 4 files in a new GitHub repo: `app.py`, `requirements.txt`, `Procfile`, `README.md`.
2. Go to render.com -> New -> Web Service -> connect the repo.
3. Settings: Runtime = Python 3, Build = `pip install -r requirements.txt`, Start = `gunicorn app:app`.
4. Environment -> add `SECRET_KEY` = a long random string (keep it the same forever; it protects stored keys).
5. Deploy. You get a URL like `https://your-app.onrender.com` - open it on any PC.

Notes: free Render sleeps after inactivity (first load ~30 s) and its disk is wiped on redeploy,
so accounts reset. Fine for a demo; use a paid disk or Postgres for real use.
Local test: `pip install -r requirements.txt` then `python app.py` -> http://127.0.0.1:5000
