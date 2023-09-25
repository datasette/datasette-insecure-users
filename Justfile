dev:
  DATASETTE_SECRET=abc123 watchexec --signal SIGKILL --restart --clear -e py,ts,js,html,css,sql -- \
  python -m datasette --memory --port 8006 --internal internal.db

