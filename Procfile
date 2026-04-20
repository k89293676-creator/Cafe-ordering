web: FLASK_APP=app flask db upgrade && gunicorn app:app --bind 0.0.0.0:$PORT --worker-class gevent --workers 1 --threads 4
