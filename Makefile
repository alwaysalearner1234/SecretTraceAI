.PHONY: setup run-backend run-frontend run-demo benchmark test docker-up docker-down clean

# Initial setup
setup:
	pip install -r backend/requirements.txt
	cd frontend && npm install
	python fixtures/generate_demo_repo.py

# Run local servers
run-backend:
	$env:PYTHONPATH="."
	python backend/app/main.py

run-frontend:
	cd frontend && npm run dev

# Run benchmark evaluation
benchmark:
	$env:PYTHONPATH="."
	python ml/evaluation/benchmark.py

# Run unit tests
test:
	$env:PYTHONPATH="."
	pytest backend/tests/ -v

# Run Docker Compose
docker-up:
	docker compose up --build

docker-down:
	docker compose down

# Clean up local cache
clean:
	Remove-Item -Path "**/__pycache__", "frontend/dist", "frontend/node_modules" -Recurse -Force -ErrorAction SilentlyContinue
