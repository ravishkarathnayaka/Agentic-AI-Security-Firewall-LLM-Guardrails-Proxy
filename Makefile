.PHONY: help install run test benchmark report lint portal docker-up docker-down clean

help:
	@echo "Agentic AI Security Firewall & LLM Guardrails Proxy"
	@echo "Available commands:"
	@echo "  make install     - Install development dependencies"
	@echo "  make run         - Run the proxy locally with reload"
	@echo "  make portal      - Serve the Obsidian Amber web portal on :3001"
	@echo "  make test        - Run unit and integration tests with coverage"
	@echo "  make benchmark   - Run automated adversarial red-teaming benchmark"
	@echo "  make report      - Generate HTML & Markdown compliance audit reports"
	@echo "  make lint        - Run ruff linter check"
	@echo "  make docker-up   - Start full Docker Compose stack (Proxy, Mock, Prometheus, Grafana)"
	@echo "  make docker-down - Stop Docker Compose stack"
	@echo "  make clean       - Remove cached files and test artifacts"

install:
	pip install --upgrade pip
	pip install ".[dev]"

run:
	python -m uvicorn proxy.main:app --host 0.0.0.0 --port 8080 --reload

portal:
	@echo "Serving Obsidian Amber web portal at http://localhost:3001..."
	python -m http.server 3001 --directory portal

test:
	python -m pytest -v tests/ --cov=proxy --cov-report=term-missing

benchmark:
	python red_teaming/evaluate_benchmark.py

report: benchmark
	python red_teaming/export_report.py

lint:
	ruff check proxy/ red_teaming/ tests/

docker-up:
	docker compose -f docker/docker-compose.yml up -d --build

docker-down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf .pytest_cache .coverage htmlcov audit_logs.jsonl benchmark_results.json
