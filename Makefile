SHELL := /bin/zsh

CPP_HTTPLIB_PREFIX := $(shell brew --prefix cpp-httplib 2>/dev/null)
JSON_PREFIX := $(shell brew --prefix nlohmann-json 2>/dev/null)
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
CMAKE_PREFIXES := $(CPP_HTTPLIB_PREFIX);$(JSON_PREFIX);$(OPENSSL_PREFIX)
POC_URL := http://poc-ptit.localhost:8020
INTERNAL_ZTAS_URL := http://127.0.0.1:8020

.PHONY: help configure build provision docker-ready opa-up opa-logs run demo logs stop down clean

help:
	@echo "make demo       Build, cap khoa thiet bi, chay ZTAS, mo Dashboard va hien log"
	@echo "make build      Chi build chuong trinh C++"
	@echo "make provision  Chi cap khoa cho thiet bi registered"
	@echo "make opa-up     Khoi dong OPA Policy Engine bang Docker"
	@echo "make logs       Theo doi audit log"
	@echo "make stop       Dung ZTAS da chay nen (giu OPA)"
	@echo "make down       Dung ca ZTAS va OPA"

configure:
	@cmake -S . -B build -DCMAKE_PREFIX_PATH="$(CMAKE_PREFIXES)"

build: configure
	@cmake --build build --parallel 4

provision: build
	@./build/provision_devices \
		policies/devices.json \
		data/device_credentials.json \
		runtime/devices

docker-ready:
	@set -e; \
	if docker info >/dev/null 2>&1; then \
		echo "Docker Engine da san sang."; \
	else \
		echo "Dang mo Docker Desktop va cho Docker Engine khoi dong..."; \
		open -a Docker; \
		for attempt in {1..60}; do \
			if docker info >/dev/null 2>&1; then break; fi; \
			sleep 2; \
		done; \
		if ! docker info >/dev/null 2>&1; then \
			echo "Docker chua san sang sau 120 giay. Hay mo Docker Desktop va kiem tra lai."; \
			exit 1; \
		fi; \
		echo "Docker Engine da san sang."; \
	fi

opa-up: docker-ready
	@docker compose up -d --force-recreate opa
	@set -e; \
	for attempt in {1..10}; do \
		if curl -fsS http://127.0.0.1:8181/health >/dev/null 2>&1; then break; fi; \
		sleep 0.5; \
	done; \
	if ! curl -fsS http://127.0.0.1:8181/health >/dev/null 2>&1; then \
		echo "OPA khoi dong that bai. Log OPA:"; \
		docker compose logs --tail=80 opa || true; \
		exit 1; \
	fi; \
	echo "OPA da san sang tai http://127.0.0.1:8181."

opa-logs:
	@docker compose logs -f opa

runtime/ztas.env:
	@mkdir -p runtime
	@if [[ ! -f $@ ]]; then \
		printf 'APP_TOKEN_SECRET=' > $@; \
		openssl rand -hex 32 >> $@; \
		chmod 600 $@; \
		echo "Da tao APP_TOKEN_SECRET rieng cho moi truong demo."; \
	fi

run: provision opa-up runtime/ztas.env
	@set -e; \
	if [[ -f runtime/ztas.pid ]] && kill -0 "$$(cat runtime/ztas.pid)" 2>/dev/null && \
		ps -p "$$(cat runtime/ztas.pid)" -o command= | grep -q 'ztas'; then \
		kill "$$(cat runtime/ztas.pid)"; \
		echo "Da khoi dong lai ZTAS de nap phien ban moi."; \
		sleep 0.5; \
	fi; \
	if curl -fsS $(INTERNAL_ZTAS_URL)/health >/dev/null 2>&1; then \
		echo "ZTAS dang chay tren cong 8020 do mot tien trinh khac quan ly."; \
	else \
		set -a; source runtime/ztas.env; set +a; \
		( trap '' INT; exec nohup ./build/ztas > runtime/ztas.stdout.log 2>&1 < /dev/null ) & \
		echo $$! > runtime/ztas.pid; \
		echo "Da khoi dong ZTAS (PID $$(cat runtime/ztas.pid))."; \
	fi

demo: run
	@set -e; \
	for attempt in {1..30}; do \
		if curl -fsS $(INTERNAL_ZTAS_URL)/health >/dev/null 2>&1; then break; fi; \
		sleep 0.5; \
	done; \
	if ! curl -fsS $(INTERNAL_ZTAS_URL)/health >/dev/null 2>&1; then \
		echo "ZTAS khoi dong that bai. Xem runtime/ztas.stdout.log de biet loi."; \
		exit 1; \
	fi; \
	open $(POC_URL)/dashboard; \
	echo "Dashboard da mo. Nhan Ctrl+C de dung theo doi log; dung 'make stop' de dung ZTAS."; \
	log_file="data/logs/$$(date +%F).jsonl"; mkdir -p data/logs; touch "$$log_file"; tail -n 30 -f "$$log_file"

logs:
	@log_file="data/logs/$$(date +%F).jsonl"; mkdir -p data/logs; touch "$$log_file"; tail -n 30 -f "$$log_file"

stop:
	@if [[ -f runtime/ztas.pid ]] && kill -0 "$$(cat runtime/ztas.pid)" 2>/dev/null; then \
		kill "$$(cat runtime/ztas.pid)"; \
		echo "Da dung ZTAS."; \
	else \
		echo "ZTAS khong chay nen."; \
	fi
	@rm -f runtime/ztas.pid

down: stop
	@docker compose down

clean:
	@cmake --build build --target clean
