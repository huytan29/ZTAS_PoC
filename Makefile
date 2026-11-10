# GNU Make entry point for macOS and Windows.
# Windows recipes run natively through cmd.exe, so invoke `make build` from CMD.

ifeq ($(OS),Windows_NT)

SHELL := cmd.exe
.SHELLFLAGS := /C
PLATFORM := windows
EXE := .exe
BUILD_DIR := build\$(PLATFORM)
ZTAS_BIN := $(BUILD_DIR)\ztas$(EXE)
PROVISION_BIN := $(BUILD_DIR)\provision_devices$(EXE)

.PHONY: help configure build provision docker-ready opa-up opa-logs env run demo logs stop down clean

help:
	@echo make build      Build ZTAS for Windows with the vcpkg preset
	@echo make provision Build and issue keys for registered devices
	@echo make opa-up     Start OPA (Docker Desktop must already be running)
	@echo make run        Build, provision, start OPA and start ZTAS
	@echo make logs       Follow today's audit log
	@echo make stop       Stop ztas.exe started for this PoC
	@echo make down       Stop ZTAS and OPA

configure:
	@set "VCPKG_DEFAULT_TRIPLET=x64-mingw-static" && set "VCPKG_DEFAULT_HOST_TRIPLET=x64-mingw-static" && cmake --preset $(PLATFORM) -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DCMAKE_MAKE_PROGRAM=mingw32-make -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++

build: configure
	@cmake --build --preset $(PLATFORM) --parallel

provision: build
	@"$(PROVISION_BIN)" policies\devices.json data\device_credentials.json runtime\devices

docker-ready:
	@docker info >nul 2>&1 || (echo Docker Engine chua san sang. Hay mo Docker Desktop roi chay lai. & exit /b 1)

opa-up: docker-ready
	@docker compose up -d --force-recreate opa
	@powershell -NoProfile -Command "$$ready = $$false; foreach ($$attempt in 1..10) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8181/health | Out-Null; $$ready = $$true; break } catch { Start-Sleep -Seconds 1 } }; if (-not $$ready) { exit 1 }"
	@echo OPA da san sang tai http://127.0.0.1:8181.

opa-logs:
	@docker compose logs -f opa

env:
	@if not exist runtime mkdir runtime
	@if not exist runtime\ztas.env powershell -NoProfile -Command "$$bytes = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($$bytes); [System.IO.File]::WriteAllText('runtime/ztas.env', 'APP_TOKEN_SECRET=' + [System.BitConverter]::ToString($$bytes).Replace('-', '').ToLowerInvariant())"

run: provision opa-up env
	@powershell -NoProfile -Command "$$running = $$false; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8020/health | Out-Null; $$running = $$true } catch {}; if ($$running) { Write-Output 'ZTAS dang chay tren cong 8020 do mot tien trinh khac quan ly.' } else { $$line = Get-Content 'runtime/ztas.env' | Where-Object { $$_ -like 'APP_TOKEN_SECRET=*' } | Select-Object -First 1; if (-not $$line) { throw 'Khong tim thay APP_TOKEN_SECRET trong runtime/ztas.env' }; $$env:APP_TOKEN_SECRET = $$line.Substring('APP_TOKEN_SECRET='.Length); Start-Process -FilePath '$(ZTAS_BIN)' -WorkingDirectory '.' -RedirectStandardOutput 'runtime/ztas.stdout.log' -RedirectStandardError 'runtime/ztas.stderr.log'; Start-Sleep -Milliseconds 500; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8020/health | Out-Null } catch { throw 'ZTAS khong khoi dong. Xem runtime/ztas.stderr.log' } }"
	@echo Dashboard: http://localhost:8020/dashboard

demo: run
	@powershell -NoProfile -Command "New-Item -ItemType Directory -Force data\logs | Out-Null; $$file = 'data/logs/' + (Get-Date -Format yyyy-MM-dd) + '.jsonl'; New-Item -ItemType File -Force $$file | Out-Null; Get-Content -Tail 30 -Wait $$file"

logs:
	@powershell -NoProfile -Command "New-Item -ItemType Directory -Force data\logs | Out-Null; $$file = 'data/logs/' + (Get-Date -Format yyyy-MM-dd) + '.jsonl'; New-Item -ItemType File -Force $$file | Out-Null; Get-Content -Tail 30 -Wait $$file"

stop:
	@taskkill /F /IM ztas.exe >nul 2>&1 || echo ZTAS khong chay.

down: stop
	@docker compose down

clean:
	@cmake --build $(BUILD_DIR) --config RelWithDebInfo --target clean

else

SHELL := /bin/sh
PLATFORM := macos
EXE :=
BUILD_DIR := build/$(PLATFORM)
ZTAS_BIN := $(BUILD_DIR)/ztas$(EXE)
PROVISION_BIN := $(BUILD_DIR)/provision_devices$(EXE)
POC_URL := http://localhost:8020
INTERNAL_ZTAS_URL := http://127.0.0.1:8020

.PHONY: help configure build provision docker-ready opa-up opa-logs env run demo logs stop down clean

help:
	@echo "make build      Build ZTAS for macOS"
	@echo "make provision Build and issue keys for registered devices"
	@echo "make opa-up     Start OPA (Docker Desktop must already be running)"
	@echo "make run        Build, provision, start OPA and start ZTAS"
	@echo "make logs       Follow today's audit log"
	@echo "make stop       Stop the ZTAS process started by make"
	@echo "make down       Stop ZTAS and OPA"

configure:
	@cmake --preset $(PLATFORM)

build: configure
	@cmake --build --preset $(PLATFORM) --parallel

provision: build
	@$(PROVISION_BIN) policies/devices.json data/device_credentials.json runtime/devices

docker-ready:
	@docker info >/dev/null 2>&1 || { echo "Docker Engine chua san sang. Hay mo Docker Desktop roi chay lai."; exit 1; }

opa-up: docker-ready
	@docker compose up -d --force-recreate opa
	@attempt=1; while [ $$attempt -le 10 ]; do \
		curl -fsS http://127.0.0.1:8181/health >/dev/null 2>&1 && break; \
		sleep 1; attempt=$$((attempt + 1)); \
	done; \
	if ! curl -fsS http://127.0.0.1:8181/health >/dev/null 2>&1; then \
		echo "OPA khoi dong that bai. Log OPA:"; docker compose logs --tail=80 opa || true; exit 1; \
	fi; \
	echo "OPA da san sang tai http://127.0.0.1:8181."

opa-logs:
	@docker compose logs -f opa

env:
	@mkdir -p runtime
	@if [ ! -f runtime/ztas.env ]; then \
		umask 077; printf 'APP_TOKEN_SECRET=' > runtime/ztas.env; openssl rand -hex 32 >> runtime/ztas.env; \
		echo "Da tao APP_TOKEN_SECRET rieng cho moi truong demo."; \
	fi

run: provision opa-up env
	@set -e; \
	if [ -f runtime/ztas.pid ] && kill -0 "$$(cat runtime/ztas.pid)" 2>/dev/null; then \
		kill "$$(cat runtime/ztas.pid)"; sleep 1; \
	fi; \
	if curl -fsS $(INTERNAL_ZTAS_URL)/health >/dev/null 2>&1; then \
		echo "ZTAS dang chay tren cong 8020 do mot tien trinh khac quan ly."; \
	else \
		set -a; . runtime/ztas.env; set +a; \
		nohup "$(ZTAS_BIN)" > runtime/ztas.stdout.log 2>&1 < /dev/null & \
		echo $$! > runtime/ztas.pid; \
		echo "Da khoi dong ZTAS (PID $$(cat runtime/ztas.pid))."; \
	fi; \
	echo "Dashboard: $(POC_URL)/dashboard"

demo: run
	@log_file="data/logs/$$(date +%F).jsonl"; mkdir -p data/logs; touch "$$log_file"; tail -n 30 -f "$$log_file"

logs:
	@log_file="data/logs/$$(date +%F).jsonl"; mkdir -p data/logs; touch "$$log_file"; tail -n 30 -f "$$log_file"

stop:
	@if [ -f runtime/ztas.pid ] && kill -0 "$$(cat runtime/ztas.pid)" 2>/dev/null; then \
		kill "$$(cat runtime/ztas.pid)"; echo "Da dung ZTAS."; \
	else \
		echo "ZTAS khong chay nen qua make."; \
	fi
	@rm -f runtime/ztas.pid

down: stop
	@docker compose down

clean:
	@cmake --build $(BUILD_DIR) --target clean

endif
