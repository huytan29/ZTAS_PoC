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
CADDY_BIN ?= C:\Tools\Caddy\caddy.exe
HTTPS_HOST ?= ztas.ptit
ZTAS_SERVER_IP ?=

.PHONY: help configure build provision docker-ready opa-up opa-logs env https-proxy deploy-https run demo logs stop down clean

help:
	@echo make build      Build ZTAS for Windows with the vcpkg preset
	@echo make provision Build and issue keys for registered devices
	@echo make opa-up     Start OPA (Docker Desktop must already be running)
	@echo make run        Build, provision, start OPA, ZTAS and local HTTPS proxy
	@echo make deploy-https Run HTTPS bootstrap; use ZTAS_SERVER_IP=x.x.x.x when needed
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

https-proxy:
	@if not exist "$(CADDY_BIN)" (echo Khong tim thay Caddy tai "$(CADDY_BIN)". Hay cai Caddy mot lan truoc khi chay make run. & exit /b 1)
	@if not exist runtime mkdir runtime
	@powershell -NoProfile -Command "$$template = Get-Content 'deploy\Caddyfile.https.local.example' -Raw; $$config = $$template.Replace('ztas.ptit', '$(HTTPS_HOST)'); [System.IO.File]::WriteAllText((Join-Path (Resolve-Path 'runtime') 'Caddyfile'), $$config); $$pidFile = 'runtime\caddy.pid'; $$running = $$false; if (Test-Path $$pidFile) { $$caddyId = Get-Content $$pidFile; $$process = Get-Process -Id $$caddyId -ErrorAction SilentlyContinue; if ($$process -and $$process.ProcessName -eq 'caddy') { $$running = $$true } else { Remove-Item $$pidFile -Force } }; if (-not $$running) { $$configPath = (Resolve-Path 'runtime\Caddyfile').Path; $$process = Start-Process -FilePath '$(CADDY_BIN)' -ArgumentList @('run','--config',$$configPath,'--adapter','caddyfile') -WorkingDirectory '.' -RedirectStandardOutput 'runtime\caddy.stdout.log' -RedirectStandardError 'runtime\caddy.stderr.log' -PassThru; $$process.Id | Set-Content $$pidFile; Start-Sleep -Milliseconds 800; if (-not (Get-Process -Id $$process.Id -ErrorAction SilentlyContinue)) { throw 'Caddy khong khoi dong. Xem runtime\caddy.stderr.log' } }"

deploy-https:
	@call scripts\deploy-https-windows.cmd "$(ZTAS_SERVER_IP)"

run: provision opa-up env
	@powershell -NoProfile -Command "$$running = $$false; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8020/health | Out-Null; $$running = $$true } catch {}; if ($$running) { Write-Output 'ZTAS dang chay tren cong 8020 do mot tien trinh khac quan ly.' } else { $$line = Get-Content 'runtime/ztas.env' | Where-Object { $$_ -like 'APP_TOKEN_SECRET=*' } | Select-Object -First 1; if (-not $$line) { throw 'Khong tim thay APP_TOKEN_SECRET trong runtime/ztas.env' }; $$env:APP_TOKEN_SECRET = $$line.Substring('APP_TOKEN_SECRET='.Length); $$env:ZTAS_BIND_ADDRESS = '127.0.0.1'; $$env:ZTAS_SECURE_COOKIES = 'true'; $$env:ZTAS_TRUST_LOOPBACK_PROXY = 'true'; Start-Process -FilePath '$(ZTAS_BIN)' -WorkingDirectory '.' -RedirectStandardOutput 'runtime/ztas.stdout.log' -RedirectStandardError 'runtime/ztas.stderr.log'; Start-Sleep -Milliseconds 500; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8020/health | Out-Null } catch { throw 'ZTAS khong khoi dong. Xem runtime/ztas.stderr.log' } }"
	@$(MAKE) --no-print-directory https-proxy
	@echo Dashboard: https://$(HTTPS_HOST):8443/dashboard

demo: run
	@powershell -NoProfile -Command "New-Item -ItemType Directory -Force data\logs | Out-Null; $$file = 'data/logs/' + (Get-Date -Format yyyy-MM-dd) + '.jsonl'; New-Item -ItemType File -Force $$file | Out-Null; Get-Content -Tail 30 -Wait $$file"

logs:
	@powershell -NoProfile -Command "New-Item -ItemType Directory -Force data\logs | Out-Null; $$file = 'data/logs/' + (Get-Date -Format yyyy-MM-dd) + '.jsonl'; New-Item -ItemType File -Force $$file | Out-Null; Get-Content -Tail 30 -Wait $$file"

stop:
	@powershell -NoProfile -Command "$$pidFile = 'runtime\caddy.pid'; if (Test-Path $$pidFile) { $$caddyId = Get-Content $$pidFile; $$process = Get-Process -Id $$caddyId -ErrorAction SilentlyContinue; if ($$process -and $$process.ProcessName -eq 'caddy') { Stop-Process -Id $$caddyId -Force }; Remove-Item $$pidFile -Force }"
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
CADDY_BIN ?= caddy
HTTPS_HOST ?= ztas.ptit
ZTAS_SERVER_IP ?=

.PHONY: help configure build provision docker-ready opa-up opa-logs env https-proxy deploy-https run demo logs stop down clean

help:
	@echo "make build      Build ZTAS for macOS"
	@echo "make provision Build and issue keys for registered devices"
	@echo "make opa-up     Start OPA (Docker Desktop must already be running)"
	@echo "make run        Build, provision, start OPA, ZTAS and local HTTPS proxy"
	@echo "make deploy-https ZTAS_SERVER_IP=x.x.x.x: one-command macOS HTTPS bootstrap"
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

https-proxy:
	@command -v "$(CADDY_BIN)" >/dev/null 2>&1 || { echo "Khong tim thay Caddy. Cai mot lan bang: brew install caddy"; exit 1; }
	@mkdir -p runtime
	@sed 's/ztas\.ptit/$(HTTPS_HOST)/g' deploy/Caddyfile.https.local.example > runtime/Caddyfile
	@if [ -f runtime/caddy.pid ] && kill -0 "$$(cat runtime/caddy.pid)" 2>/dev/null; then \
		echo "Caddy da chay (PID $$(cat runtime/caddy.pid))."; \
	else \
		nohup "$(CADDY_BIN)" run --config "$$(pwd)/runtime/Caddyfile" --adapter caddyfile > runtime/caddy.stdout.log 2> runtime/caddy.stderr.log < /dev/null & \
		echo $$! > runtime/caddy.pid; \
		sleep 1; \
		if ! kill -0 "$$(cat runtime/caddy.pid)" 2>/dev/null; then echo "Caddy khong khoi dong. Xem runtime/caddy.stderr.log"; exit 1; fi; \
	fi

deploy-https:
	@sh scripts/deploy-https-macos.sh "$(ZTAS_SERVER_IP)"

run: provision opa-up env
	@set -e; \
	if [ -f runtime/ztas.pid ] && kill -0 "$$(cat runtime/ztas.pid)" 2>/dev/null; then \
		kill "$$(cat runtime/ztas.pid)"; sleep 1; \
	fi; \
	if curl -fsS $(INTERNAL_ZTAS_URL)/health >/dev/null 2>&1; then \
		echo "ZTAS dang chay tren cong 8020 do mot tien trinh khac quan ly."; \
	else \
		set -a; . runtime/ztas.env; set +a; \
		export ZTAS_BIND_ADDRESS=127.0.0.1; \
		export ZTAS_SECURE_COOKIES=true; \
		export ZTAS_TRUST_LOOPBACK_PROXY=true; \
		nohup "$(ZTAS_BIN)" > runtime/ztas.stdout.log 2>&1 < /dev/null & \
		echo $$! > runtime/ztas.pid; \
		echo "Da khoi dong ZTAS (PID $$(cat runtime/ztas.pid))."; \
	fi
	@$(MAKE) --no-print-directory https-proxy
	@echo "Dashboard: https://$(HTTPS_HOST):8443/dashboard"

demo: run
	@log_file="data/logs/$$(date +%F).jsonl"; mkdir -p data/logs; touch "$$log_file"; tail -n 30 -f "$$log_file"

logs:
	@log_file="data/logs/$$(date +%F).jsonl"; mkdir -p data/logs; touch "$$log_file"; tail -n 30 -f "$$log_file"

stop:
	@if [ -f runtime/caddy.pid ] && kill -0 "$$(cat runtime/caddy.pid)" 2>/dev/null; then \
		kill "$$(cat runtime/caddy.pid)"; echo "Da dung Caddy."; \
	fi
	@rm -f runtime/caddy.pid
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
