#/*
# * Copyright 2017 ~ 2025 the original author or authors. <Wanglsir@gmail.com, 983708408@qq.com>
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */

PWD := $(shell pwd)
SHELL := /bin/bash
TARGET_OS=$(shell ./scripts/build/setup_env.sh get --OS)
TARGET_ARCH=$(shell ./scripts/build/setup_env.sh get --ARCH)
OUT_DIR="./_output"
VERSION=$(shell ./scripts/build/setup_env.sh get --VERSION)

all: clean build package

build: ## install & build.
	@echo "Building assets ..."
	pip install -r requirements.txt

package: ## build to target executable package.
	@echo "Packing build assets ..."
	pip3 install pyinstaller
	pyinstaller --workpath $(OUT_DIR)/tmp/ \
		--distpath $(OUT_DIR)/bin/ \
		--specpath $(OUT_DIR)/spec --clean --log-level INFO \
		--noconfirm \
		--name simplehttpfs_$(VERSION)_$(TARGET_OS)_$(TARGET_ARCH) \
		-F ./apps/simple_httpfs.py

clean: ## clean old build assets.
	@echo "Cleaning old build assets ..."
	find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf
	-rm -rf _output
	-rm -rf htmlcov
	-rm -rf .coverage
	-rm -rf build
	-rm -rf dist
	-rm -rf src/*.egg-info
	-rm -rf ../templates_module
	-rm -rf .cache
	-rm -rf __pycache__
	-rm -rf */__pycache__
	-rm -rf */*/__pycache__

help: ## print this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'