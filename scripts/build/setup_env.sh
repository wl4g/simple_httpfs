#!/bin/bash

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
set -e

function usages() {
    echo "Usage: ./$(basename $0) [OPTIONS] [arg1] [arg2] ...
      GET,get                   Gets environments.
              --OS              Gets local platform OS name.
              --ARCH            Gets local platform ARCH name.
              --VERSION         Gets that project version based git commit."
}

function get_env() {
    case $1 in
        --OS)
            LOCAL_OS=$(uname)
            # Pass environment set target operating-system to build system
            if [[ $LOCAL_OS == Linux ]]; then
                echo 'linux'
                readlink_flags="-f"
            elif [[ $LOCAL_OS == Darwin ]]; then
                echo 'darwin'
                readlink_flags=""
            else
                # echo "This system's OS, $LOCAL_OS, isn't supported"
                echo ""
                exit 1
            fi
        ;;
        --ARCH)
            LOCAL_ARCH=$(uname -m)
            # Pass environment set target architecture to build system
            if [[ ${LOCAL_ARCH} == x86_64 ]]; then
                echo 'amd64'
            elif [[ ${LOCAL_ARCH} == armv8* ]]; then
                echo 'arm64'
            elif [[ ${LOCAL_ARCH} == arm64* ]]; then
                echo 'arm64'
            elif [[ ${LOCAL_ARCH} == aarch64* ]]; then
                echo 'arm64'
            elif [[ ${LOCAL_ARCH} == armv* ]]; then
                echo 'arm'
            elif [[ ${LOCAL_ARCH} == s390x ]]; then
                echo 's390x'
            elif [[ ${LOCAL_ARCH} == ppc64le ]]; then
                echo 'ppc64le'
            else
                # echo "This system's architecture, ${LOCAL_ARCH}, isn't supported"
                echo ""
                exit 1
            fi
        ;;
        --VERSION)
            branch=$(git branch | grep '\*')
            commit=$(commitId=$(git log -n1 --format=format:"%H"); echo ${commitId:0:8})
            if [[ "$branch" =~ "HEAD" ]]; then
              branch=$(echo "$branch" | sed -E 's/\(|\)//g' | awk -F ' ' '{print $5}')
            else
              branch=$(echo "$branch" | awk -F ' ' '{print $2}')
            fi
            echo "$branch-$commit-$(date +%Y%m%d%H%M%S)"
        ;;
        *)
            usages
        ;;
    esac
}

# --- Main. ---
case $1 in
    GET|get)
        get_env "$2"
    ;;
    *)
        usages
    ;;
esac
