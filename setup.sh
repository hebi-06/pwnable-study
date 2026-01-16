#!/bin/bash

# 1. 기본 패키지 및 필수 툴 설치
sudo apt-get update
sudo apt-get install -y gdb python3 python3-pip git wget curl vim gcc file netcat-openbsd

# 2. 32비트 바이너리 실행 지원 (이게 없으면 32비트 문제 실행 안 됨)
sudo apt-get install -y gcc-multilib

# 3. Pwntools 설치 (익스플로잇 필수템)
python3 -m pip install --upgrade pip
python3 -m pip install pwntools

# 4. Pwndbg 설치 (GDB 플러그인)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
cd ..

echo "★ Pwnable 환경 구축 완료! Happy Hacking! ★"
