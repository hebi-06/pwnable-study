# venv
# 반드시 /workspaces 안에 둘 것 (홈 디렉토리는 rebuild 시 삭제됨)
source /workspaces/pwnable-study/.venv/bin/activate


# docker

1. Dockerfile 빌드하기 (예: docker build -t <imgname> .)
docker build -t probimg .
2. 빌드된 이미지로 컨테이너 실행하기 (예: docker run -d --name=<containner name> <imgname>)
docker run --rm probimg find / -name "libc.so.6" 2>/dev/null
3. 실행된 컨테이너 접속하기 (예: docker exec -it <containner name> bash)
docker create --name tmpc probimg && docker cp tmpc:<경로> ./libc.so.6 && docker rm tmpc
4. 문제 바이너리의 동적 라이브러리 확인하기 (예: ldd ./<binary>)
chall@1728e9fa7bde:~$ ldd ./main
        linux-vdso.so.1 (0x00007ffe43708000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007149eff8f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007149f01c0000)
5. 호스트에서 docker 컨테이너 내부 파일을 복사하기 (예: docker cp <containner name>:<file path> .)
(.myvenv) @hebi-06 ➜ .../dreamhack/test4/Libc_got_overwrite/deploy (main) $ docker cp 1728e9fa7bde:/lib/x86_64-linux-gnu/libc.so.6 .
Successfully copied 2.22MB (transferred 2.22MB) to /workspaces/pwnable-study/dreamhack/test4/Libc_got_overwrite/deploy/.



XKmtKrv7M9pvoAWAzSU9a7dHL0QS68pK7P7FHVx8azCI7BQS#av5F2XFAEsuCq7aMA-nVIffdF5kPAHF-kvDsvJKL-IY

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
