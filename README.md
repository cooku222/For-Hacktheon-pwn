# For-Hacktheon-pwn
포너블 코드 스니펫(bof +.. etc)
- 유형별 정리를 원칙으로 한다.
- 핵테온 풀 때 가져다 쓸 수 있게 제작함
- 로컬이 아니라 vmWare 구동해서 쓰는 것이기에, 파일 호출보다는 원격 호출을 우선시한다.

# Pattern
- Buffer Overflow : 정해진 버퍼사이즈 넘게 입력받을때 생기는 취약점
- Stack Canary : 버퍼와 SFP 사이에 임의의 데이터를 삽입하여 버퍼 오버플로우를 탐지하는 기법
- Free Hook Overwrite : free()를 쉘 따는 트리거로 바꾸는 기법 
- Format String bug : printf, fprintf, sprintf, snprintf 같은 함수에서 사용자 입력을 포맷 문자열로 직접 사용할 때 발생하는 취약점
- Return to libc : Library 내에 함수로 Return 하는 공격기법
- ROP(Return-Oriented Programming) : return-oriented-programming 의 약자로, 마치 프로그래밍 하듯이 리턴주소를 조작해 함수를 실행하는 기법. BOF 를 일으켜 리턴 주소 이후를 덮을 수 있을 때 사용
- GOT/PLT Overwrite : GOT 은 Global Offset Table 의 약자로, 호출하는 함수의 실제 주소를 구하는 코드 (PLT+6) 의 주소를 담고있다가, 함수가 최초로 호출되면, 함수의 실제주소를 담는 테이블. PLT 는 Procedure Linkage Tabel 의 약자로, 파일 내부가 아니라, 다른 라이브러리에 함수를 호출할 때 연결시켜주는 테이블
- Heap Exploitation : C 프로그램에서 malloc, free로 할당/해제되는 힙 영역의 구조를 깨거나 조작해서, 시스템 동작을 의도한 대로 바꾸는 공격
- PIE / ASLR 우회: Address Space Layout Randomization 라는 보호기법. 프로그램이 실행될 때마다 가상 주소공간에 올라가는 (mapping되는) 스택, 힙, 공유 라이브러리 의 위치가 랜덤으로 변하는 것.
- Syscall 활용 (ROP 기반) : 보통 쉘 따는 대표 방법은 system("/bin/sh")이지만, libc 없음, Partial RELRO, /bin/sh에도 문자열이 없는 경우, NX enabled인 경우 -> syscall로 직접 호출
