;    This file implements RC4 in ASM.
;    Copyright (C) 2023, 2024  Maurice Lambert

;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.

;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.

;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <https://www.gnu.org/licenses/>.

; nasm -fwin64 rc4_win.asm
; gcc.exe -shared rc4_win.obj -o librc4.dll

; "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
; cl XXXX.c rc4_win.obj

; arc4_null_byte([IN/OUT] char *data) -> NULL
; arc4([IN/OUT] char *data, [IN] unsigned long long length) -> NULL
; generate_iv() -> NULL
; xor_key_iv() -> NULL
; generate_key(char *key) -> NULL
; reset_key() -> NULL
; get_iv() -> char[256] // null byte terminate string
; set_iv([IN] char iv[256]) -> NULL
; encrypt([IN] char *key, [IN/OUT] char *data, [IN] unsigned long long length) -> NULL  // if length is 0 call arc4_null_byte
; decrypt([IN] char *key, [IN] char iv[256], [IN/OUT] char *data, [IN] unsigned long long length) -> NULL // there is no way to decrypt string terminating by null byte because encrypted data can contains null byte

global arc4, generate_iv, generate_key, xor_key_iv, reset_key, get_iv, set_iv, encrypt, decrypt, arc4_null_byte

default rel

section .text

    arc4:
        mov r8, rcx                   ; data
        mov r10, rdx                  ; length
        xor rdx, rdx                  ; dl = index1 = 0
        xor rcx, rcx                  ; cl = index2 = 0
        xor rax, rax
        xor r11, r11
        lea r9, [key]
._4:    test r10, r10                 ; if length == 0: return;
        jne ._3
        ret
._3:    mov al, byte [r8]
        dec r10                       ; length -= 1;
        inc dl
        add cl, byte [r9 + rdx]
        mov al, byte [r9 + rdx]
        mov r11b, byte [r9 + rcx]
        mov byte [r9 + rdx], r11b
        mov byte [r9 + rcx], al       ; value1, value2 = value2, value1
        add al, r11b
        mov al, byte [r9 + rax]
        xor byte [r8], al
        inc r8                        ; next character
        jmp ._4

    arc4_null_byte:
        mov r8, rcx                   ; data
        xor rdx, rdx                  ; dl = index1 = 0
        xor rcx, rcx                  ; cl = index2 = 0
        xor rax, rax
        xor r11, r11
        lea r9, [key]
._11:   mov al, byte [r8]
        test al, al
        jne ._10                      ; if character == 0 (end of string) return else crypt character
        ret
._10:   inc dl
        add cl, byte [r9 + rdx]
        mov al, byte [r9 + rdx]
        mov r11b, byte [r9 + rcx]
        mov byte [r9 + rdx], r11b
        mov byte [r9 + rcx], al       ; value1, value2 = value2, value1
        add al, r11b
        mov al, byte [r9 + rax]
        xor byte [r8], al
        inc r8                        ; next character
        jmp ._11

    generate_iv:
        mov rax, 0x005a               ; syscall 0x005a (90) == NtQuerySystemTime
        lea rcx, [iv]                 ; Write PerformanceCounter in first bytes of IV
        lea r10, [iv]                 ; https://github.com/tinysec/windows-syscall-table/blob/16542bdcf0add03960a7b0a379af7a59ceb0b822/10.0.10240-sp0-windows-10-th1-1507/amd64/ssdt_sysenter.asm#L701
        syscall
        mov rax, 0x0031               ; syscall 0x0031 (49) == NtQueryPerformanceCounter
        xor rdx, rdx                  ; Don't write PerformanceFrequency
        lea rcx, [iv + 4]             ; Write PerformanceCounter in bytes of IV
        lea r10, [iv + 4]             ; https://github.com/tinysec/windows-syscall-table/blob/16542bdcf0add03960a7b0a379af7a59ceb0b822/10.0.10240-sp0-windows-10-th1-1507/amd64/ssdt_sysenter.asm#L701
        syscall
        lea r10, [iv]
        mov rcx, 64
        mov rax, qword [r10]          ; Last bytes for nanosecond and last bytes for PerformanceCounter are used to initialize random value for IV
._5:    mov r11, rax
        shl rax, 13
        xor rax, r11
        mov r11, rax
        shr rax, 7
        xor rax, r11
        mov r11, rax
        shl rax, 17
        xor rax, r11
        mov [r10 + rcx * 4 - 4], rax
        dec rcx
        test rcx, rcx
        jne ._5
        mov byte [r10 + 256], 0       ; end with null byte (257 characters = 256 characters + null byte)
        ret

    xor_key_iv:
        xor rax, rax
        lea r8, [key]
        lea r9, [iv]
._6:    mov r11, [r9 + rax]           ; 256 / 4 == 64, faster way (using 64 bit register) to xor all the key with iv than character (8 bit register) by character
        xor [r8 + rax], r11
        add al, 8
        test al, al
        jne ._6
        ret

    generate_key:
        mov r8, rcx
        mov r9, r8                    ; save first argument (string) address
        xor rdx, rdx                  ; dl = index1 = 0
        xor rax, rax                  ; al = i = 0
        xor rcx, rcx
        lea r11, [key]
._2:    add dl, byte [r11 + rax]
        mov cl, byte [r8]
        test cl, cl                   ; test character is not 0 (end of string)
        jne ._1
        mov r8, r9                    ; if character is 0 (end of string) got to the first character of the string
._1:    add dl, byte [r8]
        inc r8                        ; next character
        mov cl, byte [r11 + rdx]
        mov r10b, byte [r11 + rax]
        mov byte [r11 + rax], cl
        mov byte [r11 + rdx], r10b    ; value1, value2 = value2, value1
        inc al
        test al, al
        jne ._2                       ; loop 256 times
        ret

    reset_key:
        xor rax, rax
        lea r8, [key]
._7:    mov byte [r8 + rax], al
        inc rax
        test al, al
        jne ._7
        ret

    get_iv:
        lea rax, [iv]
        ret

    set_iv:
        lea r9, [iv]
        xor rax, rax
._8:    mov r11, [rcx + rax]
        mov [r9 + rax], r11
        add rax, 4
        test al, al
        jne ._8
        mov byte [r9 + 256], al       ; end with null byte (257 characters = 256 characters + null byte)
        ret

    encrypt:
        push r8
        push rdx
        call generate_key
        call generate_iv
        call xor_key_iv
        pop rcx
        pop rdx
        test rdx, rdx
        jne ._12
        call arc4_null_byte
        ret
._12:   call arc4
        ret

    decrypt:
        push r9
        push r8
        push rdx
        call generate_key
        pop rcx
        call set_iv
        call xor_key_iv
        pop rcx
        pop rdx
        call arc4
        ret

section .data
    key db 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0

section .bss
    iv resb 257
