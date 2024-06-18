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

; nasm -f elf64 rc4.asm
; gcc XXXXXXX.c rc4.o
; gcc -shared   rc4.o -o librc4.so

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
        mov r10, rsi                  ; length
        xor rdx, rdx                  ; dl = index1 = 0
        xor rcx, rcx                  ; cl = index2 = 0
        xor rax, rax
        xor r11, r11
        lea rsi, [key]
._4:    test r10, r10                 ; if length == 0: return;
        jne ._3
        ret
._3:    mov al, byte [rdi]
        dec r10                       ; length -= 1;
        inc dl
        add cl, byte [rsi + rdx]
        mov al, byte [rsi + rdx]
        mov r11b, byte [rsi + rcx]
        mov byte [rsi + rdx], r11b
        mov byte [rsi + rcx], al      ; value1, value2 = value2, value1
        add al, r11b
        mov al, byte [rsi + rax]
        xor byte [rdi], al
        inc rdi                       ; next character
        jmp ._4

    arc4_null_byte:
        xor rdx, rdx                  ; dl = index1 = 0
        xor rcx, rcx                  ; cl = index2 = 0
        xor rax, rax
        xor r11, r11
        lea rsi, [key]
._11:   mov al, byte [rdi]
        test al, al
        jne ._10                      ; if character == 0 (end of string) return else crypt character
        ret
._10:   inc dl
        add cl, byte [rsi + rdx]
        mov al, byte [rsi + rdx]
        mov r11b, byte [rsi + rcx]
        mov byte [rsi + rdx], r11b
        mov byte [rsi + rcx], al      ; value1, value2 = value2, value1
        add al, r11b
        mov al, byte [rsi + rax]
        xor byte [rdi], al
        inc rdi                       ; next character
        jmp ._11

    generate_iv:
        mov rax, 228                  ; syscall 228 == sys_clock_gettime
        xor rdi, rdi                  ; 0 == CLOCK_REALTIME
        lea rsi, [iv]
        syscall
        mov rcx, 64
        mov rax, qword [rsi + 8]      ; Nanosecond (pseudo random start number)
._5:    mov r11, rax
        shl rax, 13
        xor rax, r11
        mov r11, rax
        shr rax, 7
        xor rax, r11
        mov r11, rax
        shl rax, 17
        xor rax, r11
        mov [rsi + rcx * 4 - 4], rax
        dec rcx
        test rcx, rcx
        jne ._5
        mov byte [rsi + 256], 0       ; end with null byte (257 characters = 256 characters + null byte)
        ret

    xor_key_iv:
        xor rax, rax
        lea rdi, [key]
        lea rsi, [iv]
._6:    mov r11, [rsi + rax]          ; 256 / 4 == 64, faster way (using 64 bit register) to xor all the key with iv than character (8 bit register) by character
        xor [rdi + rax], r11
        add al, 8
        test al, al
        jne ._6
        ret

    generate_key:
        mov r11, rdi                  ; save first argument (string) address
        xor rdx, rdx                  ; dl = index1 = 0
        xor rax, rax                  ; al = i = 0
        xor rcx, rcx
        lea rsi, [key]
._2:    add dl, byte [rsi + rax]
        mov cl, byte [rdi]
        test cl, cl                   ; test character is not 0 (end of string)
        jne ._1
        mov rdi, r11                  ; if character is 0 (end of string) got to the first character of the string
._1:    add dl, byte [rdi]
        inc rdi                       ; next character
        mov cl, byte [rsi + rdx]
        mov ch, byte [rsi + rax]
        mov byte [rsi + rax], cl
        mov byte [rsi + rdx], ch      ; value1, value2 = value2, value1
        inc al
        test al, al
        jne ._2                       ; loop 256 times
        ret

    reset_key:
        xor rax, rax
        lea rdi, [key]
._7:    mov byte [rdi + rax], al
        inc rax
        test al, al
        jne ._7
        ret

    get_iv:
        lea rax, [iv]
        ret

    set_iv:
        lea rsi, [iv]
        xor rax, rax
._8:    mov r11, [rdi + rax]
        mov [rsi + rax], r11
        add rax, 4
        test al, al
        jne ._8
        mov byte [rsi + 256], al      ; end with null byte (257 characters = 256 characters + null byte)
        ret

    encrypt:
        push rdx
        push rsi
        call generate_key
        call generate_iv
        call xor_key_iv
        pop rdi
        pop rsi
        test rsi, rsi
        jne ._12
        call arc4_null_byte
        ret
._12:   call arc4
        ret

    decrypt:
        mov r10, rcx
        mov r8, rsi
        mov r9, rdx
        call generate_key
        mov rdi, r8
        call set_iv
        call xor_key_iv
        mov rdi, r9
        mov rsi, r10
        call arc4
        ret

section .data
    key db 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0

section .bss
    iv resb 257
