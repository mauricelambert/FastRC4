;	This file implements RC4 in ASM.
;	Copyright (C) 2023  Maurice Lambert

;	This program is free software: you can redistribute it and/or modify
;	it under the terms of the GNU General Public License as published by
;	the Free Software Foundation, either version 3 of the License, or
;	(at your option) any later version.

;	This program is distributed in the hope that it will be useful,
;	but WITHOUT ANY WARRANTY; without even the implied warranty of
;	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;	GNU General Public License for more details.

;	You should have received a copy of the GNU General Public License
;	along with this program.  If not, see <https://www.gnu.org/licenses/>.

global arc4, generate_iv, generate_key, xor_key_iv
global key, iv

default rel

section .text

	arc4:
		xor rdx, rdx				  ; dl = index1 = 0
		xor rcx, rcx				  ; cl = index2 = 0
		xor rax, rax
		xor rbx, rbx
		lea rsi, [key]
._4:	mov al, byte [rdi]
		test al, al
		jne ._3						  ; if character == 0 (end of string) return else crypt character
		ret
._3:	add dl, 1
		add cl, byte [rsi + rdx]
		mov al, byte [rsi + rdx]
		mov bl, byte [rsi + rcx]
		mov byte [rsi + rdx], bl
		mov byte [rsi + rcx], al	  ; value1, value2 = value2, value1
		add al, bl
		mov al, byte [rsi + rax]
		xor [rdi], al
		add rdi, 1					  ; next character
		jmp ._4

	generate_iv:
		mov rax, 228
		lea rdi, [rbp-16]
		mov rdi, 1
		lea rsi, [iv]
		syscall
		mov rcx, 64
._5:	mov rax, qword [rbp-8]
		mov rbx, rax
		shl rax, 13
		xor rax, rbx
		mov rbx, rax
		shr rax, 7
		xor rax, rbx
		mov rbx, rax
		shl rax, 17
		xor rax, rbx
		mov [rsi + rcx * 4 - 4], rax
		sub rcx, 1
		test rcx, rcx
		jne ._5
		mov byte [rsi + 256], 0
		ret

	xor_key_iv:
		xor rax, rax
		lea rdi, [key]
		lea rsi, [iv]
._6:	mov rbx, [rsi + rax]		  ; 256 / 4 == 64, faster way (using 64 bit register) to xor all the key with iv than character (8 bit register) by character
		xor [rdi + rax], rbx
		add al, 4
		test al, al
		jne ._6
		ret

	generate_key:
		mov rsi, rdi				  ; save first argument (string) address
		xor rdx, rdx				  ; dl = index1 = 0
		xor rax, rax				  ; al = i = 0
		xor rbx, rbx
		lea rcx, [key]
._2:	add dl, byte [rcx + rax]
		mov bl, byte [rdi]
		test bl, bl					  ; test character is not 0 (end of string)
		jne ._1
		mov rdi, rsi				  ; if character is 0 (end of string) got to the first character of the string
._1:	add dl, byte [rdi]
		add rdi, 1					  ; next character
		mov bl, byte [rcx + rdx]
		mov bh, byte [rcx + rax]
		mov [rcx + rax], bl
		mov [rcx + rdx], bh			  ; value1, value2 = value2, value1
		add al, 1
		test al, al
		jne ._2						  ; loop 256 times
		ret

section .data
	key db 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0

section .bss
	iv resb 257
