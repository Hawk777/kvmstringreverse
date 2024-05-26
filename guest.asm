bits 32

section .text start=0x10000000

; Store bytes into ascending positions of buffer, EDI pointing to next location
; to write.
mov ebx, buffer
mov edi, ebx
loadLoop:
; Read and store next byte.
in al, 42
stosb
; If read byte is zero, that marks end of input. Break out.
or al, al
jnz loadLoop

; EDI points to next location to write, which is just past the NUL.
dec edi
; EDI points at the NUL.
dec edi
; EDI points at the last legitimate character.
mov esi, edi
; ESI points at the last legitimate character.

; Walk backwards through the characters.
std
replyLoop:
; Read and output the next character, moving backwards.
lodsb
out 47, al
; If ESI < EBX (base of buffer), then break out.
cmp esi, ebx
jae replyLoop

; Stop execution.
hlt

section .bss start=0x20000000
buffer:
