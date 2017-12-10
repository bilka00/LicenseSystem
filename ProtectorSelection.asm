use32

include 'PROC32.INC'
include 'STRUCT.INC'
include 'USER32.INC'
include 'WSOCK32.INC'
mov eax, [fs:0x30]
mov eax, [eax+0Ch]
mov eax, [eax+14h]
mov eax, [eax]
mov eax, [eax]
mov ebx, [eax+10h]
mov eax, [ebx+3Ch]
mov eax, [eax+ebx+78h]
mov [exportDir+4227072], eax
add eax, ebx
mov esi, [eax+20h]
mov [namePtr+4227072], esi
mov edi, [eax+24h]
mov [ordPtr+4227072], edi
mov eax, [esi+ebx]
add esi, ebx
add eax, ebx
push _GetProcAddress+4227072
push eax
add edi, ebx
_check:
stdcall strcmpA
test eax,eax
jne _found
mov eax, [namePtr+4227072]
add eax, 4
mov [namePtr+4227072],eax
mov ecx,[ordPtr+4227072]
add ecx,2
mov [ordPtr+4227072], ecx
mov esi, [namePtr+4227072]
add esi,ebx
add eax,ebx
mov eax,[eax]
add eax,ebx
push _GetProcAddress+4227072
push eax
jmp _check
_found:
mov eax, [exportDir+4227072]
add eax, ebx
mov ecx, ebx
add ecx, [eax+1Ch]
mov edx, [ordPtr+4227072]
add edx, ebx
movzx eax, word ptr edx
mov ecx, [ecx+eax*4]
add ecx, ebx
mov [@GetProcAddress+4227072], ecx
mov [hKernel32+4227072], ebx
stdcall [@GetProcAddress+4227072], [hKernel32+4227072], _LoadLibraryA+4227072
mov [@LoadLibraryA+4227072], eax

stdcall [@LoadLibraryA+4227072], kernel32+4227072, [hKernel32+4227072]
mov [hKernel32+4227072], eax

stdcall [@LoadLibraryA+4227072], user32+4227072, [hUser32+4227072]
mov [hUser32+4227072], eax

stdcall [@LoadLibraryA+4227072], wsock32+4227072, [hWsock32+4227072]
mov [hWsock32+4227072], eax




stdcall GetSerialNumber

stdcall GetModuleHandleA,0
mov [wc.hInstance+4227072],eax
stdcall LoadIconA,0,IDI_APPLICATION
mov [wc.hIcon+4227072],eax
stdcall LoadCursorA,0,IDC_ARROW
mov [wc.hCursor+4227072],eax
stdcall RegisterClassA,wc+4227072
cmp eax,0
je error
mov [wc.lpfnWndProc+4227072], WindowProc+4227072
stdcall CreateWindowExA,0,class+4227072,title+4227072,WS_VISIBLE,128,128,256,196,0,0,[wc.hInstance+4227072],0
cmp eax,0
je error
mov [hwnd+4227072],eax
msg_loop:
stdcall GetMessageA,msg+4227072,0,0,0
cmp eax,0
je end_loop
stdcall IsDialogMessageA,[hwnd+4227072],msg+4227072
cmp eax,0
jne msg_loop
stdcall TranslateMessage,msg+4227072
stdcall DispatchMessageA,msg+4227072
jmp msg_loop

error:
stdcall ExitProcess, 0

end_loop:
stdcall ExitProcess, [msg.wParam+4227072]

proc GetSerialNumber
pusha
pushf
xor eax,eax
cpuid
mov dword[SourceKeyBuffer+4227072], ebx
mov dword[SourceKeyBuffer+4+4227072], edx
mov dword[SourceKeyBuffer+8+4227072], ecx

xor eax,eax
inc eax
cpuid
mov dword[SourceKeyBuffer+12+4227072], edx
mov dword[SourceKeyBuffer+16+4227072], ecx

mov eax, 7
xor ecx, ecx
cpuid
mov dword[SourceKeyBuffer+20+4227072], ecx
mov dword[SourceKeyBuffer+24+4227072], edx
mov dword[SourceKeyBuffer+28+4227072], ebx

stdcall SHA1, SourceKeyBuffer+4227072, 100
stdcall  wsprintfA, RegistryKey+4227072, sha_mask+4227072, [SHA1_h0+4227072], [SHA1_h1+4227072], [SHA1_h2+4227072], [SHA1_h3+4227072], [SHA1_h4+4227072]
add     esp,7*4

popf
popa
ret
endp

proc	 strcmpA,szOne,szTwo
    pusha
    pushf
    mov esi, [szOne]
    mov edi, [szTwo]
    stdcall strlenA, edi
    inc eax
    mov ecx, eax
    repe cmpsb
    je @cmpValid
    popf
    popa
    mov eax, 0
    ret
    @cmpValid:
    popf
    popa
    mov eax, 1
    ret
endp

proc strlenA lData:dword
push edi
mov edi,[lData]
xor eax,eax
@1:
inc eax
cmp byte[eax+edi],0
jnz @1
pop edi
ret
endp

;-----------------------------------------------------
proc WebRequest link, WebResultBuffer
       pusha
       pushf
       stdcall WSAStartup, 0101h, wsadata+4227072
       stdcall  gethostbyname, [link]
       or     eax, eax
       jz     bad_hostname
              virtual at eax
               .host hostent
              end virtual
       mov    eax, [.host.h_addr_list]
       mov    eax, [eax]
       mov    eax, [eax]
       mov     [saddr.sin_addr+4227072], eax
       mov    al,00
       mov    ah,80
       mov     [saddr.sin_port+4227072], ax
       mov     [saddr.sin_family+4227072], AF_INET
       stdcall  socket, AF_INET, SOCK_STREAM, IPPROTO_TCP
       mov     [hSock+4227072], eax
       xchg    eax, esi
       stdcall  connect, esi, saddr+4227072, sizesaddr+4227072
       stdcall strlenA, sender+4227072
       stdcall  send, esi, sender+4227072,eax,0
       stdcall  recv, esi, [WebResultBuffer], 1024, 0
       .connectSucceeded:
       stdcall closesocket,esi
       stdcall WSACleanup
       popf
       popa
       ret
       bad_hostname:
       stdcall ExitProcess,0
       ret
endp

proc DecodeSelectionAndJMP DecoderKey

mov ebx, 4198399
mov ecx, 124
mov edx, [DecoderKey]
EncoderLoop0:
xor eax,eax
mov al, byte [ebx+ecx]
xor al, byte[edx+0]
add al, byte[edx+1]
xor al, byte[edx+2]
sub al, byte[edx+3]
xor al, byte[edx+4]
sub al, byte[edx+5]
xor al, byte[edx+6]
sub al, byte[edx+7]
xor al, byte[edx+8]
sub al, byte[edx+9]
xor al, byte[edx+10]
add al, byte[edx+11]
xor al, byte[edx+12]
add al, byte[edx+13]
xor al, byte[edx+14]
sub al, byte[edx+15]
xor al, byte[edx+16]
sub al, byte[edx+17]
xor al, byte[edx+18]
add al, byte[edx+19]
mov byte [ebx+ecx], al
loop EncoderLoop0
stdcall calc_CRC32, 4198400, 124, -1, 1
cmp eax, 2743339278
jne @Decoder_Exit

mov ebx, 4202495
mov ecx, 47
mov edx, [DecoderKey]
EncoderLoop1:
xor eax,eax
mov al, byte [ebx+ecx]
xor al, byte[edx+0]
add al, byte[edx+1]
xor al, byte[edx+2]
sub al, byte[edx+3]
xor al, byte[edx+4]
sub al, byte[edx+5]
xor al, byte[edx+6]
sub al, byte[edx+7]
xor al, byte[edx+8]
sub al, byte[edx+9]
xor al, byte[edx+10]
add al, byte[edx+11]
xor al, byte[edx+12]
add al, byte[edx+13]
xor al, byte[edx+14]
sub al, byte[edx+15]
xor al, byte[edx+16]
sub al, byte[edx+17]
xor al, byte[edx+18]
add al, byte[edx+19]
mov byte [ebx+ecx], al
loop EncoderLoop1
stdcall calc_CRC32, 4202496, 47, -1, 1
cmp eax, 2487612981
jne @Decoder_Exit

jmp -28672
@Decoder_Exit:
stdcall ExitProcess, 0
endp


;---------------------------------
proc WindowProc hwnd,wmsg,wparam,lparam
  push ebx esi edi
  cmp [wmsg],WM_CREATE
  je .wmcreate
  cmp [wmsg],WM_COMMAND
  je .wmcommand
  cmp [wmsg],WM_DESTROY
  je .wmdestroy
.defwndproc:
  stdcall DefWindowProcA,[hwnd],[wmsg],[wparam],[lparam]
  jmp .finish
.wmcreate:
  stdcall CreateWindowExA,0,ClassButton+4227072,LoginButtonText+4227072,WS_VISIBLE+WS_CHILD+ BS_PUSHBUTTON+WS_TABSTOP,20,100,100,40,[hwnd],1000,[wc.hInstance+4227072],0
  stdcall CreateWindowExA,0,ClassButton+4227072,ExitButtonText+4227072,WS_VISIBLE+WS_CHILD+ BS_PUSHBUTTON+WS_TABSTOP,130,100,100,40,[hwnd],1001,[wc.hInstance+4227072],0

  stdcall CreateWindowExA,0,classe+4227072,0,WS_VISIBLE+WS_CHILD+WS_BORDER+WS_TABSTOP+ES_AUTOHSCROLL,10,50,230,20,[hwnd],1002,[wc.hInstance+4227072],0
  mov [hwndKeyEdit+4227072],eax
  stdcall CreateWindowExA,0,classe+4227072,RegistryKey+4227072,WS_VISIBLE+WS_CHILD+WS_BORDER+WS_TABSTOP+ES_AUTOHSCROLL+ES_READONLY,10,25,230,20,[hwnd],1004,[wc.hInstance+4227072], 0
  mov [hwndHWIDEdit+4227072],eax
  stdcall SetFocus,[hwndKeyEdit+4227072]
  jmp .finish
.wmcommand:
  cmp [wparam],1000
  je .LoginButton
  cmp [wparam],1001
  je .ExitButton
  jmp .finish
.LoginButton:
  mov word[LoginText-2+4227072], 0x0A0D
  stdcall SendMessageA,[hwndKeyEdit+4227072],WM_GETTEXT,100,LoginText+4227072
  stdcall WebRequest, hostname+4227072, WebResultBuffer+4227072
  stdcall DestroyWindow, [hwnd]
  stdcall DecodeSelectionAndJMP, WebResultBuffer+4227072
  jmp .finish
.ExitButton:
  stdcall ExitProcess, 0
  jmp .finish
.wmdestroy:
  stdcall PostQuitMessage,0
  mov eax,0
.finish:
  pop edi esi ebx
  ret
endp


proc calc_CRC32 lData:dword, dLen:dword, dCRC32:dword, dFlag:dword
        push    ebx ecx edx esi

        mov     edx,[dCRC32]
        mov     esi,[lData]
        mov     ecx,[dLen]
        xor     eax,eax
calc_crc32:
        lodsb
        mov     ebx,edx
        and     ebx,0FFh
        xor     bl,al
        shr     edx,8
        and     edx,0FFFFFFh
        push    ecx
        mov     ecx,8
do_polynom:
        shr     ebx,1
        jnc     @f
        xor     ebx,0EDB88320h
@@:
        loop    do_polynom
        pop     ecx
        xor     edx,ebx
        loop    calc_crc32
        mov     eax,edx
        cmp     [dFlag],1
        jne     @f
        xor     eax,-1
@@:
        pop     esi edx ecx ebx
        ret
endp


proc    SHA1 lpData:DWORD, dSize:DWORD
        locals
                len     dd ?
                padding dd ?
                index   dd ?
        endl
        pusha
        mov     [SHA1_h0+4227072],0x67452301
        mov     [SHA1_h1+4227072],0xEFCDAB89
        mov     [SHA1_h2+4227072],0x98BADCFE
        mov     [SHA1_h3+4227072],0x10325476
        mov     [SHA1_h4+4227072],0xC3D2E1F0

        mov     eax,[dSize]
        push    eax
        shr     eax,6
        mov     [len],eax
        pop     eax

        and     eax,3Fh
        mov     [padding],eax
        mov     [index],0
.main_loop:
        mov     eax,[index]
        cmp     eax,[len]
        je      .main_done

        shl     eax,6
        mov     esi,[lpData]
        add     esi,eax
        mov     edi,SHA1_Buff+4227072
        mov     ecx,16
        rep     movsd

        stdcall SHA1_BE
        stdcall SHA1_Calc

        inc     [index]
        jmp     .main_loop
.main_done:
        xor     eax,eax
        mov     edi,SHA1_Buff+4227072
        mov     ecx,16
        rep     stosd

        mov     eax,[index]
        shl     eax,6
        mov     esi,[lpData]
        add     esi,eax
        mov     edi,SHA1_Buff+4227072
        mov     ecx,[padding]
        rep     movsb
        mov     al,80h
        stosb

        stdcall SHA1_BE
        cmp     [padding],56
        jae     @f

        mov     eax,[dSize]
        shl     eax,3
        mov     dword [SHA1_Buff+60+4227072],eax

        stdcall SHA1_Calc
        jmp     .sha1_done
@@:
        stdcall SHA1_Calc

        mov     edi,SHA1_Buff+4227072
        xor     eax,eax
        mov     ecx,15
        rep     stosd

        mov     eax,[dSize]
        shl     eax,3
        stosd

        stdcall SHA1_Calc

.sha1_done:
        popa
        ret
endp

proc    SHA1_BE
        pusha

        mov     ecx,16
        mov     esi,SHA1_Buff+4227072
        mov     edi,esi
@@:
        lodsd
        bswap   eax
        stosd
        loop    @b

        popa
        ret
endp

proc    SHA1_Calc
        pusha

        mov     eax,[SHA1_h0+4227072]
        mov     [SHA1_a+4227072],eax
        mov     eax,[SHA1_h1+4227072]
        mov     [SHA1_b+4227072],eax
        mov     eax,[SHA1_h2+4227072]
        mov     [SHA1_c+4227072],eax
        mov     eax,[SHA1_h3+4227072]
        mov     [SHA1_d+4227072],eax
        mov     eax,[SHA1_h4+4227072]
        mov     [SHA1_e+4227072],eax

        xor     ecx,ecx ; i
.cycle_loop:
        mov     eax,ecx
        shl     eax,2

        cmp     ecx,16
        jae     @f

        mov     ebx,dword [SHA1_Buff+eax+4227072]
        mov     dword [SHA1_W+eax+4227072],ebx
        jmp     .@1
@@:
        mov     eax,ecx
        sub     eax,3
        shl     eax,2
        mov     ebx,dword [SHA1_W+eax+4227072]

        mov     eax,ecx
        sub     eax,8
        shl     eax,2
        xor     ebx,dword [SHA1_W+eax+4227072]

        mov     eax,ecx
        sub     eax,14
        shl     eax,2
        xor     ebx,dword [SHA1_W+eax+4227072]

        mov     eax,ecx
        sub     eax,16
        shl     eax,2
        xor     ebx,dword [SHA1_W+eax+4227072]

        rol     ebx,1

        mov     eax,ecx
        shl     eax,2
        mov     dword [SHA1_W+eax+4227072],ebx
.@1:
        mov     edx,[SHA1_a+4227072]
        rol     edx,5

        cmp     ecx,20
        jae     @f
        mov     eax,[SHA1_b+4227072]
        and     eax,[SHA1_c+4227072]
        mov     ebx,[SHA1_b+4227072]
        not     ebx
        and     ebx,[SHA1_d+4227072]
        or      eax,ebx
        add     edx,0x5A827999
        jmp     .@2
@@:
        cmp     ecx,40
        jae     @f
        mov     eax,[SHA1_b+4227072]
        xor     eax,[SHA1_c+4227072]
        xor     eax,[SHA1_d+4227072]
        add     edx,0x6ED9EBA1
        jmp     .@2
@@:
        cmp     ecx,60
        jae     @f
        mov     eax,[SHA1_b+4227072]
        and     eax,[SHA1_c+4227072]
        mov     ebx,[SHA1_b+4227072]
        and     ebx,[SHA1_d+4227072]
        or      eax,ebx
        mov     ebx,[SHA1_c+4227072]
        and     ebx,[SHA1_d+4227072]
        or      eax,ebx
        add     edx,0x8F1BBCDC
        jmp     .@2
@@:
        mov     eax,[SHA1_b+4227072]
        xor     eax,[SHA1_c+4227072]
        xor     eax,[SHA1_d+4227072]
        add     edx,0xCA62C1D6
.@2:
        add     edx,eax
        add     edx,[SHA1_e+4227072]

        mov     eax,ecx
        shl     eax,2
        add     edx,[SHA1_W+eax+4227072]

        mov     eax,[SHA1_d+4227072]
        mov     [SHA1_e+4227072],eax

        mov     eax,[SHA1_c+4227072]
        mov     [SHA1_d+4227072],eax

        mov     eax,[SHA1_b+4227072]
        rol     eax,30
        mov     [SHA1_c+4227072],eax

        mov     eax,[SHA1_a+4227072]
        mov     [SHA1_b+4227072],eax

        mov     [SHA1_a+4227072],edx

        inc     ecx
        cmp     ecx,80
        jne     .cycle_loop

        mov     eax,[SHA1_a+4227072]
        add     [SHA1_h0+4227072],eax
        mov     eax,[SHA1_b+4227072]
        add     [SHA1_h1+4227072],eax
        mov     eax,[SHA1_c+4227072]
        add     [SHA1_h2+4227072],eax
        mov     eax,[SHA1_d+4227072]
        add     [SHA1_h3+4227072],eax
        mov     eax,[SHA1_e+4227072]
        add     [SHA1_h4+4227072],eax

        popa
        ret
endp
fill db 2 dup(0)
SHA1_h0         dd ?
SHA1_h1         dd ?
SHA1_h2         dd ?
SHA1_h3         dd ?
SHA1_h4         dd ?

SHA1_a          dd ?
SHA1_b          dd ?
SHA1_c          dd ?
SHA1_d          dd ?
SHA1_e          dd ?
SHA1_W          rd 80
SHA1_Buff       rb 64

sha_mask db '%.8x%.8x%.8x%.8x%.8x',0



proc ExitProcess
cmp [@ExitProcess+4227072],0
jnz flag_not_setExitProcess
stdcall [@GetProcAddress+4227072], [hKernel32+4227072], _ExitProcess+4227072
mov [@ExitProcess+4227072], eax
flag_not_setExitProcess:
jmp [@ExitProcess+4227072]
endp

proc CreateThread
cmp [@CreateThread+4227072],0
jnz flag_not_setCreateThread
stdcall [@GetProcAddress+4227072], [hKernel32+4227072], _CreateThread+4227072
mov [@CreateThread+4227072], eax
flag_not_setCreateThread:
jmp [@CreateThread+4227072]
endp

proc MessageBoxA
cmp [@MessageBoxA+4227072],0
jnz flag_not_setMessageBoxA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _MessageBoxA+4227072
mov [@MessageBoxA+4227072], eax
flag_not_setMessageBoxA:
jmp [@MessageBoxA+4227072]
endp

proc GetModuleHandleA
cmp [@GetModuleHandleA+4227072],0
jnz flag_not_setGetModuleHandleA
stdcall [@GetProcAddress+4227072], [hKernel32+4227072], _GetModuleHandleA+4227072
mov [@GetModuleHandleA+4227072], eax
flag_not_setGetModuleHandleA:
jmp [@GetModuleHandleA+4227072]
endp

proc LoadIconA
cmp [@LoadIconA+4227072],0
jnz flag_not_setLoadIconA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _LoadIconA+4227072
mov [@LoadIconA+4227072], eax
flag_not_setLoadIconA:
jmp [@LoadIconA+4227072]
endp

proc LoadCursorA
cmp [@LoadCursorA+4227072],0
jnz flag_not_setLoadCursorA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _LoadCursorA+4227072
mov [@LoadCursorA+4227072], eax
flag_not_setLoadCursorA:
jmp [@LoadCursorA+4227072]
endp

proc GetMessageA
cmp [@GetMessageA+4227072],0
jnz flag_not_setGetMessageA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _GetMessageA+4227072
mov [@GetMessageA+4227072], eax
flag_not_setGetMessageA:
jmp [@GetMessageA+4227072]
endp

proc RegisterClassA
cmp [@RegisterClassA+4227072],0
jnz flag_not_setRegisterClassA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _RegisterClassA+4227072
mov [@RegisterClassA+4227072], eax
flag_not_setRegisterClassA:
jmp [@RegisterClassA+4227072]
endp

proc CreateWindowExA
cmp [@CreateWindowExA+4227072],0
jnz flag_not_setCreateWindowExA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _CreateWindowExA+4227072
mov [@CreateWindowExA+4227072], eax
flag_not_setCreateWindowExA:
jmp [@CreateWindowExA+4227072]
endp

proc IsDialogMessageA
cmp [@IsDialogMessageA+4227072],0
jnz flag_not_setIsDialogMessageA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _IsDialogMessageA+4227072
mov [@IsDialogMessageA+4227072], eax
flag_not_setIsDialogMessageA:
jmp [@IsDialogMessageA+4227072]
endp

proc TranslateMessage
cmp [@TranslateMessage+4227072],0
jnz flag_not_setTranslateMessage
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _TranslateMessage+4227072
mov [@TranslateMessage+4227072], eax
flag_not_setTranslateMessage:
jmp [@TranslateMessage+4227072]
endp

proc DispatchMessageA
cmp [@DispatchMessageA+4227072],0
jnz flag_not_setDispatchMessageA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _DispatchMessageA+4227072
mov [@DispatchMessageA+4227072], eax
flag_not_setDispatchMessageA:
jmp [@DispatchMessageA+4227072]
endp

proc DefWindowProcA
cmp [@DefWindowProcA+4227072],0
jnz flag_not_setDefWindowProcA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _DefWindowProcA+4227072
mov [@DefWindowProcA+4227072], eax
flag_not_setDefWindowProcA:
jmp [@DefWindowProcA+4227072]
endp

proc SetFocus
cmp [@SetFocus+4227072],0
jnz flag_not_setSetFocus
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _SetFocus+4227072
mov [@SetFocus+4227072], eax
flag_not_setSetFocus:
jmp [@SetFocus+4227072]
endp

proc SendMessageA
cmp [@SendMessageA+4227072],0
jnz flag_not_setSendMessageA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _SendMessageA+4227072
mov [@SendMessageA+4227072], eax
flag_not_setSendMessageA:
jmp [@SendMessageA+4227072]
endp

proc PostQuitMessage
cmp [@PostQuitMessage+4227072],0
jnz flag_not_setPostQuitMessage
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _PostQuitMessage+4227072
mov [@PostQuitMessage+4227072], eax
flag_not_setPostQuitMessage:
jmp [@PostQuitMessage+4227072]
endp

proc WSAStartup
cmp [@WSAStartup+4227072],0
jnz flag_not_setWSAStartup
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _WSAStartup+4227072
mov [@WSAStartup+4227072], eax
flag_not_setWSAStartup:
jmp [@WSAStartup+4227072]
endp

proc socket
cmp [@socket+4227072],0
jnz flag_not_setsocket
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _socket+4227072
mov [@socket+4227072], eax
flag_not_setsocket:
jmp [@socket+4227072]
endp

proc connect
cmp [@connect+4227072],0
jnz flag_not_setconnect
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _connect+4227072
mov [@connect+4227072], eax
flag_not_setconnect:
jmp [@connect+4227072]
endp

proc gethostbyname
cmp [@gethostbyname+4227072],0
jnz flag_not_setgethostbyname
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _gethostbyname+4227072
mov [@gethostbyname+4227072], eax
flag_not_setgethostbyname:
jmp [@gethostbyname+4227072]
endp

proc send
cmp [@send+4227072],0
jnz flag_not_setsend
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _send+4227072
mov [@send+4227072], eax
flag_not_setsend:
jmp [@send+4227072]
endp

proc recv
cmp [@recv+4227072],0
jnz flag_not_setrecv
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _recv+4227072
mov [@recv+4227072], eax
flag_not_setrecv:
jmp [@recv+4227072]
endp

proc closesocket
cmp [@closesocket+4227072],0
jnz flag_not_setclosesocket
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _closesocket+4227072
mov [@closesocket+4227072], eax
flag_not_setclosesocket:
jmp [@closesocket+4227072]
endp

proc WSACleanup
cmp [@WSACleanup+4227072],0
jnz flag_not_setWSACleanup
stdcall [@GetProcAddress+4227072], [hWsock32+4227072], _WSACleanup+4227072
mov [@WSACleanup+4227072], eax
flag_not_setWSACleanup:
jmp [@WSACleanup+4227072]
endp

proc GetComputerNameA
cmp [@GetComputerNameA+4227072],0
jnz flag_not_setGetComputerNameA
stdcall [@GetProcAddress+4227072], [hKernel32+4227072], _GetComputerNameA+4227072
mov [@GetComputerNameA+4227072], eax
flag_not_setGetComputerNameA:
jmp [@GetComputerNameA+4227072]
endp

proc wsprintfA
cmp [@wsprintfA+4227072],0
jnz flag_not_setwsprintfA
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _wsprintfA+4227072
mov [@wsprintfA+4227072], eax
flag_not_setwsprintfA:
jmp [@wsprintfA+4227072]
endp

proc DestroyWindow
cmp [@DestroyWindow+4227072],0
jnz flag_not_setDestroyWindow
stdcall [@GetProcAddress+4227072], [hUser32+4227072], _DestroyWindow+4227072
mov [@DestroyWindow+4227072], eax
flag_not_setDestroyWindow:
jmp [@DestroyWindow+4227072]
endp



;---------------------------------------
;DecodeKey db "MY14OYD2VBP4S0283J2O", 0
;---------------------------------------
namePtr dd 0
ordPtr dd 0
exportDir dd 0
;===========================================================
wc WNDCLASS 0,WindowProc+4227072,0,0,0,0,0,COLOR_BTNFACE+1,0,class+4227072
class db 'LicSystem',0
title db 'Please input your login',0
ClassButton db 'BUTTON',0
classe db 'EDIT',0
classs db 'STATIC',0
LoginButtonText db 'Login',0
ExitButtonText db 'Exit',0
hwnd dd ?
hwndKeyEdit dd ?
hwndHWIDEdit dd ?
hwndc dd ?

msg MSG
;==========================================================
 SourceKeyBuffer rb 100
 IPPROTO_TCP  = 6
 wsadata WSADATA
 _caption db 'Client application',0
 _hostname db 'Wrong hostname',0

  hostname db '51.255.161.232',0
  ;hostname db 'localhost',0
  hSock dd ?
  saddr sockaddr_in
  sizesaddr = $-saddr

  WebResultBuffer rb 128
  sender        db "4V9NP4QPEQHBP401VYV0WTGENYS1H5OM84KJEZ7ETTK8POTEXL",13,10
  RegistryKey rb 40
  db 13,10
  LoginText rb 32
;==========================================================

kernel32 db "kernel32.dll", 0
hKernel32 dd ?, 0

user32 db "user32.dll", 0
hUser32 dd ?, 0

wsock32 db "wsock32.dll", 0
hWsock32 dd ?, 0



_GetProcAddress db "GetProcAddress", 0
@GetProcAddress dd ?

_LoadLibraryA db "LoadLibraryA", 0
@LoadLibraryA dd ?

_ExitProcess db "ExitProcess", 0
@ExitProcess dd ?

_CreateThread db "CreateThread", 0
@CreateThread dd ?

_MessageBoxA db "MessageBoxA", 0
@MessageBoxA dd ?

_GetModuleHandleA db "GetModuleHandleA", 0
@GetModuleHandleA dd ?

_LoadIconA db "LoadIconA", 0
@LoadIconA dd ?

_LoadCursorA db "LoadCursorA", 0
@LoadCursorA dd ?

_GetMessageA db "GetMessageA", 0
@GetMessageA dd ?

_RegisterClassA db "RegisterClassA", 0
@RegisterClassA dd ?

_CreateWindowExA db "CreateWindowExA", 0
@CreateWindowExA dd ?

_IsDialogMessageA db "IsDialogMessageA", 0
@IsDialogMessageA dd ?

_TranslateMessage db "TranslateMessage", 0
@TranslateMessage dd ?

_DispatchMessageA db "DispatchMessageA", 0
@DispatchMessageA dd ?

_DefWindowProcA db "DefWindowProcA", 0
@DefWindowProcA dd ?

_SetFocus db "SetFocus", 0
@SetFocus dd ?

_SendMessageA db "SendMessageA", 0
@SendMessageA dd ?

_PostQuitMessage db "PostQuitMessage", 0
@PostQuitMessage dd ?

_WSAStartup db "WSAStartup", 0
@WSAStartup dd ?

_socket db "socket", 0
@socket dd ?

_connect db "connect", 0
@connect dd ?

_gethostbyname db "gethostbyname", 0
@gethostbyname dd ?

_send db "send", 0
@send dd ?

_recv db "recv", 0
@recv dd ?

_closesocket db "closesocket", 0
@closesocket dd ?

_WSACleanup db "WSACleanup", 0
@WSACleanup dd ?

_GetComputerNameA db "GetComputerNameA", 0
@GetComputerNameA dd ?

_wsprintfA db "wsprintfA", 0
@wsprintfA dd ?

_DestroyWindow db "DestroyWindow", 0
@DestroyWindow dd ?

