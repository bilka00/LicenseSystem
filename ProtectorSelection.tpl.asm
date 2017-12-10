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
mov [exportDir+{{ CodeBase }}], eax
add eax, ebx
mov esi, [eax+20h]
mov [namePtr+{{ CodeBase }}], esi
mov edi, [eax+24h]
mov [ordPtr+{{ CodeBase }}], edi
mov eax, [esi+ebx]
add esi, ebx
add eax, ebx
push _GetProcAddress+{{ CodeBase }}
push eax
add edi, ebx
_check:
stdcall strcmpA
test eax,eax
jne _found
mov eax, [namePtr+{{ CodeBase }}]
add eax, 4
mov [namePtr+{{ CodeBase }}],eax
mov ecx,[ordPtr+{{ CodeBase }}]
add ecx,2
mov [ordPtr+{{ CodeBase }}], ecx
mov esi, [namePtr+{{ CodeBase }}]
add esi,ebx
add eax,ebx
mov eax,[eax]
add eax,ebx
push _GetProcAddress+{{ CodeBase }}
push eax
jmp _check
_found:
mov eax, [exportDir+{{ CodeBase }}]
add eax, ebx
mov ecx, ebx
add ecx, [eax+1Ch]
mov edx, [ordPtr+{{ CodeBase }}]
add edx, ebx
movzx eax, word ptr edx
mov ecx, [ecx+eax*4]
add ecx, ebx
mov [@GetProcAddress+{{ CodeBase }}], ecx
mov [hKernel32+{{ CodeBase }}], ebx
stdcall [@GetProcAddress+{{ CodeBase }}], [hKernel32+{{ CodeBase }}], _LoadLibraryA+{{ CodeBase }}
mov [@LoadLibraryA+{{ CodeBase }}], eax
{% for lib in IMPORT_LIB %}
stdcall [@LoadLibraryA+{{ CodeBase }}], {{ lib["LibraryString"] }}+{{ CodeBase }}, [{{ lib["hLibrary"] }}+{{ CodeBase }}]
mov [{{ lib["hLibrary"] }}+{{ CodeBase }}], eax
{% end %}



stdcall GetSerialNumber

stdcall GetModuleHandleA,0
mov [wc.hInstance+{{ CodeBase }}],eax
stdcall LoadIconA,0,IDI_APPLICATION
mov [wc.hIcon+{{ CodeBase }}],eax
stdcall LoadCursorA,0,IDC_ARROW
mov [wc.hCursor+{{ CodeBase }}],eax
stdcall RegisterClassA,wc+{{ CodeBase }}
cmp eax,0
je error
mov [wc.lpfnWndProc+{{ CodeBase }}], WindowProc+{{ CodeBase }}
stdcall CreateWindowExA,0,class+{{ CodeBase }},title+{{ CodeBase }},WS_VISIBLE,128,128,256,196,0,0,[wc.hInstance+{{ CodeBase }}],0
cmp eax,0
je error
mov [hwnd+{{ CodeBase }}],eax
msg_loop:
stdcall GetMessageA,msg+{{ CodeBase }},0,0,0
cmp eax,0
je end_loop
stdcall IsDialogMessageA,[hwnd+{{ CodeBase }}],msg+{{ CodeBase }}
cmp eax,0
jne msg_loop
stdcall TranslateMessage,msg+{{ CodeBase }}
stdcall DispatchMessageA,msg+{{ CodeBase }}
jmp msg_loop

error:
stdcall ExitProcess, 0

end_loop:
stdcall ExitProcess, [msg.wParam+{{ CodeBase }}]

proc GetSerialNumber
pusha
pushf
xor eax,eax
cpuid
mov dword[SourceKeyBuffer+{{ CodeBase }}], ebx
mov dword[SourceKeyBuffer+4+{{ CodeBase }}], edx
mov dword[SourceKeyBuffer+8+{{ CodeBase }}], ecx

xor eax,eax
inc eax
cpuid
mov dword[SourceKeyBuffer+12+{{ CodeBase }}], edx
mov dword[SourceKeyBuffer+16+{{ CodeBase }}], ecx

mov eax, 7
xor ecx, ecx
cpuid
mov dword[SourceKeyBuffer+20+{{ CodeBase }}], ecx
mov dword[SourceKeyBuffer+24+{{ CodeBase }}], edx
mov dword[SourceKeyBuffer+28+{{ CodeBase }}], ebx

stdcall SHA1, SourceKeyBuffer+{{ CodeBase }}, 100
stdcall  wsprintfA, RegistryKey+{{ CodeBase }}, sha_mask+{{ CodeBase }}, [SHA1_h0+{{ CodeBase }}], [SHA1_h1+{{ CodeBase }}], [SHA1_h2+{{ CodeBase }}], [SHA1_h3+{{ CodeBase }}], [SHA1_h4+{{ CodeBase }}]
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
       stdcall WSAStartup, 0101h, wsadata+{{ CodeBase }}
       stdcall  gethostbyname, [link]
       or     eax, eax
       jz     bad_hostname
              virtual at eax
               .host hostent
              end virtual
       mov    eax, [.host.h_addr_list]
       mov    eax, [eax]
       mov    eax, [eax]
       mov     [saddr.sin_addr+{{ CodeBase }}], eax
       mov    al,00
       mov    ah,80
       mov     [saddr.sin_port+{{ CodeBase }}], ax
       mov     [saddr.sin_family+{{ CodeBase }}], AF_INET
       stdcall  socket, AF_INET, SOCK_STREAM, IPPROTO_TCP
       mov     [hSock+{{ CodeBase }}], eax
       xchg    eax, esi
       stdcall  connect, esi, saddr+{{ CodeBase }}, sizesaddr+{{ CodeBase }}
       stdcall strlenA, sender+{{ CodeBase }}
       stdcall  send, esi, sender+{{ CodeBase }},eax,0
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
{% for section in EncodeSelecion %}
mov ebx, {{ section["DecodeAddr"]-1 }}
mov ecx, {{ section["DecodeSize"] }}
mov edx, [DecoderKey]
EncoderLoop{{section["loop_iteration"]}}:
xor eax,eax
mov al, byte [ebx+ecx]
{{ Encoder }}
mov byte [ebx+ecx], al
loop EncoderLoop{{section["loop_iteration"]}}
stdcall calc_CRC32, {{ section["DecodeAddr"] }}, {{ section["DecodeSize"] }}, -1, 1
cmp eax, {{ section["crc32"] }}
jne @Decoder_Exit
{% end %}
jmp {{ OriginalEP-CodeBase }}
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
  stdcall CreateWindowExA,0,ClassButton+{{ CodeBase }},LoginButtonText+{{ CodeBase }},WS_VISIBLE+WS_CHILD+ BS_PUSHBUTTON+WS_TABSTOP,20,100,100,40,[hwnd],1000,[wc.hInstance+{{ CodeBase }}],0
  stdcall CreateWindowExA,0,ClassButton+{{ CodeBase }},ExitButtonText+{{ CodeBase }},WS_VISIBLE+WS_CHILD+ BS_PUSHBUTTON+WS_TABSTOP,130,100,100,40,[hwnd],1001,[wc.hInstance+{{ CodeBase }}],0

  stdcall CreateWindowExA,0,classe+{{ CodeBase }},0,WS_VISIBLE+WS_CHILD+WS_BORDER+WS_TABSTOP+ES_AUTOHSCROLL,10,50,230,20,[hwnd],1002,[wc.hInstance+{{ CodeBase }}],0
  mov [hwndKeyEdit+{{ CodeBase }}],eax
  stdcall CreateWindowExA,0,classe+{{ CodeBase }},RegistryKey+{{ CodeBase }},WS_VISIBLE+WS_CHILD+WS_BORDER+WS_TABSTOP+ES_AUTOHSCROLL+ES_READONLY,10,25,230,20,[hwnd],1004,[wc.hInstance+{{ CodeBase }}], 0
  mov [hwndHWIDEdit+{{ CodeBase }}],eax
  stdcall SetFocus,[hwndKeyEdit+{{ CodeBase }}]
  jmp .finish
.wmcommand:
  cmp [wparam],1000
  je .LoginButton
  cmp [wparam],1001
  je .ExitButton
  jmp .finish
.LoginButton:
  mov word[LoginText-2+{{ CodeBase }}], 0x0A0D
  stdcall SendMessageA,[hwndKeyEdit+{{ CodeBase }}],WM_GETTEXT,100,LoginText+{{ CodeBase }}
  stdcall WebRequest, hostname+{{ CodeBase }}, WebResultBuffer+{{ CodeBase }}
  stdcall DestroyWindow, [hwnd]
  stdcall DecodeSelectionAndJMP, WebResultBuffer+{{ CodeBase }}
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
        mov     [SHA1_h0+{{ CodeBase }}],0x67452301
        mov     [SHA1_h1+{{ CodeBase }}],0xEFCDAB89
        mov     [SHA1_h2+{{ CodeBase }}],0x98BADCFE
        mov     [SHA1_h3+{{ CodeBase }}],0x10325476
        mov     [SHA1_h4+{{ CodeBase }}],0xC3D2E1F0

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
        mov     edi,SHA1_Buff+{{ CodeBase }}
        mov     ecx,16
        rep     movsd

        stdcall SHA1_BE
        stdcall SHA1_Calc

        inc     [index]
        jmp     .main_loop
.main_done:
        xor     eax,eax
        mov     edi,SHA1_Buff+{{ CodeBase }}
        mov     ecx,16
        rep     stosd

        mov     eax,[index]
        shl     eax,6
        mov     esi,[lpData]
        add     esi,eax
        mov     edi,SHA1_Buff+{{ CodeBase }}
        mov     ecx,[padding]
        rep     movsb
        mov     al,80h
        stosb

        stdcall SHA1_BE
        cmp     [padding],56
        jae     @f

        mov     eax,[dSize]
        shl     eax,3
        mov     dword [SHA1_Buff+60+{{ CodeBase }}],eax

        stdcall SHA1_Calc
        jmp     .sha1_done
@@:
        stdcall SHA1_Calc

        mov     edi,SHA1_Buff+{{ CodeBase }}
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
        mov     esi,SHA1_Buff+{{ CodeBase }}
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

        mov     eax,[SHA1_h0+{{ CodeBase }}]
        mov     [SHA1_a+{{ CodeBase }}],eax
        mov     eax,[SHA1_h1+{{ CodeBase }}]
        mov     [SHA1_b+{{ CodeBase }}],eax
        mov     eax,[SHA1_h2+{{ CodeBase }}]
        mov     [SHA1_c+{{ CodeBase }}],eax
        mov     eax,[SHA1_h3+{{ CodeBase }}]
        mov     [SHA1_d+{{ CodeBase }}],eax
        mov     eax,[SHA1_h4+{{ CodeBase }}]
        mov     [SHA1_e+{{ CodeBase }}],eax

        xor     ecx,ecx ; i
.cycle_loop:
        mov     eax,ecx
        shl     eax,2

        cmp     ecx,16
        jae     @f

        mov     ebx,dword [SHA1_Buff+eax+{{ CodeBase }}]
        mov     dword [SHA1_W+eax+{{ CodeBase }}],ebx
        jmp     .@1
@@:
        mov     eax,ecx
        sub     eax,3
        shl     eax,2
        mov     ebx,dword [SHA1_W+eax+{{ CodeBase }}]

        mov     eax,ecx
        sub     eax,8
        shl     eax,2
        xor     ebx,dword [SHA1_W+eax+{{ CodeBase }}]

        mov     eax,ecx
        sub     eax,14
        shl     eax,2
        xor     ebx,dword [SHA1_W+eax+{{ CodeBase }}]

        mov     eax,ecx
        sub     eax,16
        shl     eax,2
        xor     ebx,dword [SHA1_W+eax+{{ CodeBase }}]

        rol     ebx,1

        mov     eax,ecx
        shl     eax,2
        mov     dword [SHA1_W+eax+{{ CodeBase }}],ebx
.@1:
        mov     edx,[SHA1_a+{{ CodeBase }}]
        rol     edx,5

        cmp     ecx,20
        jae     @f
        mov     eax,[SHA1_b+{{ CodeBase }}]
        and     eax,[SHA1_c+{{ CodeBase }}]
        mov     ebx,[SHA1_b+{{ CodeBase }}]
        not     ebx
        and     ebx,[SHA1_d+{{ CodeBase }}]
        or      eax,ebx
        add     edx,0x5A827999
        jmp     .@2
@@:
        cmp     ecx,40
        jae     @f
        mov     eax,[SHA1_b+{{ CodeBase }}]
        xor     eax,[SHA1_c+{{ CodeBase }}]
        xor     eax,[SHA1_d+{{ CodeBase }}]
        add     edx,0x6ED9EBA1
        jmp     .@2
@@:
        cmp     ecx,60
        jae     @f
        mov     eax,[SHA1_b+{{ CodeBase }}]
        and     eax,[SHA1_c+{{ CodeBase }}]
        mov     ebx,[SHA1_b+{{ CodeBase }}]
        and     ebx,[SHA1_d+{{ CodeBase }}]
        or      eax,ebx
        mov     ebx,[SHA1_c+{{ CodeBase }}]
        and     ebx,[SHA1_d+{{ CodeBase }}]
        or      eax,ebx
        add     edx,0x8F1BBCDC
        jmp     .@2
@@:
        mov     eax,[SHA1_b+{{ CodeBase }}]
        xor     eax,[SHA1_c+{{ CodeBase }}]
        xor     eax,[SHA1_d+{{ CodeBase }}]
        add     edx,0xCA62C1D6
.@2:
        add     edx,eax
        add     edx,[SHA1_e+{{ CodeBase }}]

        mov     eax,ecx
        shl     eax,2
        add     edx,[SHA1_W+eax+{{ CodeBase }}]

        mov     eax,[SHA1_d+{{ CodeBase }}]
        mov     [SHA1_e+{{ CodeBase }}],eax

        mov     eax,[SHA1_c+{{ CodeBase }}]
        mov     [SHA1_d+{{ CodeBase }}],eax

        mov     eax,[SHA1_b+{{ CodeBase }}]
        rol     eax,30
        mov     [SHA1_c+{{ CodeBase }}],eax

        mov     eax,[SHA1_a+{{ CodeBase }}]
        mov     [SHA1_b+{{ CodeBase }}],eax

        mov     [SHA1_a+{{ CodeBase }}],edx

        inc     ecx
        cmp     ecx,80
        jne     .cycle_loop

        mov     eax,[SHA1_a+{{ CodeBase }}]
        add     [SHA1_h0+{{ CodeBase }}],eax
        mov     eax,[SHA1_b+{{ CodeBase }}]
        add     [SHA1_h1+{{ CodeBase }}],eax
        mov     eax,[SHA1_c+{{ CodeBase }}]
        add     [SHA1_h2+{{ CodeBase }}],eax
        mov     eax,[SHA1_d+{{ CodeBase }}]
        add     [SHA1_h3+{{ CodeBase }}],eax
        mov     eax,[SHA1_e+{{ CodeBase }}]
        add     [SHA1_h4+{{ CodeBase }}],eax

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


{% for function in IMPORT_FUNCTION[2:] %}
proc {{ function["SimbolicName"] }}
cmp [@{{ function["SimbolicName"] }}+{{ CodeBase }}],0
jnz flag_not_set{{ function["SimbolicName"] }}
stdcall [@GetProcAddress+{{ CodeBase }}], [{{ function["hLibrary"] }}+{{ CodeBase }}], {{ function["NameString"] }}+{{ CodeBase }}
mov [@{{ function["SimbolicName"] }}+{{ CodeBase }}], eax
flag_not_set{{ function["SimbolicName"] }}:
jmp [@{{ function["SimbolicName"] }}+{{ CodeBase }}]
endp
{% end %}


;---------------------------------------
;DecodeKey db "{{ DecodeKey }}", 0
;---------------------------------------
namePtr dd 0
ordPtr dd 0
exportDir dd 0
;===========================================================
wc WNDCLASS 0,WindowProc+{{ CodeBase }},0,0,0,0,0,COLOR_BTNFACE+1,0,class+{{ CodeBase }}
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

  hostname db 'localhost',0
  hSock dd ?
  saddr sockaddr_in
  sizesaddr = $-saddr

  WebResultBuffer rb 128
  sender        db "{{ build_id }}",13,10
  RegistryKey rb 40
  db 13,10
  LoginText rb 32
;==========================================================
{% for lib in IMPORT_LIB %}
{{ lib["LibraryString"] }} db "{{ lib["LibraryName"] }}", 0
{{ lib["hLibrary"] }} dd ?, 0
{% end %}

{% for function in IMPORT_FUNCTION %}
{{ function["NameString"] }} db "{{ function["SimbolicName"] }}", 0
@{{ function["SimbolicName"] }} dd ?
{% end %}
