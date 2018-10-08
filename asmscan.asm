; vim: ft=nasm
; Usage: asmscan <host>
; Author: Eugene Ma

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .data
        ; Error messages to call if we exit prematurely
        open_error_msg:         db 'Error: sys_open failed', 10, 0
        socket_error_msg:       db 'Error: sys_socket failed', 10, 0
        select_error_msg:       db 'Error: sys_select failed', 10, 0
        connect_error_msg:      db 'Error: sys_connect failed', 10, 0
        sendto_error_msg:       db 'Error: sys_sendto failed', 10, 0
        recvfrom_error_msg:     db 'Error: sys_recvfrom failed', 10, 0
        parse_error_msg:        db 'Error: malformed ip address', 10, 0
        usage_msg:              db 'Usage: asmscan <target ip>', 10, 0
        
        ; printf("%d open", port)
        port_open_fmtstr:       db ' open', 10, 0
        ; printf("%d closed", port)
        port_closed_fmtstr:     db ' closed', 10, 0
        ; printf("Latency %d ms", time)
        latency_fmtstr1:        db 'Latency: ', 0
        latency_fmtstr2:        db ' ms', 10, 0

        ; Path to the random number generator device
        devrpath:               db '/dev/urandom', 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .bss
        ; This struct needs to be filled in before using sockets
        ; struct sockaddr_in {
        ;       short int          sin_family;  // Address family, AF_INET
        ;       unsigned short int sin_port;    // Port number
        ;       struct in_addr     sin_addr;    // Internet address
        ;       unsigned char      sin_zero[8]; // Same size as struct sockaddr
        ; };
        sockaddr:               resb (2+2+4+8)
        sockaddrlen             equ $-sockaddr
        sockaddrlenbuf:         resd 1

        ; The bitmap used to track living sockets and as select argument
        ; typedef struct {
        ;       unsigned long fds_bits [__FDSET_LONGS];
        ; } __kernel_fd_set;
        masterfds:              resd 32
        wrfds:                  resd 32                
        rdfds:                  resd 32                 
        masterfdslen            equ 32                       

        ; Number of ports to scan in parallel 
        max_parallel_ports      equ 64
        ; For storing socket descriptors we care about
        socketarray:            resd max_parallel_ports        
        ; Used in conjunction with socketarray to map socket to port
        portarray:              resw max_parallel_ports        

        ; The source and target IPv4 addresses in network byte order
        victimaddr:             resd 1                  
        myaddr:                 resd 1                 

        ; Temporary storage for strings
        writebuf:               resb 256                 

        ; Maximum time to wait for incoming packets in usec
        max_timeout             equ 500000      
        ; struct timeval {
        ;     int tv_sec;     // seconds
        ;     int tv_usec;    // microseconds
        ; }; 
        ; This can be mangled by us or the kernel at any time!
        tv_volatile:            resd 2                  
        ; This is always zero
        tv_zero:                resd 2                  
        ; This is the delay between sending packets
        tv_master:              resd 2

        ; The global buffers we use to send and recieve datagrams
        sendbuf:                resb 1024               
        recvbuf:                resb 1024             
        sendbuflen:             resd 1                 
        recvbuflen:             resd 1               

        ; To store the file descriptor mapped to /dev/urandom
        devrfd:                 resd 1

        ; Useful miscellaneous constants 
        iphdrlen                equ 20                  
        icmphdrlen              equ 8                  
        EINPROGRESS             equ -115
        EAGAIN                  equ -11
        SYN_FLAG                equ 0x2 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .text
        global  _start

_start:
        mov ebp, esp
        ; String operations increment pointers by default
        cld                             

check_argc:
        ; Check argument count
        cmp [ebp], dword 2

        ; Make sure we were invoked with one argument
        je parse_argv
        ; Otherwise, print usage string and exit with exit code 1
        push dword -1 
        push dword usage_msg
        call premature_exit

parse_argv:
        ; Parse the IP string into octets and store them into a buffer
        push dword victimaddr           
        push dword [ebp + 8]           
        call parse_octets             
        add esp, 8                   

        ; Check return value
        test eax, eax      

        ; Parse returns zero on success
        jns load_sockaddr           
        ; Otherwise, complain about malformed IP and exit with exit code 1
        push dword -1
        push dword parse_error_msg            
        call premature_exit                  

load_sockaddr: 
        mov edi, sockaddr
        ; Set the protocol family to AF_INET
        mov ax, 2
        stosw
        ; Set the port to zero for now
        xor ax, ax
        stosw
        mov eax, [victimaddr]
        stosd
        ; Store the length of this struct in a buffer 
        mov [sockaddrlenbuf], dword sockaddrlen

check_root:
        ; Root user has uid = 0
        call sys_getuid
        cmp eax, 0
        je ping

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

tcp_scan:
        ; Store the current port in ebx 
        xor ebx, ebx 
        tcp_scan_loop: 
                ; Store the index into socketarray and portarray in esi
                ; Store the highest numbered socket descriptor in edi
                xor esi, esi 
                xor edi, edi 
                tcp_scan_connect_loop:
                        ; Create a non-blocking stream socket
                        ; (PF_INET, (SOCK_STREAM | O_NONBLOCK), IPPROTO_TCP)
                        push dword 6 
                        push dword (1 | 4000q) 
                        call spawn_socket
                        add esp, 8

                        ; Check return value
                        test eax, eax

                        ; Return value should be a valid socket descriptor
                        jns tcp_scan_store_socket
                        ; Else, print socket error message and exit with errno
                        push eax 
                        push socket_error_msg
                        call premature_exit

                        tcp_scan_store_socket:
                        ; Save the socket descriptor in an array 
                        mov [socketarray + 4 * esi], eax 
                        ; Map the socket descriptor to the port
                        mov [portarray + 2 * esi], word bx 
                        ; Update highest numbered socket descriptor
                        cmp eax, edi
                        cmovg edi, eax

                        ;;; Connect socket to current port ;;;

                        ; Load sockaddr with port in network byte order 
                        mov [sockaddr + 2], byte bh 
                        mov [sockaddr + 3], byte bl 
                        push sockaddrlen
                        push sockaddr        
                        push eax 
                        call sys_connect
                        add esp, 12

                        ; The errno should indicate the connection is pending
                        cmp eax, EINPROGRESS
                        je tcp_scan_connect_next
                        cmp eax, EAGAIN
                        je tcp_scan_connect_next
                        test eax, eax
                        jns tcp_scan_connect_next
                        ; Else, print connect error message and exit with errno
                        push eax 
                        push connect_error_msg
                        call premature_exit

                tcp_scan_connect_next:
                ; Increment and port 
                inc word bx
                ; Increment array index
                inc esi
                cmp esi, max_parallel_ports
                jl tcp_scan_connect_loop

                ; Wait 500 ms for requested connects to finish or timeout
                mov [tv_volatile + 4], dword 500000
                push tv_volatile
                push dword 0
                push dword 0
                push dword 0
                push dword 0
                call sys_select
                add esp, 20

                ; Copy master fds to wrfds 
                mov esi, masterfds
                mov edi, wrfds
                mov ecx, masterfdslen
                rep movsd

                ; Monitor sockets with select
                push tv_zero
                push dword 0
                push dword wrfds
                push dword 0
                ; Select takes highest numbered file descriptor + 1
                inc edi 
                push edi
                call sys_select
                add esp, 20
                ; Reset index into socketarray and portarray
                xor esi, esi

                ; Check return value
                cmp eax, 0

                ; Select returns the number of bits set in wrfds
                je tcp_scan_next_batch
                jns tcp_scan_write_loop 
                ; Otherwise, print select error message and exit with errno
                push eax
                push select_error_msg
                call premature_exit
        
                tcp_scan_write_loop:
                        ; Traverse array and write to sockets set in wrfds
                        mov eax, [socketarray + 4 * esi]
                        ; Test the bit mapped to this socket 
                        bt [wrfds], eax
                        ; If the bit is cleared, the socket is not ready for
                        ; writing and the state of the TCP connection is
                        ; unknown. This possibly exposes a filtered port which
                        ; drops TCP "three-way handshake" packets.
                        jnc tcp_scan_port_filtered 

                        ; If the bit is set, the socket is ready for writing;
                        ; try a 0 byte write to the socket
                        push dword 0
                        push dword 0
                        push eax
                        call sys_write
                        add esp, 12 

                        ; Check return value 
                        test eax, eax
                        ; If return value is negative, then the write failed
                        js tcp_scan_port_closed

                        ; The write succeeded, so print the open port
                        push port_open_fmtstr
                        movzx eax, word [portarray + 2 * esi]
                        push eax
                        call print_port
                        add esp, 4

                tcp_scan_port_filtered:
                tcp_scan_port_closed:
                ; Try next socket
                inc esi
                cmp esi, max_parallel_ports
                jl tcp_scan_write_loop

        tcp_scan_next_batch:
        ; Close all open socket descriptors
        call cleanup_sockets
        ; Scan the next batch of ports, or exit
        cmp bx, word 1024 
        jl tcp_scan_loop

tcp_scan_done:
        jmp exit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

ping:
        ; Create non-blocking raw socket with ICMP protocol
        ; (PF_SET, (SOCK_RAW | O_NONBLOCK), IPPROTO_ICMP)
        push dword 1                    
        push dword (3 | 4000q)         
        call spawn_socket                 
        add esp, 8                  
        
        ; Check return value
        test eax, eax                   

        ; Return value should be a valid socket descriptor
        jns ping_store_socket
        ; Otherwise, print socket error message and exit with errno
        push eax 
        push socket_error_msg
        call premature_exit

        ping_store_socket:
        ; Store the returned socket descriptor 
        mov [socketarray], eax             

        ; Build an ICMP packet with message type 8 (Echo request). 
        ; The kernel will craft the IP header.
        mov edi, sendbuf            
        ; Type: 8 (Echo request)
        mov al, 8                     
        stosb                           
        ; Code: 0 (Cleared for this type)
        xor al, al                      
        stosb                          
        ; Calculate the ICMP checksum later
        xor eax, eax                    
        stosw                         
        ; Identifier: 0, Sequence number: 0
        stosd                           
        ; Now we have to zero out 56 bytes of ICMP padding data
        xor eax, eax                    
        mov ecx, 14                    
        rep stosd                       
        ; Calculate the ICMP checksum which includes ICMP header and data
        push dword ((icmphdrlen+56)/2)
        push dword sendbuf        
        call cksum                     
        add esp, 8                  
        ; Store result in packet ICMP header
        mov [sendbuf + 2], word ax   
        ; Store the length of the packet we wish to send
        mov [sendbuflen], dword (icmphdrlen + 56)

        ; Count down the number of packets sent in ebx
        mov ebx, 3                             
        ping_send_packets:
                ; The socket is in non-blocking mode, so sending and receiving data
                ; occurs asynchronously. Send 3 pings and block until socket has data
                ; ready to be read.
                push dword [socketarray]
                call send_packet
                add esp, 4

                ; The errno should indicate connection in progress 
                cmp eax, EINPROGRESS   
                je ping_send_next_packet
                cmp eax, EAGAIN
                je ping_send_next_packet
                test eax, eax
                jns ping_send_next_packet
                ; Otherwise, print sendto error message and exit with errno
                push eax
                push sendto_error_msg
                call premature_exit

        ping_send_next_packet:
        ; Send another packet?
        dec ebx
        jnz ping_send_packets

        ; Time how long it takes to receieve the first ICMP echo response
        mov edi, tv_volatile
        xor eax, eax
        stosd
        mov eax, max_timeout
        ; Initialize tv_usec to maximum timeout 
        stosd

        ; Copy masterfds to rdfds
        mov esi, masterfds
        mov edi, rdfds
        mov ecx, masterfdslen
        rep movsd

        ; Block until data is ready to be read, or timeout is exceeded 
        push tv_volatile       
        push dword 0                    
        push dword 0                   
        push rdfds                  
        push dword [socketarray]
        inc dword [esp]
        call sys_select                 
        add esp, 20

        ; Check return value
        cmp eax, 0

        ; Select returns the number of bits set in rdfds
        je ping_no_reply
        jns ping_replied
        ; Otherwise, print select error message and exit with errno
        push eax
        push dword select_error_msg
        call premature_exit

        ping_no_reply:
        ;;; Victim didn't respond to our ping ;;;

        ; Free the socket we used
        call cleanup_sockets
        ; Give up on SYN scanning, because we have no other way of
        ; getting the IP address for now.
        jmp tcp_scan

        ping_replied:
        ; Calculate the packet delay from max_timeout - remaining time
        mov eax, max_timeout
        mov ecx, [tv_volatile + 4]
        sub eax, ecx
        ; Set delay to RTT * 2 
        shl eax, 1
        mov [tv_master + 4], eax   

        ; Read the socket for a response
        mov [recvbuflen], dword 0xffff
        push dword [socketarray]
        call recv_packet
        add esp, 4

        ; Check return value
        test eax, eax

        ; recvfrom should return the number of bytes received
        jns ping_save_address
        ; Otherwise, print recvfrom error message and exit with errno
        push eax
        push dword recvfrom_error_msg
        call premature_exit

        ping_save_address:
        ;;; Swipe the IP address from the ICMP packet we recieved ;;;

        ; This should get the destination address field of the IP header
        lea esi, [recvbuf + 16]
        mov edi, myaddr
        movsd

        ;;; Print expected latency (useful for debugging) ;;;

        ; Convert microseconds to milliseconds
        mov eax, [tv_master + 4]
        mov ecx, 1000
        div ecx
        ; Convert this number to a string
        push writebuf
        push eax
        call ultostr
        add esp, 8
        ; "Latency: %d ms"
        push latency_fmtstr1
        call printstr
        mov [esp], dword writebuf
        call printstr
        mov [esp], dword latency_fmtstr2
        call printstr
        add esp, 4

        ; All done - close socket 
        call cleanup_sockets

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

syn_scan:
        ; Create a raw non-blocking socket with TCP protocol
        ; (PF_INET, (SOCK_RAW | NON_BLOCK), IPPROTO_TCP)
        push dword 6
        push dword (3|4000q)
        call spawn_socket
        add esp, 8

        ; Check return value
        test eax, eax                   

        ; Return value should be a valid socket descriptor
        jns syn_scan_store_socket
        ; Otherwise, print socket error message and exit with errno
        push eax 
        push socket_error_msg
        call premature_exit

        syn_scan_store_socket:
        ; Store the raw socket file descriptor in socketarray array
        mov [socketarray], eax             

        ; Open random number generator device for generating SYN sequences
        ; (O_RDONLY, "/dev/urandom")
        push dword 0
        push dword devrpath
        call sys_open
        add esp, 8

        ; Check return value
        test eax, eax

        ; Return value should be a valid file descriptor
        jns syn_scan_store_random
        ; Otherwise, print open error message and exit with errno
        push dword eax
        push dword open_error_msg
        call premature_exit

        syn_scan_store_random:
        ; Save the returned file descriptor
        mov [devrfd], eax

        ; Store the current port in ebx
        xor ebx, ebx
        syn_scan_loop:
                ; Count down the number of packets sent in esi
                mov esi, max_parallel_ports
                syn_scan_send_syn_loop:
                        ; Send a TCP packet with the SYN flag set
                        push dword SYN_FLAG
                        push dword ebx
                        push dword [socketarray]
                        call send_tcp_raw
                        add esp, 12

                        ; Check return value
                        test eax, eax

                        ; Return value should be number of bytes sent
                        jns syn_scan_send_next
                        ; Else, print sendto error message and exit with errno
                        push eax
                        push dword sendto_error_msg
                        call premature_exit

                syn_scan_send_next:
                ; Increment current port
                inc ebx
                ; Check if we should do another port
                dec esi
                jnz syn_scan_send_syn_loop

                ; Copy tv_master to tv_volatile
                lea esi, [tv_master + 4]
                lea edi, [tv_volatile + 4]
                movsd

                ; Give some time for the packets to arrive
                push tv_volatile
                push dword 0
                push dword 0
                push dword 0
                push dword 0
                call sys_select
                add esp, 20

                ; Copy masterfds to rdfds 
                mov esi, masterfds
                mov edi, rdfds
                mov ecx, masterfdslen
                rep movsd

                ; Monitor sockets with select
                push tv_zero
                push dword 0
                push dword 0
                push dword rdfds
                push dword [socketarray]
                inc dword [esp] 
                call sys_select
                add esp, 20

                ; Check return value
                cmp eax, 0

                ; Select returns the number of bits set in rdfds
                je syn_scan_next_batch
                jns syn_scan_recv_reply_loop
                ; Otherwise, print select error message and exit with errno
                push eax
                push dword select_error_msg
                call premature_exit

                syn_scan_recv_reply_loop:
                        ;;; Store the reply packet in recvbuf and look for flags ;;;

                        ; Read the socket for a response
                        mov [recvbuflen], dword 0xffff
                        push dword [socketarray]
                        call recv_packet
                        add esp, 4

                        ; Check return value
                        test eax, eax

                        ; If signed, then we were unable to read any more data
                        ; Otherwise, recvfrom returns the number of bytes received
                        js syn_scan_next_batch

                        ; IP header length located in last 4 bits of first byte
                        movzx eax, byte [recvbuf]
                        and eax, 0xf
                        ; Convert from words to bytes
                        shl eax, 2
                        ; Store the address of start of TCP header in edi
                        mov edi, eax
                        ; Point to flags field
                        add eax, 13
                        ; Bitwise separation of flags in the target byte:
                        ; 0 | 0 | URG | ACK | PSH | RST | SYN | FIN
                        lea esi, [recvbuf + eax]
                        lodsb
                        ; Filter for the ACK and SYN flags
                        and al, 0x12
                        ; ACK = 1, SYN = 1
                        cmp al, 0x12
                        jne syn_scan_recv_reply_loop

                        ; Print the port if flags ACK and SYN are on
                        push dword port_open_fmtstr
                        ; Extract the port from the TCP header
                        movzx eax, word [recvbuf + edi]
                        xchg al, ah
                        ; Print the open port
                        push eax
                        call print_port
                        add esp, 8

                ; Keep receiving packets until recvfrom fails
                jmp syn_scan_recv_reply_loop

        syn_scan_next_batch:
        ; Scan the next batch of ports, or clean up
        cmp ebx, 1024
        jl syn_scan_loop

syn_scan_done:
        ; Clean up file descriptors and exit
        push dword [devrfd]
        call sys_close
        add esp, 4
        call cleanup_sockets

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

exit:
        mov ebp, esp
        mov eax, 1
        xor ebx, ebx
        int 0x80

; ------------------------------------------------------------------------------
; send_tcp_raw:
;       Send a TCP packet with custom header to the specified port
;               Expects: stack - socket descriptor, port, TCP header flag
;                        devrfd - contains file descriptor mapped to random
;                        number generator device
;               Returns: number of bytes sent in eax, or -errno on error
send_tcp_raw:
        push ebp
        mov ebp, esp
        push edi

        ; Prepare the raw TCP packet to send
        mov edi, sendbuf
        ; Load the source port
        mov ax, 31337
        xchg al, ah
        stosw
        ; Load the destination port
        mov ax, [ebp + 12]
        xchg al, ah
        stosw
        ; SEQ = rand()
        call rand
        stosd
        ; ACK = 0
        xor eax, eax
        stosd
        ; Data offset = 5 << 4 (length of header in dwords)
        mov al, 0x5
        shl al, 4
        stosb
        ; Flags = type; 0x2 = SYN, 0x3 = RST
        xor al, al
        or al, [ebp + 16]
        stosb
        ; Max window size = 4096 bytes
        mov ax, 4096
        xchg al, ah
        stosw
        ; Checksum = 0
        xor ax, ax
        stosw
        ; Urgent pointer = 0 (not used)
        stosw

        ; Prepare TCP pseudo-header
        ; struct pseudo_hdr {
        ;       u_int32_t src;          /* 32bit source ip address*/
        ;       u_int32_t dst;          /* 32bit destination ip address */      
        ;       u_char mbz;             /* 8 reserved bits (all 0)      */
        ;       u_char proto;           /* protocol field of ip header */
        ;       u_int16_t len;          /* tcp length (both header and data) */
        ; }
        ; Load source ip address
        mov eax, [myaddr]
        stosd
        ; Load destination ip address
        mov eax, [victimaddr]
        stosd
        ; 8 reserved bits (all 0)
        xor al, al
        stosb
        ; Protocol field of ip header = IPPROTO_TCP
        mov al, 6
        stosb
        ; Length of TCP header and data (20 + 0) in bytes
        mov ax, 20
        xchg al, ah
        stosw

        ; Calculate TCP header and pseudo-header checksum
        push dword (20+12)
        push sendbuf
        call cksum
        add esp, 8

        ; Store checksum in TCP header
        mov [sendbuf + 16], ax
        ; Set the length in bytes to send
        mov [sendbuflen], dword 20

        ; Send the SYN packet
        push dword [ebp + 8]
        call send_packet
        add esp, 4

        pop edi
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; cksum:  
;       Do a 16 bit checksum for given data and length
;               Expects: pointer to data, data length in words 
;               Returns: checksum 
cksum:
        push ebx
		mov ecx, [esp + 12]
		mov edx, [esp + 8]
		
		test ecx, ecx
		je .return
		
		lea ebx, [edx + ecx * 2]
		xor eax, eax
		
.loop:
		movzx ecx, word [edx]
		
		add edx, 2
		add eax, ecx
		cmp edx, ebx
		jne .loop
		
		mov edx, eax
		movzx ebx, ax
		shr edx, 16
		add edx, ebx
		mov eax, edx
		shr eax, 16
		add eax, edx
		not eax
		
.return:
		pop ebx
		ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; printstr: 
;       Print a string to standard output
;               Expects: string address
;               Returns: bytes written, -errno on error
printstr:
        push ebx
		mov ebx, [esp + 8]
		
		push ebx
		call strlen
		
		mov [esp], eax	; After the call to strlen, we don't reset the stack and thus have space for the args (mov [esp], x is quicker than push x)
		push ebx
		push 1
		call sys_write
		add esp, 12
		
		pop ebx
		ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; strlen: 
;       Calculate the length of null-terminated string
;               Expects: string address
;               Returns: length in eax
strlen:
        push edi
		
		mov edi, [esp + 8]
		xor eax, eax
		or ecx, -1
		repnz scasb
		
		pop edi
		mov eax, ecx
		not eax
		dec eax
		ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; parse_octets:
;       Convert an IPv4 address from text to binary form
;               Expects: ip string, destination buffer
;               Returns: 0 in eax, ~0 on error
parse_octets:
        push ebp
        mov ebp, esp
        sub esp, 4
        push ebx
        push esi
        push edi

        mov esi, [ebp + 8]
        mov ebx, [ebp + 12]
        lea edi, [ebp - 4]
        ; This value comes in handy when its on the stack
        push edi
        parse_loop:
                ; Load the string into the four byte buffer we allocated
                load_string:
                        ; This loads the next byte from [esi] into al
                        lodsb
                        ; Check for termination characters
                        cmp al, byte 0
                        je convert_octet
                        cmp al, byte '.'
                        je convert_octet
                        ; Make sure its a valid octet digit (0-9)
                        cmp al, byte '0'
                        jl invalid_ip
                        cmp al, byte '9'
                        jg invalid_ip
                        ; Otherwise this is a valid digit, store it in buffer
                        stosb
                        ; Make sure we stored less than 4 bytes in the buffer
                        cmp edi, ebp
                        jg invalid_ip
                        jmp load_string
                ; If we reached here, we're ready to convert the octet into its
                ; binary representation
                convert_octet:
                ; First make sure we stored at least one digit
                cmp edi, [esp]
                je invalid_ip
                ; Okay, now we've confirmed our octet consists of 1 to 3
                ; digits, terminate the string by writing the null byte.
                mov [edi], byte 0
                ; The argument we need is already on the stack, it points to
                ; the first byte of the octet string
                call strtoul
                ; An octet has to be an 8-bit value
                cmp eax, 255
                jg invalid_ip
                ; Now load the next octet into the destination octet buffer 
                mov [ebx], byte al
                count_octets:
                push ebx
                sub ebx, [ebp + 12]
                cmp ebx, 3
                pop ebx
                je last_octet
                cmp [esi - 1], byte '.' 
                jne invalid_ip
                ; We still have more work to do!
                prepare_next_octet:
                ; First, make sure we increment the destination address.
                inc ebx
                ; Finally, reset buffer pointer to start of buffer so we can
                ; write another octet 
                lea edi, [ebp - 4]
                jmp parse_loop
                last_octet:
                ; All four octets are supposedly loaded in the destination
                ; buffer. This means esi is must be pointing to a null byte.
                cmp [esi - 1], byte 0
                jne invalid_ip        
                jmp parse_success
        invalid_ip:
        xor eax, eax
        not eax
        jmp exit_parse_octets
        parse_success:
        xor eax, eax
        exit_parse_octets:
        add esp, 4

        pop edi
        pop esi
        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; strtoul:
;       Convert a number from text to binary form
;               Expects: string address
;               Returns: 32-bit unsigned integer in eax
strtoul:
		push ebx
		mov eax, [esp + 8]
		
		movzx ebx, byte [eax]
		lea edx, [eax + 1]
		
		xor eax, eax
		
		test bl, bl
		je .return
		
.loop:
		lea ecx, [eax + eax * 4]
		inc edx
		lea eax, [ebx + ecx * 2 - 48]
		movzx ebx, byte [edx - 1]
		test bl, bl
		jne .loop
		
.return:
		pop ebx
		ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; ultostr: 
;       Convert a number from binary to text form
;               Expects: 32-bit unsigned integer, buffer 
;               Returns: nothing
ultostr:
        push edi
		mov ecx, 1
		push esi
		mov esi, 10
		sub esp, 16
		
.loop:
		mov eax, [esp + 28]
		xor edx, edx
		inc ecx
		div esi
		
		cmp dword [esp + 28], 0
		jbe .finish
		
		mov [esp + 28], eax
		jmp .loop
		
.finish:
		mov dl, byte [esp + 28]
		lea esi, [esp + 15]
		mov edi, [esp + 32]
		add dl, 48
		mov byte [esp + 15], dl
		rep movsb
		
		add esp, 16
		pop esi
		pop edi
		ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; spawn_socket:
;       Create a new socket and add it to masterfds
;               Expects: socket type, protocol
;               Returns: socket descriptor in eax, or -errno on error
spawn_socket:
        push ebp
        mov ebp, esp

        ; Push protocol
        push dword [ebp + 12]
        ; Push type
        push dword [ebp + 8]
        ; PF_INET by default
        push dword 2
        call sys_socket
        add esp, 12
        ; Check return value
        test eax, eax
        js spawn_socket_done
        ; Add it to "master" fd bitfield
        bts [masterfds], eax

        spawn_socket_done:
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; cleanup_sockets:
;       Close all living sockets 
;               Expects: nothing
;               Returns: nothing
cleanup_sockets:
        push ebp
        mov ebp, esp

        ; Initialize bitmap index to 1023, which is the highest file descriptor
        ; that can exist in a fdset.
        mov eax, 1023
        lea ecx, [masterfds + masterfdslen]

        ; Find dword containing highest numbered file descriptor
        find_highest_loop:
                cmp [ecx], dword 0
                jnz cleanup_sockets_loop
                sub eax, 32
                sub ecx, 4
                jmp find_highest_loop

        ; Loop through remaining bits in fdset
        cleanup_sockets_loop:
                ; Clear bit to zero and store original bit in CF
                btr [masterfds], eax
                ; If bit was set, close the mapped socket
                jc close_socket

                ; Otherwise go to next socket
                jmp free_next_socket

                close_socket:
                push eax
                call sys_close
                pop eax

        ; Keep looking for sockets to free until counter is negative
        free_next_socket:
        dec eax
        jns cleanup_sockets_loop

        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; premature_exit:
;       Print error message, clean up file descriptors, then exit with exit code
;               Expects: error msg, -errno
;               Returns: errno to shell
premature_exit:
        push ebp
        mov ebp, esp
        
        ; Print error message
        push dword [ebp + 8]
        call printstr
        add esp, 4
        ; Close file descriptor mapped to /dev/urandom 
        cmp dword [devrfd], 0
        je premature_exit_close_sockets
        push dword [devrfd]
        call sys_close
        add esp, 4
        ; Free all open sockets (raw, icmp, tcp, etc...)
        premature_exit_close_sockets:
        call cleanup_sockets
        ; Convert -errno to errno
        mov ebx, [ebp + 12]
        not ebx
        inc ebx
        ; Exit and send errno to shell
        mov eax, 1
        int 0x80
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_getuid:
;       Return the user ID of this process
;               Expects: nothing
;               Returns: uid in eax
sys_getuid:
        push ebp
        mov ebp, esp
        
        mov eax, 199
        int 0x80

        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_read:
;       Read from file
;               Expects: fd, buffer, buffer len
;               Returns: number of bytes read, or -errno
sys_read:
        push ebp
        mov ebp, esp
        push ebx

        mov eax, 3
        mov ebx, [ebp + 8]
        mov ecx, [ebp + 12]
        mov edx, [ebp + 16]
        int 0x80

        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_write:
;       Write to file
;               Expects: fd, buffer, buffer len
;               Returns: number of bytes written, or -errno
sys_write:
        push ebp
        mov ebp, esp
        push ebx

        mov eax, 4
        mov ebx, [ebp + 8]
        mov ecx, [ebp + 12]
        mov edx, [ebp + 16]
        int 0x80

        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_close:
;       Close a file descriptor
;               Expects: file descriptor
;               Returns: 0 in eax | -errno in eax if error
sys_close:
        push ebp
        mov ebp, esp
        push ebx
        
        mov eax, 6
        mov ebx, [ebp + 8]
        int 0x80
        
        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_open:
;       Open a file descriptor
;               Expects: file descriptor
;               Returns: fd in eax, or -errno if error
sys_open:
        push ebp
        mov ebp, esp
        push ebx
        
        ; int open(const char *pathname, int flags);
        mov eax, 5
        mov ebx, [ebp + 8]
        mov ecx, [ebp + 12]
        int 0x80
        
        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_connect:
;       Connect a socket       
;               Expects: int socket, address, address length
;               Returns: 0 in eax or -errno on error
sys_connect:
        push ebp
        mov ebp, esp
        push ebx
        push edi

        mov eax, 102
        mov ebx, 3
        ; sys_socketcall is a wrapper around all the socket system calls, and
        ; takes as an argument a pointer to the arguments specific to the
        ; socket call we want to use, so load ecx with the address of the first
        ; argument on the stack
        lea ecx, [ebp + 8]
        int 0x80

        pop edi
        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_socket: 
;       Create a socket       
;               Expects: int domain, int type, int protocol
;               Returns: socket descriptor in eax or -errno on error
sys_socket:
        push ebp
        mov ebp, esp
        push ebx
        push edi

        mov eax, 102
        mov ebx, 1
        lea ecx, [ebp + 8]
        int 0x80

        pop edi
        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_select:
;       Wrapper around sys_select
;               Expects: int nfds, fd_set *rdfds, fd_set *wrfds,
;                       fd_set *exceptfds, struct timeval *timeout
;               Returns: total number of fildes set in fd_set structs, -errno if error
sys_select:
        push ebp
        mov ebp, esp
        push ebx
        push esi
        push edi

        mov eax, 142
        mov ebx, [ebp + 8]
        mov ecx, [ebp + 12]
        mov edx, [ebp + 16]
        mov esi, [ebp + 20]
        mov edi, [ebp + 24]
        int 0x80

        pop edi
        pop esi
        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_sendto 
;       Send a packet to target host
;               Expects: socket, buffer, length, flags, sockaddr, sockaddrlen
;               Returns: number of characters sent, -errno on error
sys_sendto:
        push ebp
        mov ebp, esp
        push ebx

        mov eax, 102
        mov ebx, 11
        lea ecx, [ebp + 8] 
        int 0x80

        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; sys_recvfrom 
;       Receieve a packet from target host
;               Expects: socket, buffer, length, flags, sockaddr, sockaddrlen
;               Returns: number of characters received, -errno on error
sys_recvfrom:
        push ebp
        mov ebp, esp
        push ebx

        mov eax, 102
        mov ebx, 12
        lea ecx, [ebp + 8] 
        int 0x80

        pop ebx
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; send_packet
;       Send a packet to target host
;               Expects: stack - socket
;                        sockaddr - points to target host
;                        sendbuf - filled out for us
;                        sendbuflen - filled out for us
;               Returns: number of bytes sent, or -errno
send_packet:
        push ebp
        mov ebp, esp
        
        push dword sockaddrlen         
        push dword sockaddr           
        push dword 0                 
        push dword [sendbuflen]     
        push dword sendbuf         
        push dword [ebp + 8]      
        call sys_sendto          
        add esp, 24            

        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; recv_packet
;       Receive a packet from target host
;               Expects: stack - socket
;                        sockaddr - points to target host
;                        recvbuf - filled out for us
;                        recvbuflen - filled out for us
;               Returns: number of bytes received, or -errno
recv_packet:
        push ebp
        mov ebp, esp
        
        push dword sockaddrlenbuf     
        push dword sockaddr        
        push dword 0                
        push dword [recvbuflen]      
        push dword recvbuf  
        push dword [ebp + 8]  
        call sys_recvfrom    
        add esp, 24            

        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; rand
;       Get a random 32-bit integer from /dev/urandom
;               Expects: stack - nothing 
;                        devrfd - fd with read perms mapped to /dev/urandom 
;               Returns: random int in eax
rand:
        push ebp
        mov ebp, esp
        sub esp, 4
        push esi

        lea esi, [ebp - 4]

        push dword 4
        push esi
        push dword [devrfd]
        call sys_read
        add esp, 12

        lodsd

        pop esi
        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------

; ------------------------------------------------------------------------------
; print_port
;       Write to stdout telling the user if the port was open or closed.       
;               Expects: port, open/closed message buffer
;               Returns: nothing
print_port:
        push ebp
        mov ebp, esp

        ; Convert port number to string 
        push writebuf
        push dword [ebp + 8]
        call ultostr 
        add esp, 8
        ; Print port number
        push dword writebuf 
        call printstr 
        ; Swap buffers
        mov eax, [ebp + 12]
        mov [esp], eax
        call printstr
        add esp, 4

        mov esp, ebp
        pop ebp
        ret
; ------------------------------------------------------------------------------
; EOF ==========================================================================
