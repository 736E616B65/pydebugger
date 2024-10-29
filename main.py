import my_debugger

debugger = my_debugger.Debugger()
pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))
lists = debugger.enumerate_threads()

for thread in lists:
    thread_context = debugger.get_thread_context(thread)
    
    print(f"[*] Dumping registers for thread ID: 0x{thread:08X}")
    print(f"[**] EIP: 0x{thread_context.Eip:08X}")
    print(f"[**] ESP: 0x{thread_context.Esp:08X}")
    print(f"[**] EBP: 0x{thread_context.Ebp:08X}")
    print(f"[**] EAX: 0x{thread_context.Eax:08X}")
    print(f"[**] EBX: 0x{thread_context.Ebx:08X}")
    print(f"[**] ECX: 0x{thread_context.Ecx:08X}")
    print(f"[**] EDX: 0x{thread_context.Edx:08X}")
    print(f"[*] END DUMP")

debugger.detach()